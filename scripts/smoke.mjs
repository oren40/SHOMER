/**
 * Shomer smoke test - exercises the control plane end to end via HTTP.
 * Usage: node scripts/smoke.mjs   (server running on :8787)
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const B = process.env.SHOMER_URL || "http://localhost:8787";
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

// dev key written to data/DEV_KEY.txt on first boot
let KEY = fs.readFileSync(path.join(ROOT, "data", "DEV_KEY.txt"), "utf8").trim();
const H_KEY = () => ({ "Content-Type": "application/json", Authorization: "Bearer " + KEY });
const post = (p, b, extraHeaders) => fetch(B + p, { method: "POST", headers: { ...H_KEY(), ...(extraHeaders || {}) }, body: JSON.stringify(b) }).then((r) => r.json());
const get = (p, extraHeaders) => fetch(B + p, { headers: extraHeaders || H_KEY() }).then((r) => r.json());

let failures = 0;
const check = (name, cond, extra = "") => {
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${extra ? "  -> " + extra : ""}`);
  if (!cond) failures++;
};

const ledgerLen = async () => (await get("/v1/ledger?limit=1000")).events.length;

let evaluates = 0;
/** INVARIANT: exactly one ledger entry per /v1/evaluate, for every decision type */
async function evaluateAndAssertLedger(body) {
  const before = await ledgerLen();
  const r = await post("/v1/evaluate", body);
  evaluates++;
  const after = await ledgerLen();
  check(`invariant: one ledger entry per evaluate (${body.tool})`, after === before + 1, `delta=${after - before}`);
  return r;
}

// 0) auth
check("auth: no key -> 401", (await fetch(B + "/v1/evaluate", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ agent_id: "refunds-prod", tool: "lookup_order", args: {} }) }).then((r) => r.status)) === 401);
check("auth: bad key -> 401", (await fetch(B + "/v1/evaluate", { method: "POST", headers: { "Content-Type": "application/json", Authorization: "Bearer sk_live_nope" }, body: JSON.stringify({ agent_id: "refunds-prod", tool: "lookup_order", args: {} }) }).then((r) => r.status)) === 401);

// 1) normal call -> allow
let r = await evaluateAndAssertLedger({ agent_id: "refunds-prod", tool: "lookup_order", args: { order_id: "O-1" }, estimated_cost_usd: 0.02 });
check("evaluate: allow", r.decision === "allow", r.reason);
await post("/v1/complete", { decision_id: r.decision_id, cost_usd: 0.02, tokens: 100, status: "succeeded", cost_source: "agent_reported" });

// 2) PII -> sanitize
r = await evaluateAndAssertLedger({ agent_id: "refunds-prod", tool: "notify_customer", args: { email: "bob@example.com", order_id: "O-2" }, estimated_cost_usd: 0.03 });
check("evaluate: sanitize PII", r.decision === "sanitize" && r.redactions >= 1, JSON.stringify(r.args));
if (r.allowed) await post("/v1/complete", { decision_id: r.decision_id, cost_usd: 0.03, tokens: 100, status: "succeeded", cost_source: "agent_reported" });

// 3) $320 refund -> require_human, approve, binding check
r = await evaluateAndAssertLedger({ agent_id: "refunds-prod", tool: "issue_refund", args: { order_id: "O-3", amount_usd: 320 }, estimated_cost_usd: 0.15 });
check("evaluate: require_human", r.decision === "require_human", r.approval_id);
const approval = await get("/api/approvals/" + r.approval_id);
const ledDec = (await get("/v1/ledger?limit=50")).events.find((e) => e.type === "decision" && e.decision_id === r.decision_id);
check("approval bound to args hash", approval.args_hash === ledDec.args_hash && !!ledDec.args_hash);
await post(`/api/approvals/${r.approval_id}/resolve`, { approved: true, by: "smoke_test" });
check("approval resolved", (await get(`/api/approvals/${r.approval_id}`)).status === "approved");

// 4) $5000 -> hard cap deny
r = await evaluateAndAssertLedger({ agent_id: "refunds-prod", tool: "issue_refund", args: { order_id: "O-4", amount_usd: 5000 }, estimated_cost_usd: 0.15 });
check("evaluate: hard cap deny", r.decision === "deny" && r.reason === "hard_cap_exceeded", r.reason);

// 5) runaway loop: same call twice -> second denied
r = await evaluateAndAssertLedger({ agent_id: "refunds-prod", tool: "issue_refund", args: { order_id: "O-5", amount_usd: 60 }, estimated_cost_usd: 0.15 });
check("loop: first allowed", r.decision === "allow", r.reason);
if (r.allowed) await post("/v1/complete", { decision_id: r.decision_id, cost_usd: 0.15, tokens: 100, status: "succeeded", cost_source: "agent_reported" });
r = await evaluateAndAssertLedger({ agent_id: "refunds-prod", tool: "issue_refund", args: { order_id: "O-5", amount_usd: 60 }, estimated_cost_usd: 0.15 });
check("loop: repeat denied", r.decision === "deny" && r.reason === "runaway_loop_detected", r.reason);

// 6) allowlist: tool blocked (support-triage has no issue_refund)
r = await evaluateAndAssertLedger({ agent_id: "support-triage", tool: "issue_refund", args: {}, estimated_cost_usd: 0.02 });
check("allowlist: tool blocked", r.decision === "deny" && r.reason === "tool_not_allowed", r.reason);

// 7) observe mode: flip one policy to observe -> same inputs become allow with would_* reason
const pols = await get("/api/policies");
const allowPol = pols.policies.find((p) => p.agent_id === "support-triage" && p.type === "tool_allowlist");
const patched = await fetch(B + "/api/policies/" + allowPol.id, { method: "PATCH", headers: H_KEY(), body: JSON.stringify({ mode: "observe" }) }).then((r) => r.json());
check("policy switched to observe", patched.mode === "observe");
r = await post("/v1/evaluate", { agent_id: "support-triage", tool: "issue_refund", args: {}, estimated_cost_usd: 0.02 });
evaluates++;
check("observe: would-be block not enforced", r.decision === "allow" && r.would_deny_reason === "tool_not_allowed", r.would_deny_reason);
await fetch(B + "/api/policies/" + allowPol.id, { method: "PATCH", headers: H_KEY(), body: JSON.stringify({ mode: "enforce" }) });

// 8) scoped key enforcement
const otherKey = await post("/api/keys", { name: "smoke-other", scopes: ["agent:other"] });
const forbidden = await fetch(B + "/v1/evaluate", {
  method: "POST",
  headers: { "Content-Type": "application/json", Authorization: "Bearer " + otherKey.key },
  body: JSON.stringify({ agent_id: "refunds-prod", tool: "lookup_order", args: {} }),
});
check("scope: agent:other cannot act as refunds-prod -> 403", forbidden.status === 403);
await fetch(B + "/api/keys/" + otherKey.id, { method: "DELETE", headers: H_KEY() });

// 9) totals: decisions recorded == evaluates performed
const v = await get("/v1/ledger/verify");
const stats = await get("/api/overview");
check("ledger: hash chain valid", v.valid === true, `length=${v.length}`);
check(`ledger: decision count (${stats.actions_today}) == evaluates (${evaluates})`, stats.actions_today === evaluates);

// 10) evidence pack JSON
const ev = await get("/api/evidence?agent_id=refunds-prod");
check("evidence pack builds", ev.summary.actions_governed > 0 && ev.integrity.chain_verification.valid === true, `actions=${ev.summary.actions_governed} blocked=${ev.summary.blocked}`);
const pdfResp = await fetch(B + "/api/evidence/export?format=pdf&agent_id=refunds-prod", { headers: H_KEY() });
const pdfBuf = Buffer.from(await pdfResp.arrayBuffer());
check("evidence PDF exports", pdfResp.status === 200 && pdfBuf.subarray(0, 5).toString() === "%PDF-", `${pdfBuf.length} bytes`);

console.log(failures === 0 ? "\nALL CHECKS PASSED" : `\n${failures} CHECK(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);