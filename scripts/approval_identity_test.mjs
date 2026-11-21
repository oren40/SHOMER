/**
 * Approver identity test: a typed name is a claim, not evidence.
 * Resolutions require an authenticated per-human key; the ledger records the
 * principal + key id + args binding.
 * Usage: node scripts/approval_identity_test.mjs
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const PORT = 8797;
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "shomer-appr-"));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let failures = 0;
const check = (name, cond, extra = "") => {
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${extra ? "  -> " + extra : ""}`);
  if (!cond) failures++;
};

const tsx = path.join(ROOT, "node_modules", "tsx", "dist", "cli.mjs");
if (!fs.existsSync(tsx)) {
  console.error("FAIL: tsx not found - run npm install first");
  process.exit(1);
}
const child = spawn(process.execPath, [tsx, "src/index.ts"], {
  cwd: ROOT,
  env: { ...process.env, PORT: String(PORT), SHOMER_DATA_DIR: TMP, SHOMER_CHECKPOINT_DIR: path.join(TMP, "checkpoints"), SHOMER_CHECKPOINT_KEY_PATH: path.join(TMP, "keys", "cp.pem") },
  stdio: ["ignore", "ignore", "pipe"],
});
let stderr = "";
child.stderr.on("data", (d) => (stderr += d));

const B = `http://localhost:${PORT}`;
async function waitUp() {
  for (let i = 0; i < 60; i++) {
    try {
      await fetch(B + "/healthz");
      return true;
    } catch {
      await sleep(250);
    }
  }
  return false;
}

try {
  if (!(await waitUp())) throw new Error("control plane did not start: " + stderr.slice(0, 600));
  const ADMIN = fs.readFileSync(path.join(TMP, "DEV_KEY.txt"), "utf8").trim();
  const HA = { "Content-Type": "application/json", Authorization: "Bearer " + ADMIN };
  const jpost = (p, b, h) => fetch(B + p, { method: "POST", headers: h || HA, body: JSON.stringify(b) }).then(async (r) => ({ status: r.status, body: await r.json().catch(() => ({})) }));

  // per-human keys
  const alice = (await jpost("/api/keys", { name: "alice@acme.com", scopes: ["dashboard"] })).body;
  const agentOnly = (await jpost("/api/keys", { name: "svc-bot", scopes: ["agent:refunds-prod"] })).body;
  const HA_KEY = (k) => ({ "Content-Type": "application/json", Authorization: "Bearer " + k });

  // a $320 refund -> require_human
  const ev = await jpost("/v1/evaluate", { agent_id: "refunds-prod", tool: "issue_refund", args: { order_id: "AI-1", amount_usd: 320 }, estimated_cost_usd: 0.15 }, HA);
  check("require_human raised", ev.body.decision === "require_human", ev.body.approval_id);

  // 1) a caller WITHOUT dashboard scope cannot resolve, even with a typed name
  const denied = await jpost(`/api/approvals/${ev.body.approval_id}/resolve`, { approved: true, by: "I am totally the approver" }, HA_KEY(agentOnly.key));
  check("agent-scoped key cannot approve -> 403", denied.status === 403, String(denied.status));

  // 2) typed name alone is not enough (no approver key, caller has no dashboard key)
  const typed = await jpost(`/api/approvals/${ev.body.approval_id}/resolve`, { approved: true, by: "someone" }, { "Content-Type": "application/json" });
  check("unauthenticated approval attempt -> 401", typed.status === 401, String(typed.status));

  // 3) authenticated per-human key -> recorded as evidence
  const ok = await jpost(`/api/approvals/${ev.body.approval_id}/resolve`, { approved: true, approver_key: alice.key, by: "alice (note)" }, HA);
  check("alice's approval accepted", ok.status === 200 && ok.body.resolved_by === "alice@acme.com", ok.body.resolved_by);

  const led = await fetch(B + "/v1/ledger?limit=50", { headers: HA }).then((r) => r.json());
  const outcome = led.events.find((e) => e.type === "outcome" && e.decision_id === ev.body.decision_id);
  check("ledger: actor is the authenticated principal", outcome?.actor === "alice@acme.com", outcome?.actor);
  check("ledger: principal key id recorded", typeof outcome?.actor_key_id === "string" && outcome.actor_key_id.length > 0);
  check("ledger: approval bound to args hash", outcome?.binding_verified === true);
  check("ledger: typed name kept as note only", (outcome?.note ?? "").includes("alice (note)"), outcome?.note);
} catch (e) {
  console.error("FAIL: unexpected error:", e.message);
  failures++;
} finally {
  child.kill();
  fs.rmSync(TMP, { recursive: true, force: true });
}
console.log(failures === 0 ? "\nAPPROVAL IDENTITY TEST PASSED" : `\n${failures} APPROVAL CHECK(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);