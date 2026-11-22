/**
 * seed_timeseries.mjs - backfills a realistic 14-day evidence history for the
 * pilot demo (docs/one-pager-he.md + observe-pilot.md). Appends tamper-evident
 * ledger events (decisions + outcomes) and a matching Ed25519 checkpoint.
 *
 * Usage:
 *   1) rm -rf data shomer-checkpoints shomer-keys && npm run start   (seeds agents/policies, creates the signing key)
 *   2) stop the server, then:  node scripts/seed_timeseries.mjs --agent refunds-prod --days 14
 *   3) npm run start && python demo/refunds_agent.py && npm run pilot -- --agent refunds-prod --days 14
 */
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const DATA = process.env.SHOMER_DATA_DIR || path.join(ROOT, "data");
const CP_DIR = process.env.SHOMER_CHECKPOINT_DIR || path.resolve(DATA, "..", "shomer-checkpoints");
const KEY_PATH = process.env.SHOMER_CHECKPOINT_KEY_PATH || path.resolve(DATA, "..", "shomer-keys", "checkpoint_ed25519.pem");

const argv = process.argv.slice(2);
const argVal = (n, d) => { const i = argv.indexOf("--" + n); return i >= 0 && argv[i + 1] ? argv[i + 1] : d; };
const AGENT = argVal("agent", "refunds-prod");
const DAYS = Number(argVal("days", "14"));

const canonical = (v) => {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(canonical).join(",") + "]";
  return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canonical(v[k])).join(",") + "}";
};
const sha256 = (s) => crypto.createHash("sha256").update(s).digest("hex");

const ledgerPath = path.join(DATA, "ledger.jsonl");
const approvalsPath = path.join(DATA, "approvals.json");
if (!fs.existsSync(ledgerPath)) {
  console.error("no ledger found at " + ledgerPath + " - start the control plane once first (it seeds agents and creates the signing key)");
  process.exit(1);
}

const rows = fs.readFileSync(ledgerPath, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
let seq = rows.length ? rows[rows.length - 1].seq : 0;
let prevHash = rows.length ? rows[rows.length - 1].hash : "0".repeat(64);

const out = [];
const approvals = fs.existsSync(approvalsPath) ? JSON.parse(fs.readFileSync(approvalsPath, "utf8")) : [];

function append(payload) {
  seq += 1;
  const rec = { ...payload, seq, ts: payload.ts, prev_hash: prevHash };
  delete rec.hash;
  rec.hash = sha256(canonical(rec));
  prevHash = rec.hash;
  out.push(JSON.stringify(rec) + "\n");
  return rec;
}

let privateKey = null;
try {
  privateKey = crypto.createPrivateKey(fs.readFileSync(KEY_PATH, "utf8"));
} catch {
  // no key yet: create one (same scheme as the control plane) so the seed can checkpoint
  const gen = crypto.generateKeyPairSync("ed25519");
  fs.mkdirSync(path.dirname(KEY_PATH), { recursive: true });
  fs.writeFileSync(KEY_PATH, gen.privateKey.export({ type: "pkcs8", format: "pem" }).toString(), { mode: 0o600 });
  privateKey = gen.privateKey;
  console.log("created signing key at " + KEY_PATH);
}

let decisionCount = 0;
let spend = 0;
// day 0 (today) is left for LIVE demo traffic; history covers days 1..DAYS-1
for (let d = DAYS - 1; d >= 1; d--) {
  const day = new Date(Date.now() - d * 86400_000);
  const dow = day.getUTCDay();
  const base = dow === 0 || dow === 6 ? 12 : 34; // lighter weekends
  for (let i = 0; i < base; i++) {
    const ts = new Date(day.getTime() + (9 + (i % 9) * 60 + (i * 7) % 60) * 60000 + 2 * 3600000).toISOString();
    const roll = Math.random();
    const tool = roll < 0.45 ? "lookup_order" : roll < 0.75 ? "issue_refund" : "notify_customer";
    const did = crypto.randomUUID();
    if (tool === "issue_refund") {
      const amount = Math.round(Math.random() * 700 * 100) / 100;
      if (amount > 1000) {
        append({ type: "decision", decision_id: did, agent_id: AGENT, tool, decision: "deny", reason: "hard_cap_exceeded", policy_id: null, args_hash: sha256(String(did)), args_preview: '{"order_id":"O-' + i + '","amount_usd":' + amount + "}", ts });
        decisionCount++;
        continue;
      }
      const requiresHuman = amount > 100;
      const decision = requiresHuman ? "require_human" : "allow";
      append({
        type: "decision", decision_id: did, agent_id: AGENT, tool, decision,
        reason: requiresHuman ? "refund_above_100" : "policy_default_allow",
        policy_id: requiresHuman ? "threshold-h" : null,
        args_hash: sha256(String(did)), args_preview: '{"order_id":"O-' + i + '","amount_usd":' + amount + "}", ts,
      });
      decisionCount++;
      if (requiresHuman) {
        approvals.push({
          id: crypto.randomUUID(), decision_id: did, agent_id: AGENT, tool,
          args: { order_id: "O-" + i, amount_usd: amount }, args_hash: sha256(String(did)),
          reason: "refund_above_100", status: Math.random() < 0.85 ? "approved" : "denied",
          requested_at: ts, resolved_at: ts, resolved_by: "ops@acme.com", resolved_by_key_id: "key-ops-01",
        });
        const st = approvals[approvals.length - 1].status;
        append({ type: "outcome", decision_id: did, agent_id: AGENT, tool, status: st, cost_usd: 0, tokens: 0, actor: "ops@acme.com", args_hash: sha256(String(did)), binding_verified: true, result_preview: st === "approved" ? "human approved" : "human denied", ts });
        if (st === "approved") {
          const cost = 0.12 + Math.random() * 0.12;
          spend += cost;
          append({ type: "outcome", decision_id: did, agent_id: AGENT, tool, status: "succeeded", cost_usd: Math.round(cost * 1e4) / 1e4, tokens: 900 + Math.round(Math.random() * 400), cost_source: "broker_metered", result_preview: "refund issued", ts });
        }
        continue;
      }
      const cost = 0.12 + Math.random() * 0.12;
      spend += cost;
      append({ type: "outcome", decision_id: did, agent_id: AGENT, tool, status: "succeeded", cost_usd: Math.round(cost * 1e4) / 1e4, tokens: 900 + Math.round(Math.random() * 400), cost_source: "broker_metered", result_preview: "refund issued", ts });
    } else {
      const redacted = tool === "notify_customer" && Math.random() < 0.25;
      const decision = redacted ? "sanitize" : "allow";
      append({
        type: "decision", decision_id: did, agent_id: AGENT, tool, decision,
        reason: redacted ? "pii_redacted" : "policy_default_allow",
        policy_id: redacted ? "pii" : null,
        args_hash: sha256(String(did)), args_preview: redacted ? '{"customer_email":"[REDACTED:email]"}' : '{"order_id":"O-' + i + '"}', ts,
      });
      decisionCount++;
      const cost = tool === "lookup_order" ? 0.015 + Math.random() * 0.01 : 0.02 + Math.random() * 0.01;
      spend += cost;
      append({ type: "outcome", decision_id: did, agent_id: AGENT, tool, status: "succeeded", cost_usd: Math.round(cost * 1e4) / 1e4, tokens: 400 + Math.round(Math.random() * 300), cost_source: "broker_metered", result_preview: "ok", ts });
    }
  }
  // an occasional runaway-loop denial block per day
  for (let k = 0; k < 3; k++) {
    const did = crypto.randomUUID();
    const ts = new Date(day.getTime() + 17 * 3600000).toISOString();
    append({ type: "decision", decision_id: did, agent_id: AGENT, tool: "notify_customer", decision: "deny", reason: "runaway_loop_detected", policy_id: "loop", args_hash: sha256("loop-" + d + "-" + k), args_preview: '{"order_id":"O-L' + k + '"}', ts });
    decisionCount++;
  }
}

fs.appendFileSync(ledgerPath, out.join(""));
fs.writeFileSync(approvalsPath, JSON.stringify(approvals, null, 2));

let cp = null;
if (privateKey && out.length > 0) {
  const ts = new Date().toISOString();
  const sig = crypto.sign(null, Buffer.from(`${seq}|${prevHash}|${ts}`), privateKey).toString("hex");
  cp = { seq, ts, last_hash: prevHash, alg: "ed25519", pub_fp: "seeded", sig };
  fs.mkdirSync(CP_DIR, { recursive: true });
  fs.appendFileSync(path.join(CP_DIR, "checkpoints.jsonl"), JSON.stringify(cp) + "\n");
}

console.log(`seeded ${out.length} events (${decisionCount} decisions) over ${DAYS} days for ${AGENT}; simulated spend $${Math.round(spend * 100) / 100}`);
console.log(cp ? `checkpoint written at seq ${seq} (Ed25519)` : "checkpoint skipped (no signing key)");
console.log("next: npm run start && npm run pilot -- --agent " + AGENT + " --days " + DAYS);