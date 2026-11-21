/**
 * Pilot report - for the 14-day observe-only pilot (docs/observe-pilot.md).
 * Runs against a live control plane: collects the window's evidence, verifies
 * the chain, and exports an evidence pack (JSON + PDF).
 *
 * Usage:  npm run pilot -- --agent refunds-prod --days 14
 * Env:    SHOMER_URL (default http://localhost:8787), SHOMER_API_KEY (default data/DEV_KEY.txt)
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const argv = process.argv.slice(2);
const argVal = (name, dflt) => {
  const i = argv.indexOf("--" + name);
  return i >= 0 && argv[i + 1] ? argv[i + 1] : dflt;
};

const agentId = argVal("agent", "");
const days = Number(argVal("days", "14"));
if (!agentId) {
  console.error("usage: npm run pilot -- --agent <agent_id> [--days 14]");
  process.exit(1);
}

const BASE = process.env.SHOMER_URL || "http://localhost:8787";
const keyFile = path.join(ROOT, "data", "DEV_KEY.txt");
const KEY = process.env.SHOMER_API_KEY || (fs.existsSync(keyFile) ? fs.readFileSync(keyFile, "utf8").trim() : "");
if (!KEY) {
  console.error("no API key found: set SHOMER_API_KEY or run the control plane once");
  process.exit(1);
}
const H = { Authorization: "Bearer " + KEY };

const from = new Date(Date.now() - days * 86400_000).toISOString();
const to = new Date().toISOString();
const q = `agent_id=${encodeURIComponent(agentId)}&from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`;

const [agentsRes, evidence, verify] = await Promise.all([
  fetch(BASE + "/api/agents", { headers: H }).then((r) => r.json()),
  fetch(BASE + "/api/evidence?" + q, { headers: H }).then((r) => r.json()),
  fetch(BASE + "/v1/ledger/verify", { headers: H }).then((r) => r.json()),
]);

const agent = (agentsRes.agents || []).find((a) => a.id === agentId);
if (!agent) {
  console.error("agent not found: " + agentId);
  process.exit(1);
}
if (agent.enforcement !== "observe") {
  console.warn(`WARNING: ${agentId} is in ${agent.enforcement || "enforce"} mode. The pilot protocol expects observe mode.`);
}

const s = evidence.summary || {};
const byTool = {};
const byReason = {};
for (const d of evidence.decisions || []) {
  byTool[d.tool] = byTool[d.tool] || { total: 0, blocked: 0 };
  byTool[d.tool].total++;
  if (d.decision === "deny") byTool[d.tool].blocked++;
  if (d.decision === "deny") {
    const r = d.reason || "unknown";
    byReason[r] = (byReason[r] || 0) + 1;
  }
}

const lines = [];
const row = (l) => lines.push(l);
row(`# Shomer pilot report - ${agentId}`);
row(``);
row(`- window: ${from.slice(0, 10)} .. ${to.slice(0, 10)} (${days} days)`);
row(`- agent: ${agent.name} (mode: ${agent.enforcement || "enforce"})`);
row(`- chain verification: ${verify.valid ? "VALID" : "INVALID: " + verify.why} (length ${verify.length}, checkpoint seq ${verify.checkpoint?.seq ?? "none"})`);
row(`- open window: ${verify.open_window?.records_since_checkpoint ?? "?"} records since checkpoint (policy: every ${verify.open_window?.policy?.every_records ?? "?"} records / ${verify.open_window?.policy?.every_seconds ?? "?"}s)`);
row(``);
row(`## Numbers`);
row(`- actions governed: ${s.actions_governed}`);
row(`- allowed / sanitized: ${s.allowed} / ${s.sanitized}`);
row(`- blocked: ${s.blocked}`);
row(`- human reviews: ${s.human_reviews}`);
row(`- observe-only would-be blocks: ${s.observe_only}`);
row(`- metered spend (USD): ${s.metered_spend_usd}`);
row(``);
row(`## Per tool`);
for (const [tool, v] of Object.entries(byTool)) row(`- ${tool}: ${v.total} actions, ${v.blocked} blocked`);
row(``);
row(`## Block reasons`);
for (const [reason, n] of Object.entries(byReason)) row(`- ${reason}: ${n}`);

const outDir = path.join(ROOT, "pilot-out");
fs.mkdirSync(outDir, { recursive: true });
const stamp = new Date().toISOString().slice(0, 10);
fs.writeFileSync(path.join(outDir, `pilot-${agentId}-${stamp}.md`), lines.join("\n") + "\n");
fs.writeFileSync(path.join(outDir, `evidence-${agentId}-${stamp}.json`), JSON.stringify(evidence, null, 2));
try {
  const pdfResp = await fetch(
    BASE + "/api/evidence/export?format=pdf&agent_id=" + encodeURIComponent(agentId) + "&from=" + encodeURIComponent(from) + "&to=" + encodeURIComponent(to),
    { headers: H }
  );
  fs.writeFileSync(path.join(outDir, `evidence-${agentId}-${stamp}.pdf`), Buffer.from(await pdfResp.arrayBuffer()));
} catch {
  console.warn("PDF export failed (non-fatal)");
}

console.log(lines.join("\n"));
console.log(`\nArtifacts written to ${outDir}:`);
console.log(`  - pilot-${agentId}-${stamp}.md`);
console.log(`  - evidence-${agentId}-${stamp}.json`);
console.log(`  - evidence-${agentId}-${stamp}.pdf`);
process.exit(verify.valid ? 0 : 2);