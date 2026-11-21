/**
 * Tail-truncation test: deleting the last N ledger lines must be detectable.
 * With a checkpoint at seq 25 and only 20 records left, verify must FAIL with
 * ledger_behind_checkpoint (an external reviewer holding the checkpoint wins).
 * Usage: node scripts/tail_truncation_test.mjs
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const PORT = 8796;
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "shomer-trunc-"));
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
  const KEY = fs.readFileSync(path.join(TMP, "DEV_KEY.txt"), "utf8").trim();
  const H = { "Content-Type": "application/json", Authorization: "Bearer " + KEY };

  for (let i = 0; i < 30; i++) {
    await fetch(B + "/v1/evaluate", {
      method: "POST",
      headers: H,
      body: JSON.stringify({ agent_id: "refunds-prod", tool: "lookup_order", args: { order_id: "TR-" + i }, estimated_cost_usd: 0.02 }),
    });
  }
  const before = await fetch(B + "/v1/ledger/verify", { headers: H }).then((r) => r.json());
  check("pre-truncation: chain valid", before.valid === true && before.length === 30, `length=${before.length}`);
  check("checkpoint exists at seq>=25", before.checkpoint?.seq >= 25 && before.checkpoint?.seq <= 30, JSON.stringify(before.checkpoint));

  // delete the last 10 ledger lines (30 -> 20), leaving the seq-25 checkpoint unfulfilled
  const ledgerPath = path.join(TMP, "ledger.jsonl");
  const lines = fs.readFileSync(ledgerPath, "utf8").split("\n").filter(Boolean);
  fs.writeFileSync(ledgerPath, lines.slice(0, 20).join("\n") + "\n");

  const after = await fetch(B + "/v1/ledger/verify", { headers: H }).then((r) => r.json());
  check("post-truncation: verify FAILS", after.valid === false, JSON.stringify(after).slice(0, 200));
  check("post-truncation: detected as rollback", after.why === "ledger_behind_checkpoint", after.why);

  // an external verifier with the public key must also see the break
  const cps = await fetch(B + "/api/checkpoints", { headers: H }).then((r) => r.json());
  check("public key exportable for external verification", typeof cps.public_key_pem === "string" && cps.public_key_pem.includes("BEGIN PUBLIC KEY"));
} catch (e) {
  console.error("FAIL: unexpected error:", e.message);
  failures++;
} finally {
  child.kill();
  fs.rmSync(TMP, { recursive: true, force: true });
}
console.log(failures === 0 ? "\nTAIL-TRUNCATION TEST PASSED" : `\n${failures} TRUNCATION CHECK(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);