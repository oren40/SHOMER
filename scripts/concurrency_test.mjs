/**
 * Concurrency test: 200 parallel /v1/evaluate calls must produce a VALID chain
 * with EXACTLY 200 ledger entries - appends are serialized so log-before-act
 * and chain integrity hold under load.
 * Usage: node scripts/concurrency_test.mjs
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const PORT = 8795;
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "shomer-conc-"));
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
  const N = 200;
  const calls = [];
  for (let i = 0; i < N; i++) {
    calls.push(
      fetch(B + "/v1/evaluate", {
        method: "POST",
        headers: H,
        // distinct args per call so runaway-loop detection does not interfere
        body: JSON.stringify({ agent_id: "refunds-prod", tool: "lookup_order", args: { order_id: "C-" + i }, estimated_cost_usd: 0.02 }),
      }).then((r) => r.json())
    );
  }
  const results = await Promise.all(calls);
  check(`all ${N} concurrent calls returned a verdict`, results.length === N && results.every((r) => r.decision !== undefined));
  check("each returned a unique decision_id", new Set(results.map((r) => r.decision_id)).size === N);

  const v = await fetch(B + "/v1/ledger/verify", { headers: H }).then((r) => r.json());
  check("chain valid after 200 concurrent appends", v.valid === true, JSON.stringify(v).slice(0, 160));
  check(`exactly ${N} ledger entries`, v.length === N, `length=${v.length}`);

  const ev = (await fetch(B + "/v1/ledger?limit=1000", { headers: H }).then((r) => r.json())).events;
  const seqs = ev.map((e) => e.seq);
  check("seqs are unique", new Set(seqs).size === N);
  check("seqs are contiguous 1..N", Math.min(...seqs) === 1 && Math.max(...seqs) === N && seqs.length === N);
  const cps = await fetch(B + "/api/checkpoints", { headers: H }).then((r) => r.json());
  check("Ed25519 checkpoint written and signature valid", cps.latest?.signature_valid === true && !!cps.public_key_pem, `seq=${cps.latest?.seq} fp=${cps.public_key_fingerprint}`);
} catch (e) {
  console.error("FAIL: unexpected error:", e.message);
  failures++;
} finally {
  child.kill();
  fs.rmSync(TMP, { recursive: true, force: true });
}
console.log(failures === 0 ? "\nCONCURRENCY TEST PASSED" : `\n${failures} CONCURRENCY CHECK(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);