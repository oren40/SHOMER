/**
 * Ledger-write-failure test: if the ledger cannot be written, evaluate must FAIL CLOSED.
 * Spins up an isolated control plane, deletes its data dir mid-flight, then asserts deny.
 * Usage: node scripts/ledger_failure_test.mjs
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const PORT = 8793;
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "shomer-failclosed-"));
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
  env: { ...process.env, PORT: String(PORT), SHOMER_DATA_DIR: TMP },
  stdio: ["ignore", "ignore", "pipe"],
});
let stderr = "";
child.stderr.on("data", (d) => (stderr += d));

const B = `http://localhost:${PORT}`;
async function waitUp() {
  for (let i = 0; i < 40; i++) {
    try {
      await fetch(B + "/api/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ key: "" }) });
      return true;
    } catch {
      await sleep(250);
    }
  }
  return false;
}

try {
  if (!(await waitUp())) throw new Error("server did not start: " + stderr.slice(0, 400));
  const KEY = fs.readFileSync(path.join(TMP, "DEV_KEY.txt"), "utf8").trim();
  const H = { "Content-Type": "application/json", Authorization: "Bearer " + KEY };
  const evaluate = (b) => fetch(B + "/v1/evaluate", { method: "POST", headers: H, body: JSON.stringify(b) }).then((r) => r.json());

  const r1 = await evaluate({ agent_id: "refunds-prod", tool: "lookup_order", args: { order_id: "F-1" }, estimated_cost_usd: 0.02 });
  check("before failure: call allowed + recorded", r1.decision === "allow");

  // sabotage: remove the ledger store out from under the running process
  fs.rmSync(TMP, { recursive: true, force: true });
  // make the ledger path unwritable: a FILE where the data dir used to be
  fs.writeFileSync(TMP, "not-a-directory");

  const r2 = await evaluate({ agent_id: "refunds-prod", tool: "lookup_order", args: { order_id: "F-2" }, estimated_cost_usd: 0.02 });
  check("ledger write fails -> FAIL CLOSED (deny)", r2.decision === "deny" && r2.reason === "ledger_append_failed", r2.reason);
  check("fail-closed verdict is not allowed", r2.allowed === false);

  // server process itself must still be alive afterwards
  const alive = await fetch(B + "/api/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ key: KEY }) }).then((r) => r.status);
  check("control plane still serves after failure", alive === 200);
} catch (e) {
  console.error("FAIL: unexpected error:", e.message);
  failures++;
} finally {
  child.kill();
  fs.rmSync(TMP, { recursive: true, force: true });
  // make the ledger path unwritable: a FILE where the data dir used to be
  fs.writeFileSync(TMP, "not-a-directory");
}
console.log(failures === 0 ? "\nLEDGER-FAILURE TEST PASSED" : `\n${failures} FAIL-CLOSED CHECK(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);