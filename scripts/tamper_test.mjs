/**
 * Tamper test: mutate one ledger line -> verify must FAIL.
 * Spins up its own control plane on a temp data dir. Usage: node scripts/tamper_test.mjs
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const PORT = 8791;
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "shomer-tamper-"));

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
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

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

let failures = 0;
const check = (name, cond, extra = "") => {
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${extra ? "  -> " + extra : ""}`);
  if (!cond) failures++;
};

try {
  if (!(await waitUp())) throw new Error("server did not start: " + stderr.slice(0, 400));
  const KEY = fs.readFileSync(path.join(TMP, "DEV_KEY.txt"), "utf8").trim();
  const H = { "Content-Type": "application/json", Authorization: "Bearer " + KEY };
  const evaluate = (b) => fetch(B + "/v1/evaluate", { method: "POST", headers: H, body: JSON.stringify(b) }).then((r) => r.json());

  await evaluate({ agent_id: "refunds-prod", tool: "lookup_order", args: { order_id: "T-1" }, estimated_cost_usd: 0.02 });
  await evaluate({ agent_id: "refunds-prod", tool: "lookup_order", args: { order_id: "T-2" }, estimated_cost_usd: 0.02 });
  await evaluate({ agent_id: "refunds-prod", tool: "lookup_order", args: { order_id: "T-3" }, estimated_cost_usd: 0.02 });

  const ledgerPath = path.join(TMP, "ledger.jsonl");
  const before = await fetch(B + "/v1/ledger/verify", { headers: H }).then((r) => r.json());
  check("pre-tamper: chain valid", before.valid === true && before.length >= 3, `length=${before.length}`);

  // mutate a hex char in the prev_hash of the SECOND record -> breaks the link
  const lines = fs.readFileSync(ledgerPath, "utf8").split("\n").filter(Boolean);
  const target = 1;
  lines[target] = lines[target].replace(/"prev_hash":"[0-9a-f]/, (m) => m.slice(0, -1) + (m.slice(-1) === "a" ? "b" : "a"));
  fs.writeFileSync(ledgerPath, lines.join("\n") + "\n");

  const after = await fetch(B + "/v1/ledger/verify", { headers: H }).then((r) => r.json());
  check("post-tamper: verify FAILS", after.valid === false && !!after.first_invalid_seq, JSON.stringify(after));
  check("post-tamper: failure reason is structural", ["record_hash_mismatch", "broken_link"].includes(after.why), after.why);
} catch (e) {
  console.error("FAIL: unexpected error:", e.message);
  failures++;
} finally {
  child.kill();
  fs.rmSync(TMP, { recursive: true, force: true });
}
console.log(failures === 0 ? "\nTAMPER TEST PASSED" : `\n${failures} TAMPER CHECK(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);