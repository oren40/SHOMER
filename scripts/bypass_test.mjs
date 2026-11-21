/**
 * Bypass test: the control plane is the only path to the credential.
 * Spins up a mock tool server + an isolated control plane, then proves:
 *   1. direct calls to the tool without the broker secret -> rejected
 *   2. unauthorized / wrong-scope calls to the broker -> 401/403
 *   3. calls via the broker succeed, are metered from REAL usage, and land in the ledger
 * Usage: node scripts/bypass_test.mjs
 */
import fs from "node:fs";
import os from "node:os";
import http from "node:http";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const PORT = 8792;
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "shomer-bypass-"));
const TOOL_SECRET = "broker-only-secret-xyz";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let failures = 0;
const check = (name, cond, extra = "") => {
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${extra ? "  -> " + extra : ""}`);
  if (!cond) failures++;
};

/* ---------------- mock tool server ---------------- */
const mock = http.createServer((req, res) => {
  if (req.headers["x-tool-secret"] !== TOOL_SECRET) {
    res.writeHead(401, { "Content-Type": "application/json" });
    return res.end(JSON.stringify({ error: "credential required - talk to the broker" }));
  }
  let body = "";
  req.on("data", (c) => (body += c));
  req.on("end", () => {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(
      JSON.stringify({
        result: { echo: JSON.parse(body || "{}"), receipt: "paid-991" },
        usage: { model: "demo-model-1", input_tokens: 1000, output_tokens: 500 },
      })
    );
  });
});
await new Promise((r) => mock.listen(0, "127.0.0.1", r));
const MOCK_PORT = mock.address().port;
const B = `http://localhost:${PORT}`;

/* ---------------- isolated control plane ---------------- */
const tsx = path.join(ROOT, "node_modules", "tsx", "dist", "cli.mjs");
if (!fs.existsSync(tsx)) {
  console.error("FAIL: tsx not found - run npm install first");
  process.exit(1);
}
const child = spawn(process.execPath, [tsx, "src/index.ts"], {
  cwd: ROOT,
  env: { ...process.env, PORT: String(PORT), SHOMER_DATA_DIR: TMP, SHOMER_CHECKPOINT_DIR: path.join(TMP, "checkpoints"), SHOMER_CHECKPOINT_KEY_PATH: path.join(TMP, "keys", "cp.pem"), TOOL_SECRET },
  stdio: ["ignore", "ignore", "pipe"],
});
let stderr = "";
child.stderr.on("data", (d) => (stderr += d));

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
  if (!(await waitUp())) throw new Error("control plane did not start: " + stderr.slice(0, 400));
  const KEY = fs.readFileSync(path.join(TMP, "DEV_KEY.txt"), "utf8").trim();
  const H = { "Content-Type": "application/json", Authorization: "Bearer " + KEY };
  const jpost = (p, b, h) => fetch(B + p, { method: "POST", headers: { ...(h || H) }, body: b ? JSON.stringify(b) : undefined }).then(async (r) => ({ status: r.status, body: await r.json().catch(() => ({})) }));

  // register the tool (holds the secret reference), the allowlist policy and pricing
  check("register tool", (await jpost("/api/credentials", { name: "invoice-system", kind: "http", url: `http://127.0.0.1:${MOCK_PORT}`, allowed_cidrs: ["127.0.0.0/8"], allowed_hosts: ["127.0.0.1"], auth_header: "x-tool-secret", auth_env: "TOOL_SECRET", description: "mock invoice system" })).status === 200);
  await jpost("/api/agents", { id: "broker-agent", name: "Broker Test Agent", daily_budget_usd: 5 });
  const pol = (await jpost("/api/policies", { agent_id: "broker-agent", type: "tool_allowlist", config: { tools: ["invoice-system"] }, priority: 40 })).body;
  await jpost("/api/pricing", { model: "demo-model-1", input_per_mtok: 1, output_per_mtok: 2 });

  // 1) direct call to the tool WITHOUT the credential -> must be rejected
  const direct = await fetch(`http://127.0.0.1:${MOCK_PORT}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ order_id: "X-1" }),
  });
  check("bypass attempt: direct tool call without credential -> 401", direct.status === 401);

  // 2) unauthorized + wrong-scope broker calls
  const noAuth = await jpost("/mcp/v1/tools/invoice-system/call", { agent_id: "broker-agent", args: { order_id: "X-1" } }, { "Content-Type": "application/json" });
  check("broker: no key -> 401", noAuth.status === 401);
  const otherKey = await jpost("/api/keys", { name: "bypass-other", scopes: ["agent:someoneelse"] });
  const wrongScope = await jpost("/mcp/v1/tools/invoice-system/call", { agent_id: "broker-agent", args: { order_id: "X-1" } }, { "Content-Type": "application/json", Authorization: "Bearer " + otherKey.body.key });
  check("broker: wrong agent scope -> 403", wrongScope.status === 403);

  // 3) legal broker call: allowed, metered from REAL usage, recorded
  const ok = await jpost("/mcp/v1/tools/invoice-system/call", { agent_id: "broker-agent", args: { order_id: "X-2", amount: 42 } });
  check("broker: legal call succeeds", ok.status === 200 && ok.body.ok === true);
  const expectedCost = (1000 / 1e6) * 1 + (500 / 1e6) * 2; // 0.002 from the pricing catalog
  check("metering: cost from real usage (not agent estimate)", Math.abs((ok.body.cost_usd ?? 0) - expectedCost) < 1e-9 && ok.body.cost_source === "broker_metered", `cost=${ok.body.cost_usd}`);
  const led = await fetch(B + "/v1/ledger?limit=50", { headers: H }).then((r) => r.json());
  const outcomeEvt = led.events.find((e) => e.type === "outcome" && e.cost_source === "broker_metered" && e.cost_usd === expectedCost);
  check("ledger: brokered call recorded once", !!outcomeEvt);

  // 4) tool NOT on the allowlist -> blocked at the broker, never executed
  const blocked = await jpost("/mcp/v1/tools/invoice-system/call", { agent_id: "refunds-prod", args: { order_id: "X-3" } });
  check("broker: non-allowlisted agent -> denied", blocked.status === 200 && blocked.body.ok === false && blocked.body.decision?.reason === "tool_not_allowed", blocked.body.decision?.reason);

  // 5) unregistered tool -> not executed
  const unknown = await jpost("/mcp/v1/tools/ghost-system/call", { agent_id: "broker-agent", args: {} });
  check("broker: unregistered tool -> not executed", unknown.status === 200 && unknown.body.ok === false && unknown.body.decision?.decision === "deny", unknown.body.decision?.reason);

  // 6) secret never returned to the client
  const raw = JSON.stringify(ok.body);
  check("broker: secret not leaked to caller", !raw.includes(TOOL_SECRET));
} catch (e) {
  console.error("FAIL: unexpected error:", e.message);
  failures++;
} finally {
  child.kill();
  mock.close();
  fs.rmSync(TMP, { recursive: true, force: true });
}
console.log(failures === 0 ? "\nBYPASS TEST PASSED" : `\n${failures} BYPASS CHECK(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);