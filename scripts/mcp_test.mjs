/**
 * MCP conformance + SSRF test.
 * Acts as a real MCP client over Streamable HTTP: initialize -> notifications/initialized
 * -> tools/list -> tools/call, and proves broker hardening (destination allowlist,
 * blocked IP ranges, literal-secret rejection).
 * Usage: node scripts/mcp_test.mjs
 */
import fs from "node:fs";
import os from "node:os";
import http from "node:http";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const PORT = 8794;
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "shomer-mcp-"));
const TOOL_SECRET = "broker-only-secret-xyz";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let failures = 0;
const check = (name, cond, extra = "") => {
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${extra ? "  -> " + extra : ""}`);
  if (!cond) failures++;
};

const mock = http.createServer((req, res) => {
  if (req.headers["x-tool-secret"] !== TOOL_SECRET) {
    res.writeHead(401, { "Content-Type": "application/json" });
    return res.end(JSON.stringify({ error: "credential required" }));
  }
  let body = "";
  req.on("data", (c) => (body += c));
  req.on("end", () => {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(
      JSON.stringify({
        result: { echo: JSON.parse(body || "{}"), receipt: "paid-777" },
        usage: { model: "mcp-demo-model", input_tokens: 1000, output_tokens: 500 },
      })
    );
  });
});
await new Promise((r) => mock.listen(0, "127.0.0.1", r));
const MOCK_PORT = mock.address().port;

const tsx = path.join(ROOT, "node_modules", "tsx", "dist", "cli.mjs");
if (!fs.existsSync(tsx)) {
  console.error("FAIL: tsx not found - run npm install first");
  process.exit(1);
}
const child = spawn(process.execPath, [tsx, "src/index.ts"], {
  cwd: ROOT,
  env: { ...process.env, PORT: String(PORT), SHOMER_DATA_DIR: TMP, TOOL_SECRET },
  stdio: ["ignore", "ignore", "pipe"],
});
let stderr = "";
child.stderr.on("data", (d) => (stderr += d));

const B = `http://localhost:${PORT}`;
async function waitUp() {
  for (let i = 0; i < 60; i++) {
    try {
      await fetch(B + "/api/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ key: "" }) });
      return true;
    } catch {
      await sleep(250);
    }
  }
  return false;
}

/** A real MCP client: JSON-RPC 2.0 over HTTP POST. */
class McpClient {
  constructor(url, key) {
    this.url = url;
    this.key = key;
    this.n = 0;
  }
  async rpc(method, params) {
    this.n += 1;
    const res = await fetch(this.url, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream", Authorization: "Bearer " + this.key },
      body: JSON.stringify({ jsonrpc: "2.0", id: this.n, method, params }),
    });
    const text = await res.text();
    return { status: res.status, body: text.startsWith("{") ? JSON.parse(text) : { raw: text } };
  }
}

try {
  if (!(await waitUp())) throw new Error("control plane did not start: " + stderr.slice(0, 600));
  const KEY = fs.readFileSync(path.join(TMP, "DEV_KEY.txt"), "utf8").trim();
  const H = { "Content-Type": "application/json", Authorization: "Bearer " + KEY };
  const jpost = (p, b) => fetch(B + p, { method: "POST", headers: H, body: JSON.stringify(b) }).then(async (r) => ({ status: r.status, body: await r.json().catch(() => ({})) }));

  // setup: tool with destination allowlist (127.0.0.1), agent, policy, pricing
  const reg = await jpost("/api/credentials", {
    name: "invoice-system",
    kind: "http",
    url: `http://127.0.0.1:${MOCK_PORT}`,
    allow_private: true,
    allowed_hosts: ["127.0.0.1"],
    auth_header: "x-tool-secret",
    auth_env: "TOOL_SECRET",
    description: "invoice API (MCP test)",
  });
  check("register tool with allowlist", reg.status === 200);
  await jpost("/api/agents", { id: "mcp-agent", name: "MCP Test Agent", daily_budget_usd: 5 });
  await jpost("/api/policies", { agent_id: "mcp-agent", type: "tool_allowlist", config: { tools: ["invoice-system"] }, priority: 40 });
  await jpost("/api/pricing", { model: "mcp-demo-model", input_per_mtok: 1, output_per_mtok: 2 });

  // ---- MCP spec conformance over Streamable HTTP ----
  const mcp = new McpClient(B + "/mcp", KEY);
  const init = await mcp.rpc("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "shomer-test-client", version: "0.1" } });
  check("initialize: protocol negotiated", init.body?.result?.protocolVersion === "2025-06-18" && init.body?.result?.capabilities?.tools !== undefined, JSON.stringify(init.body?.result?.serverInfo));

  const inited = await mcp.rpc("notifications/initialized", {});
  check("notifications/initialized: acknowledged", inited.status === 202);

  const ping = await mcp.rpc("ping", {});
  check("ping", ping.body?.result !== undefined);

  const list = await mcp.rpc("tools/list", {});
  const names = (list.body?.result?.tools ?? []).map((t) => t.name);
  check("tools/list: governed tools exposed", names.includes("invoice-system"), names.join(","));

  const call = await mcp.rpc("tools/call", { name: "invoice-system", _agent_id: "mcp-agent", arguments: { order_id: "M-1", amount: 42 } });
  const text = call.body?.result?.content?.[0]?.text ?? "";
  check("tools/call: legal call succeeds", call.body?.result?.isError === false && text.includes("paid-777"), call.body?.result?.isError);
  check("tools/call: result metered by broker", call.body?.result?.structuredContent?.receipt === "paid-777");

  const badAgent = await mcp.rpc("tools/call", { name: "invoice-system", _agent_id: "refunds-prod", arguments: { x: 1 } });
  check("tools/call: non-allowlisted agent -> isError with decision", badAgent.body?.result?.isError === true && badAgent.body?.result?.content?.[0]?.text?.includes("tool_not_allowed"));

  const notFound = await mcp.rpc("resources/list", {});
  check("unknown method -> JSON-RPC -32601", notFound.body?.error?.code === -32601, notFound.body?.error?.message);

  // ---- SSRF / secret hardening ----
  const meta = await jpost("/api/credentials", { name: "sneaky-meta", kind: "http", url: "http://169.254.169.254/latest/meta-data/" });
  check("SSRF: cloud metadata IP blocked at registration", meta.status === 400, meta.body?.error);
  const loki = await jpost("/api/credentials", { name: "sneaky-local", kind: "http", url: "http://127.0.0.1:1/x", allowed_hosts: ["api.example.com"] });
  check("SSRF: destination allowlist enforced", loki.status === 400, loki.body?.error);
  const secretLeak = await jpost("/api/credentials", { name: "sneaky-secret", kind: "http", url: "https://api.example.com/x", auth_header: "Authorization", auth_value: "sk-super-secret" });
  check("SSRF: literal secret value rejected", secretLeak.status === 400, secretLeak.body?.error);
  const credsInUrl = await jpost("/api/credentials", { name: "sneaky-url", kind: "http", url: "https://user:pass@api.example.com/x" });
  check("SSRF: URL-embedded credentials rejected", credsInUrl.status === 400, credsInUrl.body?.error);
} catch (e) {
  console.error("FAIL: unexpected error:", e.message);
  failures++;
} finally {
  child.kill();
  mock.close();
  fs.rmSync(TMP, { recursive: true, force: true });
}
console.log(failures === 0 ? "\nMCP CONFORMANCE TEST PASSED" : `\n${failures} MCP CHECK(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);