/**
 * SSRF + DNS-rebinding test.
 *
 * A hostile DNS server answers "rebind.test" with 127.0.0.2 first and
 * 127.0.0.1 afterwards. The tool permits only 127.0.0.2/32.
 * Expected: call 1 succeeds against the PINNED 127.0.0.2 server (and the
 * 127.0.0.1 impostor never receives anything), call 2 is blocked.
 * Also covers IPv4-mapped IPv6 and numeric-IP encodings.
 * Usage: node scripts/ssrf_rebind_test.mjs
 */
import fs from "node:fs";
import os from "node:os";
import http from "node:http";
import dgram from "node:dgram";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const PORT = 8798;
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "shomer-rebind-"));
const TOOL_SECRET = "broker-only-secret-xyz";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let failures = 0;
const check = (name, cond, extra = "") => {
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${extra ? "  -> " + extra : ""}`);
  if (!cond) failures++;
};

const hits = { good: 0, bad: 0 };
const makeMock = (label, counter) =>
  http.createServer((req, res) => {
    if (req.headers["x-tool-secret"] !== TOOL_SECRET) {
      res.writeHead(401);
      return res.end(JSON.stringify({ error: "credential required" }));
    }
    counter.count++;
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          result: { served_by: label, echo: JSON.parse(body || "{}") },
          usage: { model: "rebind-model", input_tokens: 1000, output_tokens: 500 },
        })
      );
    });
  });

const mockGood = makeMock("127.0.0.2", { get count() { return hits.good; }, set count(v) { hits.good = v; } });
const mockBad = makeMock("127.0.0.1", { get count() { return hits.bad; }, set count(v) { hits.bad = v; } });

await new Promise((r) => mockGood.listen(0, "127.0.0.2", r));
await new Promise((r) => mockBad.listen(0, "127.0.0.1", r));
const GOOD_PORT = mockGood.address().port;

/* ---- hostile DNS: first answer 127.0.0.2, then 127.0.0.1 ---- */
const queryCount = new Map();
const dnsServer = dgram.createSocket("udp4");
const DNS_PORT = 5354;
await new Promise((r) => dnsServer.bind(DNS_PORT, "127.0.0.1", r));
dnsServer.on("message", (msg, rinfo) => {
  const id = msg.subarray(0, 2);
  let off = 12;
  const labels = [];
  while (msg[off] !== 0) {
    const len = msg[off++];
    labels.push(msg.subarray(off, off + len).toString());
    off += len;
  }
  off++;
  const qname = labels.join(".");
  const n = (queryCount.get(qname) ?? 0) + 1;
  queryCount.set(qname, n);
  // first two lookups (registration + call 1) are legit; the rebind starts after that
  const ip = n <= 2 ? [127, 0, 0, 2] : [127, 0, 0, 1];
  const header = Buffer.concat([
    id,
    Buffer.from([0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]),
  ]);
  const question = msg.subarray(12, off + 4); // qname + qtype + qclass
  const answer = Buffer.concat([
    Buffer.from([0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04]),
    Buffer.from(ip),
  ]);
  dnsServer.send(Buffer.concat([header, question, answer]), rinfo.port, rinfo.address);
});

const tsx = path.join(ROOT, "node_modules", "tsx", "dist", "cli.mjs");
if (!fs.existsSync(tsx)) {
  console.error("FAIL: tsx not found - run npm install first");
  process.exit(1);
}
const child = spawn(process.execPath, [tsx, "src/index.ts"], {
  cwd: ROOT,
  env: {
    ...process.env,
    PORT: String(PORT),
    SHOMER_DATA_DIR: TMP,
    SHOMER_CHECKPOINT_DIR: path.join(TMP, "checkpoints"),
    SHOMER_CHECKPOINT_KEY_PATH: path.join(TMP, "keys", "cp.pem"),
    SHOMER_DNS_SERVERS: `127.0.0.1:${DNS_PORT}`,
    TOOL_SECRET,
  },
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
  const jpost = (p, b) => fetch(B + p, { method: "POST", headers: H, body: JSON.stringify(b) }).then(async (r) => ({ status: r.status, body: await r.json().catch(() => ({})) }));

  // encodings that must be refused
  const mapped = await jpost("/api/credentials", { name: "sneaky-mapped", kind: "http", url: "http://[::ffff:127.0.0.1]/x" });
  check("IPv4-mapped IPv6 normalized and blocked", mapped.status === 400, mapped.body?.error);
  const numeric = await jpost("/api/credentials", { name: "sneaky-decimal", kind: "http", url: "http://2130706433/x" });
  check("decimal-encoded IP normalized and blocked", numeric.status === 400, numeric.body?.error);
  const legacy = await jpost("/api/credentials", { name: "sneaky-hex", kind: "http", url: "http://0x7f.0.0.1/x" });
  check("hex-encoded IP normalized and blocked", legacy.status === 400, legacy.body?.error);

  // the tool under test: only 127.0.0.2/32 permitted, via a hostname that flips DNS
  const reg = await jpost("/api/credentials", {
    name: "rebind-tool",
    kind: "http",
    url: `http://rebind.test:${GOOD_PORT}`,
    allowed_hosts: ["rebind.test"],
    allowed_cidrs: ["127.0.0.2/32"],
    auth_header: "x-tool-secret",
    auth_env: "TOOL_SECRET",
  });
  check("register rebind tool (127.0.0.2/32 only)", reg.status === 200, reg.body?.error);

  await jpost("/api/agents", { id: "rebind-agent", name: "Rebind Agent", daily_budget_usd: 5 });
  await jpost("/api/policies", { agent_id: "rebind-agent", type: "tool_allowlist", config: { tools: ["rebind-tool"] }, priority: 40 });
  await jpost("/api/pricing", { model: "rebind-model", input_per_mtok: 1, output_per_mtok: 2 });

  // call 1: DNS answers 127.0.0.2 -> allowed, connection PINNED there
  const c1 = await jpost("/mcp/v1/tools/rebind-tool/call", { agent_id: "rebind-agent", args: { probe: 1 } });
  check("call 1: allowed against the validated IP", c1.body.ok === true, c1.body.error ?? c1.body.status);
  check("call 1: served by the pinned 127.0.0.2 server", c1.body.result?.served_by === "127.0.0.2", JSON.stringify(c1.body.result ?? {}).slice(0, 120));
  check("pinning: the 127.0.0.1 impostor never received a request", hits.bad === 0, `bad_hits=${hits.bad}`);

  // call 2: DNS now answers 127.0.0.1 -> outside the CIDR allowlist -> blocked
  const c2 = await jpost("/mcp/v1/tools/rebind-tool/call", { agent_id: "rebind-agent", args: { probe: 2 } });
  check("call 2: post-rebind destination blocked", c2.body.ok === false && c2.body.status === "destination_blocked", c2.body.error);
  check("pinning: still no request to the impostor", hits.bad === 0, `bad_hits=${hits.bad}`);

  const led = await fetch(B + "/v1/ledger?limit=50", { headers: H }).then((r) => r.json());
  const blocked = led.events.find((e) => e.type === "outcome" && e.status === "destination_blocked");
  check("ledger: blocked attempt recorded", !!blocked);
} catch (e) {
  console.error("FAIL: unexpected error:", e.message);
  failures++;
} finally {
  child.kill();
  mockGood.close();
  mockBad.close();
  dnsServer.close();
  fs.rmSync(TMP, { recursive: true, force: true });
}
console.log(failures === 0 ? "\nSSRF REBIND TEST PASSED" : `\n${failures} SSRF CHECK(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);