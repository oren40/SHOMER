/**
 * Credential broker + metered gateway - hardened (v0.2.3).
 *
 * The agent calls the control plane, not the tool. The control plane:
 *   1. evaluates the call against policy (same engine as the SDK path),
 *   2. resolves + validates the destination and PINS the connection to a
 *      validated IP (closes the DNS-rebinding window),
 *   3. executes server-side with the credential injected,
 *   4. meters the ACTUAL usage from the response,
 *   5. records one ledger entry.
 *
 * Destination policy (per tool):
 *   - allowed_hosts: hostname allowlist (optional)
 *   - allowed_cidrs: CIDR allowlist (optional). If set, ONLY those ranges are
 *     permitted. If not set, the default is public-only (private/loopback/
 *     link-local/CGNAT/benchmark/multicast ranges are refused).
 *   - the old global allow_private flag is gone.
 * IPv4-mapped IPv6 and legacy numeric encodings (0x7f.., 127., 2130706433) are
 * normalized before validation.
 */
import { spawn } from "node:child_process";
import dns from "node:dns/promises";
import { setServers } from "node:dns";
import net from "node:net";
import http from "node:http";
import https from "node:https";
import { db } from "./store";
import { evaluate } from "./policy";
import { spentToday } from "./ledger";

export interface BrokerResult {
  ok: boolean;
  decision?: any;
  decision_id?: string;
  result?: any;
  cost_usd?: number;
  cost_source?: "broker_metered" | "broker_unmetered";
  spent_today_usd?: number;
  status?: string;
  error?: string;
}

/* Custom resolvers (used by tests and on-prem DNS pinning). Affects dns.resolve4. */
const DNS_SERVERS = process.env.SHOMER_DNS_SERVERS || "";
if (DNS_SERVERS) {
  try {
    setServers(DNS_SERVERS.split(",").map((x) => x.trim()).filter(Boolean));
  } catch {
    /* ignore: fall back to the system resolver */
  }
}

const MAX_RESPONSE_BYTES = Number(process.env.SHOMER_BROKER_MAX_RESPONSE_BYTES || 1_000_000);

/* ---------------- destination policy ---------------- */

const DEFAULT_BLOCKED_V4_CIDRS = [
  "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
  "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16",
  "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
];
const DEFAULT_BLOCKED_V6_PREFIXES = ["::", "::1", "fc", "fd", "fe", "ff"];

function ipv4ToLong(ip: string): number | null {
  const p = ip.split(".");
  if (p.length !== 4) return null;
  let n = 0;
  for (const part of p) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const v = Number(part);
    if (v > 255) return null;
    n = n * 256 + v;
  }
  return n;
}

export function ipInCidr(ip: string, cidr: string): boolean {
  const [range, bitsRaw] = cidr.split("/");
  const bits = Number(bitsRaw ?? (net.isIPv4(ip) ? 32 : 128));
  if (net.isIPv4(ip) && net.isIPv4(range)) {
    const a = ipv4ToLong(ip);
    const b = ipv4ToLong(range);
    if (a == null || b == null) return false;
    if (bits <= 0) return true;
    if (bits >= 32) return a === b;
    const mask = (0xffffffff << (32 - bits)) >>> 0;
    return (a & mask) === (b & mask);
  }
  if (net.isIPv6(ip) && net.isIPv6(range)) {
    const expand = (v: string) => {
      const parts = v.split("::");
      const groups = (parts[1] ?? "").split(":").filter(Boolean).map((g) => parseInt(g || "0", 16));
      const head = parts[0].split(":").filter(Boolean).map((g) => parseInt(g || "0", 16));
      const fill = new Array(Math.max(0, 8 - head.length - groups.length)).fill(0);
      return [...head, ...fill, ...groups];
    };
    const a = expand(ip);
    const b = expand(range);
    if (a.length !== 8 || b.length !== 8) return false;
    let rem = bits;
    for (let i = 0; i < 8 && rem > 0; i++) {
      const take = Math.min(16, rem);
      const mask = take === 0 ? 0 : (0xffff << (16 - take)) & 0xffff;
      if ((a[i] & mask) !== (b[i] & mask)) return false;
      rem -= take;
    }
    return true;
  }
  return false;
}

function isPrivateIp(ip: string): boolean {
  if (net.isIPv4(ip)) return DEFAULT_BLOCKED_V4_CIDRS.some((c) => ipInCidr(ip, c));
  if (net.isIPv6(ip)) {
    const v = ip.toLowerCase();
    return DEFAULT_BLOCKED_V6_PREFIXES.some((p) => v.startsWith(p));
  }
  return true;
}

/** Normalize IP-ish hostnames: IPv4-mapped IPv6, hex/octal/decimal legacy forms. */
export function normalizeHostname(host: string): string | null {
  let h = host.replace(/^\[|\]$/g, "").toLowerCase();
  if (net.isIP(h)) {
    // IPv4-mapped IPv6 -> embedded IPv4
    if (h.startsWith("::ffff:") && net.isIPv4(h.slice(7))) return h.slice(7);
    return h;
  }
  // pure decimal integer (e.g. 2130706433)
  if (/^\d+$/.test(h)) {
    const n = Number(h);
    if (n >= 0 && n <= 0xffffffff)
      return [24, 16, 8, 0].map((s) => (n >>> s) & 255).join(".");
    return null;
  }
  // legacy dotted forms: 0x7f.0.0.1 / 0177.0.0.1 / 127.1
  if (/^[0-9a-fx.:]+$/.test(h) && h.includes(".")) {
    const parts = h.split(".");
    if (parts.length === 4) {
      let n = 0;
      for (const part of parts) {
        let v: number;
        if (/^0x[0-9a-f]+$/.test(part)) v = parseInt(part.slice(2), 16);
        else if (/^0[0-7]+$/.test(part)) v = parseInt(part, 8);
        else if (/^\d+$/.test(part)) v = parseInt(part, 10);
        else return null;
        if (v < 0 || v > 255) return null;
        n = n * 256 + v;
      }
      return [24, 16, 8, 0].map((s) => (n >>> s) & 255).join(".");
    }
  }
  return null;
}

/** Registration-time validation. Secrets are references, never values. */
export function validateToolConfig(body: any): string | null {
  if (!body?.name || !["http", "shell"].includes(body.kind)) return "name and kind(http|shell) are required";
  if (body.allow_private) return "allow_private was removed: use per-tool allowed_cidrs (e.g. [\"127.0.0.0/8\"])";
  if (body.auth_value || body.secret || body.password)
    return "store a reference (auth_env), never a literal secret value: Shomer keeps no secret material";
  if (body.kind === "http") {
    if (!body.url || !/^https?:\/\//.test(body.url)) return "http tools need an http(s) url";
    try {
      const u = new URL(body.url);
      if (u.username || u.password) return "credentials in the URL are not allowed; use auth_env + auth_header";
    } catch {
      return "unparseable url";
    }
  }
  if (body.kind === "shell" && !body.cmd) return "shell tools need a cmd";
  return null;
}

/** Resolve + validate every candidate IP. Returns the IPs to try, in order. */
export async function validateAndCheckTool(body: any): Promise<string | null> {
  const v = validateToolConfig(body);
  if (v) return v;
  if (body.kind === "http") {
    const r = await resolveAndValidate(body);
    if (!r.ok) return r.reason;
  }
  return null;
}

export async function resolveAndValidate(tool: any): Promise<{ ok: true; ips: string[] } | { ok: false; reason: string }> {
  if (!tool.url) return { ok: false, reason: "tool has no url" };
  const u = new URL(tool.url);
  const host = u.hostname.replace(/^\[|\]$/g, "");
  const allowHosts: string[] = tool.allowed_hosts ?? [];
  const cidrs: string[] = tool.allowed_cidrs ?? [];

  let ips: string[];
  const literal = normalizeHostname(host);
  if (literal) {
    ips = [literal];
  } else {
    if (allowHosts.length > 0 && !allowHosts.includes(host))
      return { ok: false, reason: `host ${host} not in this tool's allowed_hosts` };
    try {
      ips = (await dns.resolve4(host)).map((a) => a);
    } catch {
      try {
        ips = (await dns.lookup(host, { all: true })).map((r) => r.address);
      } catch {
        return { ok: false, reason: `dns resolution failed for ${host}` };
      }
    }
  }
  const normalized = ips.map((i) => normalizeHostname(i) ?? i).filter(Boolean);
  if (normalized.length === 0) return { ok: false, reason: "no usable A records" };

  for (const ip of normalized) {
    const permitted = cidrs.length > 0 ? cidrs.some((c) => ipInCidr(ip, c)) : !isPrivateIp(ip);
    if (!permitted)
      return { ok: false, reason: `destination ${ip} (${host}) is not permitted by this tool's policy (${cidrs.length ? "allowed_cidrs" : "public-only default"})` };
  }
  return { ok: true, ips: normalized };
}

/** Meter real usage from the response body using the pricing catalog. */
export function meterCost(usage: any, explicitUsd?: number): { cost_usd: number; source: "broker_metered" | "broker_unmetered" } {
  if (typeof explicitUsd === "number" && isFinite(explicitUsd))
    return { cost_usd: explicitUsd, source: "broker_metered" };
  if (!usage) return { cost_usd: 0, source: "broker_unmetered" };
  const model = String(usage.model ?? "");
  const inTok = Number(usage.input_tokens ?? 0);
  const outTok = Number(usage.output_tokens ?? 0);
  if (!model && inTok === 0 && outTok === 0) return { cost_usd: 0, source: "broker_unmetered" };
  const price = db.pricing.find((p) => p.model === model);
  if (!price) return { cost_usd: 0, source: "broker_unmetered" };
  const cost = (inTok / 1e6) * price.input_per_mtok + (outTok / 1e6) * price.output_per_mtok;
  return { cost_usd: Math.round(cost * 1e6) / 1e6, source: "broker_metered" };
}

/**
 * POST to a PINNED IP. The Host header and TLS SNI keep the original hostname,
 * so certificate validation stays correct while the connection cannot be
 * redirected by a second DNS answer (no redirect following either).
 */
function pinnedPost(url: URL, ip: string, headers: Record<string, string>, body: string, timeoutMs: number): Promise<{ status: number; text: string }> {
  const isHttps = url.protocol === "https:";
  const mod: any = isHttps ? https : http;
  return new Promise((resolve, reject) => {
    const opts: any = {
      method: "POST",
      host: ip,
      port: url.port || (isHttps ? 443 : 80),
      path: (url.pathname || "/") + (url.search || ""),
      headers: { ...headers, Host: url.host },
      timeout: timeoutMs,
      agent: false,
    };
    if (isHttps) opts.servername = url.hostname; // SNI + cert validation against the real hostname
    const req = mod.request(opts, (res: any) => {
      let text = "";
      let size = 0;
      res.on("data", (c: Buffer) => {
        size += c.length;
        if (size <= MAX_RESPONSE_BYTES) text += c.toString();
      });
      res.on("end", () => resolve({ status: res.statusCode ?? 0, text: size > MAX_RESPONSE_BYTES ? text + "...[truncated]" : text }));
    });
    req.on("timeout", () => req.destroy(new Error("broker_timeout")));
    req.on("error", reject);
    req.end(body);
  });
}

function execShell(tool: any, args: any): Promise<any> {
  return new Promise((resolve, reject) => {
    const env: Record<string, string> = { ...process.env } as any;
    env.SHOMER_TOOL_NAME = tool.name;
    env.SHOMER_TOOL_ARGS = JSON.stringify(args ?? {});
    if (tool.auth_env && !process.env[tool.auth_env])
      return reject(new Error("missing_upstream_credential:" + tool.auth_env));
    const child = spawn(tool.cmd, {
      shell: true,
      env,
      timeout: tool.timeout_ms ?? 15_000,
      windowsHide: true,
    });
    let out = "";
    let errOut = "";
    child.stdout.on("data", (d) => {
      if (out.length < MAX_RESPONSE_BYTES) out += d.toString();
    });
    child.stderr.on("data", (d) => {
      if (errOut.length < 100_000) errOut += d.toString();
    });
    child.on("error", reject);
    child.on("close", (code) => {
      if (code !== 0) return reject(new Error(`exit_${code}: ${errOut.slice(0, 200)}`));
      try {
        resolve(JSON.parse(out || "{}"));
      } catch {
        resolve({ raw: out.slice(0, 1000) });
      }
    });
  });
}

/** The single enforcement point. The SDK is only a convenience layer on top of it. */
export async function brokerCall(tool_name: string, agent_id: string, args: any): Promise<BrokerResult> {
  const tool = db.credentials.find((c) => c.name === tool_name);
  if (!tool) {
    const d = await evaluate({ agent_id, tool: tool_name, args });
    return { ok: false, decision: d }; // audited, but never executed
  }
  const decision = await evaluate({ agent_id, tool: tool_name, args });
  const decision_id: string | undefined = (decision as any).decision_id;
  if (!decision.allowed) return { ok: false, decision };

  const bodyStr = JSON.stringify(args ?? {});

  if (tool.kind === "shell") {
    let out: any;
    try {
      out = await execShell(tool, args);
    } catch (e: any) {
      await recordExecFailure(decision_id, String(e?.message || e));
      return { ok: false, decision, status: "executor_failed", error: String(e?.message || e) };
    }
    return await recordMetered(decision_id, agent_id, out);
  }

  // http: resolve, validate, PIN, execute
  let validated: Awaited<ReturnType<typeof resolveAndValidate>>;
  try {
    validated = await resolveAndValidate(tool);
  } catch (e: any) {
    validated = { ok: false, reason: "resolve_error: " + String(e?.message || e) };
  }
  if (!validated.ok) {
    await recordExecFailure(decision_id, (validated as any).reason, "destination_blocked");
    return { ok: false, decision, status: "destination_blocked", error: (validated as any).reason };
  }

  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (tool.auth_env) {
    const secret = process.env[tool.auth_env];
    // The header NAME comes from the tool config; the env var holds the exact
    // credential material, injected as-is. It is never read back into any response.
    if (!secret && !tool.optional_auth) {
      await recordExecFailure(decision_id, "missing_upstream_credential:" + tool.auth_env);
      return { ok: false, decision, status: "executor_failed", error: "missing_upstream_credential" };
    }
    if (secret) headers[tool.auth_header || "Authorization"] = secret;
  }

  let resp: { status: number; text: string };
  try {
    resp = await pinnedPost(new URL(tool.url!), validated.ips[0], headers, bodyStr, tool.timeout_ms ?? 15_000);
  } catch (e: any) {
    await recordExecFailure(decision_id, String(e?.message || e));
    return { ok: false, decision, status: "executor_failed", error: String(e?.message || e) };
  }

  let parsed: any;
  try {
    parsed = JSON.parse(resp.text);
  } catch {
    parsed = { raw: resp.text.slice(0, 1000) };
  }
  if (resp.status < 200 || resp.status >= 300) {
    await recordExecFailure(decision_id, `upstream_${resp.status}`);
    return { ok: false, decision, status: "executor_failed", error: `upstream_${resp.status}` };
  }
  return await recordMetered(decision_id, agent_id, parsed);
}

async function recordExecFailure(decision_id: string | undefined, detail: string, status: "executor_failed" | "destination_blocked" | "missing_credential" = "executor_failed") {
  if (!decision_id) return;
  const { recordOutcome } = await import("./policy");
  await recordOutcome({
    decision_id,
    cost_usd: 0,
    status,
    result_summary: detail.slice(0, 180),
    cost_source: "broker_unmetered",
  });
}

async function recordMetered(decision_id: string | undefined, agent_id: string, body: any) {
  const metered = meterCost(body?.usage, body?.cost_usd);
  if (decision_id) {
    const { recordOutcome } = await import("./policy");
    await recordOutcome({
      decision_id,
      cost_usd: metered.cost_usd,
      tokens: Number(body?.usage?.input_tokens ?? 0) + Number(body?.usage?.output_tokens ?? 0),
      status: "succeeded",
      result_summary: JSON.stringify(body?.result ?? {}).slice(0, 180),
      cost_source: metered.source,
    });
  }
  return {
    ok: true,
    decision_id,
    result: body?.result ?? body,
    cost_usd: metered.cost_usd,
    cost_source: metered.source,
    spent_today_usd: spentToday(agent_id),
  };
}