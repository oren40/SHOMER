/**
 * Credential broker + metered gateway - hardened.
 *
 * The agent calls the control plane, not the tool. The control plane:
 *   1. evaluates the call against policy (same engine as the SDK path),
 *   2. if allowed, executes the tool server-side with the credential injected,
 *   3. meters the ACTUAL usage from the response (never an agent-reported number),
 *   4. records one ledger entry.
 *
 * Hardening (v0.2.1):
 *   - destination allowlist per tool; private/loopback/link-local/CGNAT/metadata
 *     addresses are refused unless the tool is explicitly marked allow_private
 *     (for local testing and on-prem deployments)
 *   - no redirect following (redirect: "error")
 *   - timeouts + response size caps
 *   - secrets are references (env var names) only - literal secret values are
 *     rejected at registration and never reach the ledger or the logs
 */
import { spawn } from "node:child_process";
import dns from "node:dns/promises";
import net from "node:net";
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

const MAX_RESPONSE_BYTES = Number(process.env.SHOMER_BROKER_MAX_RESPONSE_BYTES || 1_000_000);

/** Registration-time validation. Secrets are references, never values. */
export function validateToolConfig(body: any): string | null {
  if (!body?.name || !["http", "shell"].includes(body.kind)) return "name and kind(http|shell) are required";
  if (body.auth_value || body.secret || body.password)
    return "store a reference (auth_env), never a literal secret value: Shomer keeps no secret material";
  if (body.kind === "http") {
    if (!body.url || !/^https?:\/\//.test(body.url)) return "http tools need an http(s) url";
    let u: URL;
    try {
      u = new URL(body.url);
    } catch {
      return "unparseable url";
    }
    if (!u.username && !u.password) {
      /* credentials must not live in the URL either */
    }
    if (u.username || u.password) return "credentials in the URL are not allowed; use auth_env + auth_header";
  }
  if (body.kind === "shell" && !body.cmd) return "shell tools need a cmd";
  return null;
}

function isBlockedIp(ip: string): boolean {
  if (net.isIPv4(ip)) {
    const p = ip.split(".").map(Number);
    if (p[0] === 0) return true;
    if (p[0] === 10) return true;
    if (p[0] === 127) return true;
    if (p[0] === 169 && p[1] === 254) return true; // link-local + cloud metadata
    if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
    if (p[0] === 192 && p[1] === 168) return true;
    if (p[0] === 100 && p[1] >= 64 && p[1] <= 127) return true; // CGNAT
    if (p[0] >= 224) return true; // multicast/reserved
    return false;
  }
  const v = ip.toLowerCase();
  if (v === "::1" || v === "::") return true;
  if (v.startsWith("fe80")) return true; // link-local
  if (v.startsWith("fc") || v.startsWith("fd")) return true; // unique local
  return false;
}

/** SSRF gate: resolves the hostname and refuses blocked ranges. */
export async function assertDestinationAllowed(tool: any): Promise<string | null> {
  if (!tool.url) return "tool has no url";
  const u = new URL(tool.url);
  const allow: string[] | undefined = tool.allowed_hosts;
  if (allow && allow.length > 0 && !allow.includes(u.hostname))
    return `host ${u.hostname} not in this tool's destination allowlist`;
  let ips: string[] = [];
  if (net.isIP(u.hostname)) ips = [u.hostname];
  else {
    try {
      ips = (await dns.lookup(u.hostname, { all: true })).map((r) => r.address);
    } catch {
      return `dns resolution failed for ${u.hostname}`;
    }
  }
  if (!tool.allow_private) {
    for (const ip of ips) if (isBlockedIp(ip)) return `destination ${ip} (${u.hostname}) is in a blocked range`;
  }
  return null;
}

/** Registration-time SSRF gate: refuses blocked/allowlist-denied destinations up front.
 *  Call-time DNS checks still apply (a hostname can later resolve inside). */
export async function validateAndCheckTool(body: any): Promise<string | null> {
  const v = validateToolConfig(body);
  if (v) return v;
  if (body.kind === "http" && !body.allow_private) {
    return assertDestinationAllowed(body);
  }
  return null;
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

async function execHttp(tool: any, args: any): Promise<any> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  // The header NAME comes from the tool config; the env var holds the exact
  // credential material, injected as-is. It is never read back into any response.
  if (tool.auth_env) {
    const secret = process.env[tool.auth_env];
    if (!secret && !tool.optional_auth)
      throw new Error("missing_upstream_credential:" + tool.auth_env);
    if (secret) headers[tool.auth_header || "Authorization"] = secret;
  }
  const res = await fetch(tool.url, {
    method: tool.method || "POST",
    headers,
    body: JSON.stringify(args ?? {}),
    signal: AbortSignal.timeout(tool.timeout_ms ?? 15_000),
    redirect: "error", // never follow: a redirect would carry the credential elsewhere
    cache: "no-store",
  });
  const text = await res.text();
  if (text.length > MAX_RESPONSE_BYTES)
    throw new Error("response_too_large:" + text.length);
  let body: any;
  try {
    body = JSON.parse(text);
  } catch {
    body = { raw: text.slice(0, 1000) };
  }
  if (!res.ok) {
    const err: any = new Error(`upstream_${res.status}`);
    err.body = body;
    throw err;
  }
  return body;
}

function execShell(tool: any, args: any): Promise<any> {
  return new Promise((resolve, reject) => {
    const env: Record<string, string> = { ...process.env } as any;
    env.SHOMER_TOOL_NAME = tool.name;
    env.SHOMER_TOOL_ARGS = JSON.stringify(args ?? {});
    if (tool.auth_env && !process.env[tool.auth_env]) {
      return reject(new Error("missing_upstream_credential:" + tool.auth_env));
    }
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

  if (tool.kind === "http") {
    const ssrf = await assertDestinationAllowed(tool);
    if (ssrf) {
      const { recordOutcome } = await import("./policy");
      await recordOutcome({
        decision_id: decision_id,
        cost_usd: 0,
        status: "destination_blocked",
        result_summary: ssrf.slice(0, 180),
        cost_source: "broker_unmetered",
      });
      return { ok: false, decision, status: "destination_blocked", error: ssrf };
    }
  }

  let body: any;
  try {
    body = tool.kind === "shell" ? await execShell(tool, args) : await execHttp(tool, args);
  } catch (e: any) {
    const { recordOutcome } = await import("./policy");
    await recordOutcome({
      decision_id: decision_id,
      cost_usd: 0,
      status: "executor_failed",
      result_summary: String(e?.message || e).slice(0, 180),
      cost_source: "broker_unmetered",
    });
    return { ok: false, decision, status: "executor_failed", error: String(e?.message || e) };
  }

  const metered = meterCost(body?.usage, body?.cost_usd);
  const { recordOutcome } = await import("./policy");
  await recordOutcome({
    decision_id: decision_id,
    cost_usd: metered.cost_usd,
    tokens: Number(body?.usage?.input_tokens ?? 0) + Number(body?.usage?.output_tokens ?? 0),
    status: "succeeded",
    result_summary: JSON.stringify(body?.result ?? {}).slice(0, 180),
    cost_source: metered.source,
  });
  return {
    ok: true,
    decision_id: decision_id,
    result: body?.result ?? body,
    cost_usd: metered.cost_usd,
    cost_source: metered.source,
    spent_today_usd: spentToday(agent_id),
  };
}