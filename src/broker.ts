/**
 * Credential broker + metered gateway.
 *
 * The agent calls the control plane, not the tool. The control plane:
 *   1. evaluates the call against policy (same engine as the SDK path),
 *   2. if allowed, executes the tool server-side with the credential injected,
 *   3. meters the ACTUAL usage from the response (never an agent-reported number),
 *   4. records one ledger entry.
 * The agent never sees the secret, so the control plane cannot be bypassed.
 */
import { spawn } from "node:child_process";
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
}

/** Meter real usage from the response body using the pricing catalog. */
export function meterCost(usage: any, explicitUsd?: number): { cost_usd: number; source: "broker_metered" | "broker_unmetered" } {
  if (typeof explicitUsd === "number" && isFinite(explicitUsd)) {
    return { cost_usd: explicitUsd, source: "broker_metered" };
  }
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
  if (tool.auth_env) {
    const secret = process.env[tool.auth_env];
    if (secret) headers[tool.auth_header || "Authorization"] = secret;
  }
  const res = await fetch(tool.url, {
    method: tool.method || "POST",
    headers,
    body: JSON.stringify(args ?? {}),
    signal: AbortSignal.timeout(tool.timeout_ms ?? 15_000),
  });
  const text = await res.text();
  let body: any;
  try {
    body = JSON.parse(text);
  } catch {
    body = { raw: text.slice(0, 2000) };
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
      // nothing to inject: fail closed rather than running uncredentialed
      return reject(new Error("missing_upstream_credential"));
    }
    const child = spawn(tool.cmd, {
      shell: true,
      env,
      timeout: tool.timeout_ms ?? 15_000,
      windowsHide: true,
    });
    let out = "";
    let errOut = "";
    child.stdout.on("data", (d) => (out += d.toString()));
    child.stderr.on("data", (d) => (errOut += d.toString()));
    child.on("error", reject);
    child.on("close", (code) => {
      if (code !== 0) return reject(new Error(`exit_${code}: ${errOut.slice(0, 300)}`));
      try {
        resolve(JSON.parse(out || "{}"));
      } catch {
        resolve({ raw: out.slice(0, 2000) });
      }
    });
  });
}

/** The single enforcement point. The SDK is only a convenience layer on top of it. */
export async function brokerCall(tool_name: string, agent_id: string, args: any): Promise<BrokerResult> {
  const tool = db.credentials.find((c) => c.name === tool_name);
  if (!tool) {
    const d = evaluate({ agent_id, tool: tool_name, args }); return { ok: false, decision: d }; // audited, but never executed
  }
  const decision = evaluate({ agent_id, tool: tool_name, args });
  if (!decision.allowed) return { ok: false, decision };

  let body: any;
  try {
    body = tool.kind === "shell" ? await execShell(tool, args) : await execHttp(tool, args);
  } catch (e: any) {
    const { recordOutcome } = await import("./policy");
    recordOutcome({
      decision_id: decision.decision_id,
      cost_usd: 0,
      status: "executor_failed",
      result_summary: String(e?.message || e).slice(0, 180),
      cost_source: "broker_unmetered",
    });
    return { ok: false, decision, status: "executor_failed", error: String(e?.message || e) };
  }

  const metered = meterCost(body?.usage, body?.cost_usd);
  const { recordOutcome } = await import("./policy");
  recordOutcome({
    decision_id: decision.decision_id,
    cost_usd: metered.cost_usd,
    tokens: Number(body?.usage?.input_tokens ?? 0) + Number(body?.usage?.output_tokens ?? 0),
    status: "succeeded",
    result_summary: JSON.stringify(body?.result ?? {}).slice(0, 180),
    cost_source: metered.source,
  });
  return {
    ok: true,
    decision_id: decision.decision_id,
    result: body?.result ?? body,
    cost_usd: metered.cost_usd,
    cost_source: metered.source,
    spent_today_usd: spentToday(agent_id),
  };
}