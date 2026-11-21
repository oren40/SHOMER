import crypto from "node:crypto";
import { db, saveApprovals, type Agent, type Policy } from "./store";
import {
  canonical,
  sha256,
  appendEvent,
  spentToday,
  countDecisions,
  countLoops,
  ledgerEvents,
} from "./ledger";

export interface EvalInput {
  agent_id: string;
  tool: string;
  args?: any;
  estimated_cost_usd?: number;
  context?: any;
}

const EMAIL_RE = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;
const CARD_RE = /\b(?:\d[ -]?){13,19}\b/g;

export function redactString(s: string): string {
  return s.replace(EMAIL_RE, "[REDACTED:email]").replace(CARD_RE, "[REDACTED:card]");
}

function redactDeep(v: any): { value: any; count: number } {
  if (typeof v === "string") {
    const r = redactString(v);
    return { value: r, count: r !== v ? 1 : 0 };
  }
  if (Array.isArray(v)) {
    let c = 0;
    const out = v.map((x) => {
      const r = redactDeep(x);
      c += r.count;
      return r.value;
    });
    return { value: out, count: c };
  }
  if (v && typeof v === "object") {
    let c = 0;
    const out: any = {};
    for (const k of Object.keys(v)) {
      const r = redactDeep(v[k]);
      c += r.count;
      out[k] = r.value;
    }
    return { value: out, count: c };
  }
  return { value: v, count: 0 };
}

function safePreview(obj: any): string {
  return redactString(JSON.stringify(obj)).slice(0, 160);
}

function getPath(obj: any, dotted: string): any {
  return dotted.split(".").reduce((a, k) => (a == null ? a : a[k]), obj);
}

function remainingBudget(agent: Agent): number {
  const budget = agent.daily_budget_usd ?? 0;
  return Math.max(0, Math.round((budget - spentToday(agent.id)) * 10000) / 10000);
}

function enforcing(agent: Agent | undefined, policy: Policy | null): boolean {
  if (!policy) return true; // agent-level blocks (kill switch, unknown agent) always enforce
  if (policy.mode === "observe") return false;
  if (agent && agent.enforcement === "observe") return false;
  return true;
}

interface Proposal {
  kind: "block" | "require_human";
  reason: string;
  policy: Policy | null;
}

export function evaluate(input: EvalInput) {
  const agent = db.agents.find((a) => a.id === input.agent_id);
  let args = input.args ?? {};
  let argsHash = sha256(canonical({ tool: input.tool, args }));
  const est = Number(input.estimated_cost_usd ?? 0.02);

  /**
   * Log-before-act: the decision is written to the tamper-evident ledger BEFORE
   * the verdict is returned. If the append fails we fail CLOSED (deny).
   */
  const logAndReturn = (payload: Record<string, any>, verdict: Record<string, any>) => {
    const decision_id = crypto.randomUUID();
    const rec: Record<string, any> = {
      type: "decision",
      decision_id,
      agent_id: input.agent_id,
      tool: input.tool,
      args_hash: argsHash,
      args_preview: safePreview(args),
      policy_id: payload.policy_id ?? null,
      ...payload,
    };
    try {
      appendEvent(rec);
    } catch {
      return {
        decision: "deny",
        allowed: false,
        reason: "ledger_append_failed",
        policy_id: null,
      };
    }
    return { decision_id, ...verdict };
  };

  const deny = (reason: string, policy: Policy | null, extra: Record<string, any> = {}) =>
    logAndReturn({ decision: "deny", reason, policy_id: policy?.id ?? null }, {
      decision: "deny",
      allowed: false,
      reason,
      ...extra,
    });

  const observe = (proposal: Proposal, extra: Record<string, any> = {}) =>
    logAndReturn(
      {
        decision: "observe_blocked",
        reason: "observe_mode",
        would_deny_reason: proposal.reason,
        policy_id: proposal.policy?.id ?? null,
      },
      {
        decision: "allow",
        allowed: true,
        reason: "observe_mode",
        would_deny_reason: proposal.reason,
        enforcement: "observe",
        ...extra,
      }
    );

  /* ---------- agent-level, always-enforce blocks ---------- */
  if (!agent) return deny("agent_not_found", null);
  if (db.settings.global_kill)
    return deny("kill_switch_global", null, { budget_remaining_usd: remainingBudget(agent) });
  if (agent.status !== "active")
    return deny(agent.status === "paused" ? "agent_paused" : "agent_killed", null, {
      budget_remaining_usd: remainingBudget(agent),
    });

  /* ---------- policy pass: first blocking proposal wins, like before ---------- */
  const policies: Policy[] = db.policies
    .filter((p) => p.enabled && (p.agent_id === null || p.agent_id === agent.id))
    .sort((a, b) => a.priority - b.priority);

  let sanitized = false;
  let redactions = 0;
  let wouldRedactions = 0;
  let lastMatchedPolicyId: string | null = null;
  let proposal: Proposal | null = null;

  for (const p of policies) {
    if (p.type === "pii_redaction") {
      const active = enforcing(agent, p);
      const r = redactDeep(args);
      if (r.count > 0) {
        if (active) {
          args = r.value;
          redactions += r.count;
          sanitized = true;
          argsHash = sha256(canonical({ tool: input.tool, args }));
        } else {
          wouldRedactions += r.count;
        }
      }
      lastMatchedPolicyId = p.id;
      continue;
    }
    if (proposal) break; // first blocking proposal (by priority) wins

    const block = (reason: string) => {
      proposal = { kind: "block", reason, policy: p };
    };
    switch (p.type) {
      case "rate_limit":
        if (countDecisions(agent.id, 60_000) >= Number(p.config.max_per_minute ?? 30))
          block("rate_limit_exceeded");
        break;
      case "loop_detection": {
        const win = Number(p.config.window_minutes ?? 5) * 60_000;
        if (countLoops(agent.id, input.tool, argsHash, win) >= Number(p.config.max_repeats ?? 1))
          block("runaway_loop_detected");
        break;
      }
      case "tool_allowlist": {
        const list: string[] | undefined = p.config.tools;
        if (list && list.length > 0 && !list.includes(input.tool))
          block("tool_not_allowed");
        break;
      }
      case "threshold": {
        const val = Number(getPath(args, p.config.field ?? "amount_usd") ?? 0);
        const thr = Number(p.config.threshold ?? 0);
        if (val > thr) {
          if (p.config.action === "deny")
            block(p.config.reason ?? "hard_cap_exceeded");
          else proposal = { kind: "require_human", reason: "human_approval_required", policy: p };
        }
        break;
      }
      case "max_call_cost":
        if (est > Number(p.config.max_usd ?? Infinity)) block("max_call_cost_exceeded");
        break;
      case "budget_daily": {
        const budget = Number(p.config.max_usd ?? agent.daily_budget_usd ?? 0);
        if (spentToday(agent.id) + est > budget) block("daily_budget_exhausted");
        break;
      }
    }
    lastMatchedPolicyId = p.id;
  }

  const budgetRemaining = remainingBudget(agent);

  // no blocking proposal -> allow / sanitize
  if (!proposal) {
    const decision = sanitized ? "sanitize" : "allow";
    return logAndReturn(
      {
        decision,
        reason: sanitized ? "pii_redacted" : "policy_default_allow",
        policy_id: sanitized ? lastMatchedPolicyId : null,
      },
      {
        decision,
        allowed: true,
        reason: sanitized ? "pii_redacted" : "policy_default_allow",
        args,
        redactions,
        would_redact_count: wouldRedactions,
        budget_remaining_usd: budgetRemaining,
      }
    );
  }

  // observe mode (per-policy, or whole-agent): log the would-be decision, enforce nothing
  if (!enforcing(agent, proposal.policy))
    return observe(proposal, { budget_remaining_usd: budgetRemaining });

  // human-in-the-loop
  if (proposal.kind === "require_human") {
    const decision_id = crypto.randomUUID();
    const approval_id = crypto.randomUUID();
    try {
      appendEvent({
        type: "decision",
        decision_id,
        agent_id: agent.id,
        tool: input.tool,
        decision: "require_human",
        reason: proposal.reason,
        policy_id: proposal.policy?.id ?? null,
        args_hash: argsHash,
        args_preview: safePreview(args),
      });
    } catch {
      return { decision: "deny", allowed: false, reason: "ledger_append_failed", policy_id: null };
    }
    db.approvals.push({
      id: approval_id,
      decision_id,
      agent_id: agent.id,
      tool: input.tool,
      args,
      args_hash: argsHash, // the approval is cryptographically bound to these exact args
      reason: proposal.reason,
      status: "pending",
      requested_at: new Date().toISOString(),
    });
    saveApprovals();
    return {
      decision: "require_human",
      allowed: false,
      decision_id,
      approval_id,
      reason: proposal.reason,
      policy_id: proposal.policy?.id ?? null,
      args,
      budget_remaining_usd: budgetRemaining,
    };
  }

  return deny(proposal.reason, proposal.policy, { budget_remaining_usd: budgetRemaining });
}

export function recordOutcome(body: {
  decision_id: string;
  cost_usd?: number;
  tokens?: number;
  status?: string;
  result_summary?: string;
  cost_source?: "agent_reported" | "broker_metered" | "broker_unmetered";
}) {
  const decision = ledgerEvents((e) => e.type === "decision" && e.decision_id === body.decision_id).pop();
  if (!decision) return { ok: false, error: "decision_not_found" };
  const status = body.status ?? "succeeded";
  appendEvent({
    type: "outcome",
    decision_id: body.decision_id,
    agent_id: decision.agent_id,
    tool: decision.tool,
    status,
    cost_usd: Number(body.cost_usd ?? 0),
    tokens: Number(body.tokens ?? 0),
    cost_source: body.cost_source ?? "agent_reported",
    result_preview: (body.result_summary ?? "").slice(0, 200),
  });
  const agent = db.agents.find((a) => a.id === decision.agent_id);
  return { ok: true, spent_today_usd: agent ? spentToday(agent.id) : 0 };
}