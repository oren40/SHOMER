import { Router } from "express";
import crypto from "node:crypto";
import {
  db,
  saveAgents,
  savePolicies,
  saveApprovals,
  saveSettings,
  saveCredentials,
  savePricing,
  type Agent,
  type Policy,
} from "./store";
import { evaluate, recordOutcome, type EvalInput } from "./policy";
import {
  verifyLedger,
  ledgerEvents,
  spentToday,
  appendEvent,
} from "./ledger";
import {
  keyFromRequest,
  scopesFor,
  hasScope,
  createKey,
  listKeys,
  revokeKey,
} from "./auth";
import { brokerCall } from "./broker";
import {
  buildEvidence,
  simplePDF,
  evidenceToText,
  type EvidenceQuery,
} from "./evidence";

export const router = Router();

const bad = (res: any, code: number, error: string) => res.status(code).json({ error });

/* ---------------- auth gates ---------------- */
function anyKey(req: any): string[] | null {
  return scopesFor(keyFromRequest(req));
}
function gate(res: any, scopes: string[] | null, need: string): boolean {
  if (!scopes) {
    bad(res, 401, "missing or invalid API key");
    return false;
  }
  if (need === "authenticated") return true;
  if (!hasScope(scopes, need)) {
    bad(res, 403, "insufficient scope: " + need);
    return false;
  }
  return true;
}

/* ---------------- Agent-facing API (scope: agent:<id>) ---------------- */

router.post("/v1/evaluate", (req, res) => {
  const scopes = anyKey(req);
  if (!gate(res, scopes, "authenticated")) return;
  const b = req.body as EvalInput;
  if (!b?.agent_id || !b?.tool) return bad(res, 400, "agent_id and tool are required");
  if (!gate(res, scopes, "agent:" + b.agent_id)) return;
  res.json(evaluate(b));
});

router.post("/v1/complete", (req, res) => {
  const scopes = anyKey(req);
  if (!gate(res, scopes, "authenticated")) return;
  const b = req.body;
  if (!b?.decision_id) return bad(res, 400, "decision_id is required");
  res.json(recordOutcome(b));
});

router.get("/v1/ledger", (req, res) => {
  if (!gate(res, anyKey(req), "dashboard")) return;
  const { agent_id, limit } = req.query as any;
  let rows = ledgerEvents((e) => !agent_id || e.agent_id === agent_id);
  rows = rows.slice(-Math.min(Number(limit ?? 100), 1000)).reverse();
  res.json({ events: rows });
});

router.get("/v1/ledger/verify", (req, res) => {
  if (!gate(res, anyKey(req), "dashboard")) return;
  res.json(verifyLedger());
});

/* ---------------- MCP proxy / credential broker ---------------- */

router.post("/mcp/v1/tools/:tool/call", async (req, res) => {
  const scopes = anyKey(req);
  if (!gate(res, scopes, "authenticated")) return;
  const tool = req.params.tool;
  const { agent_id, args } = req.body ?? {};
  if (!agent_id) return bad(res, 400, "agent_id is required");
  if (!gate(res, scopes, "agent:" + agent_id)) return;
  const out = await brokerCall(tool, agent_id, args ?? {});
  res.json(out);
});

/** Minimal JSON-RPC shim so MCP-native clients can call too: {"tools/call":{name,arguments,_agent_id}} */
router.post("/mcp", async (req, res) => {
  const scopes = anyKey(req);
  if (!gate(res, scopes, "authenticated")) return;
  const method = String(req.body?.method ?? "");
  const params = req.body?.params ?? {};
  if (method !== "tools/call")
    return res.status(400).json({ jsonrpc: "2.0", error: { code: -32601, message: "only tools/call is supported in v0.2" } });
  const agent_id = params._agent_id;
  if (!agent_id) return bad(res, 400, "params._agent_id is required");
  if (!gate(res, scopes, "agent:" + agent_id)) return;
  const out = await brokerCall(params.name, agent_id, params.arguments ?? {});
  res.json({ jsonrpc: "2.0", id: req.body?.id ?? null, result: out });
});

/* ---------------- Dashboard / Ops API ---------------- */

router.post("/api/login", (req, res) => {
  const plaintext = req.body?.key;
  const scopes = scopesFor(plaintext);
  if (!scopes) return bad(res, 401, "invalid key");
  res.json({ ok: true, scopes });
});

router.get("/api/overview", (_req, res) => {
  if (!gate(res, anyKey(_req), "dashboard")) return;
  const t = new Date().toISOString().slice(0, 10);
  const todays = ledgerEvents((e) => e.ts.slice(0, 10) === t);
  const decisions = todays.filter((e) => e.type === "decision");
  const spend = db.agents.reduce((s, a) => s + spentToday(a.id), 0);
  res.json({
    global_kill: db.settings.global_kill,
    spend_today_usd: Math.round(spend * 10000) / 10000,
    actions_today: decisions.length,
    blocked_today: decisions.filter((e) => e.decision === "deny").length,
    observe_today: decisions.filter((e) => e.decision === "observe_blocked").length,
    human_reviews_today: decisions.filter((e) => e.decision === "require_human").length,
    pending_approvals: db.approvals.filter((a) => a.status === "pending").length,
    agents: db.agents.length,
  });
});

router.get("/api/agents", (_req, res) => {
  if (!gate(res, anyKey(_req), "dashboard")) return;
  res.json({
    agents: db.agents.map((a) => ({ ...a, spent_today_usd: spentToday(a.id) })),
  });
});

router.post("/api/agents", (req, res) => {
  if (!gate(res, anyKey(req), "admin")) return;
  const b = req.body as Partial<Agent>;
  if (!b.id || !b.name) return bad(res, 400, "id and name are required");
  if (db.agents.some((a) => a.id === b.id)) return bad(res, 409, "agent exists");
  const agent: Agent = {
    id: b.id,
    name: b.name,
    owner: b.owner ?? "unassigned",
    status: "active",
    daily_budget_usd: Number(b.daily_budget_usd ?? 5),
    enforcement: b.enforcement === "observe" ? "observe" : "enforce",
    created_at: new Date().toISOString(),
  };
  db.agents.push(agent);
  saveAgents();
  res.json(agent);
});

router.patch("/api/agents/:id", (req, res) => {
  if (!gate(res, anyKey(req), "dashboard")) return;
  const a = db.agents.find((x) => x.id === req.params.id);
  if (!a) return bad(res, 404, "agent not found");
  const { status, daily_budget_usd, owner, enforcement } = req.body ?? {};
  if (status && ["active", "paused", "killed"].includes(status)) a.status = status;
  if (daily_budget_usd != null) a.daily_budget_usd = Number(daily_budget_usd);
  if (owner) a.owner = owner;
  if (enforcement === "observe" || enforcement === "enforce") a.enforcement = enforcement;
  saveAgents();
  res.json(a);
});

router.get("/api/policies", (_req, res) => {
  if (!gate(res, anyKey(_req), "dashboard")) return;
  res.json({ policies: db.policies });
});

router.post("/api/policies", (req, res) => {
  if (!gate(res, anyKey(req), "admin")) return;
  const b = req.body as Partial<Policy>;
  if (!b.type) return bad(res, 400, "type is required");
  const p: Policy = {
    id: crypto.randomUUID(),
    agent_id: b.agent_id ?? null,
    type: b.type,
    config: b.config ?? {},
    mode: b.mode === "observe" ? "observe" : "enforce",
    priority: Number(b.priority ?? 50),
    enabled: b.enabled ?? true,
  };
  db.policies.push(p);
  savePolicies();
  res.json(p);
});

router.patch("/api/policies/:id", (req, res) => {
  if (!gate(res, anyKey(req), "admin")) return;
  const p = db.policies.find((x) => x.id === req.params.id);
  if (!p) return bad(res, 404, "policy not found");
  const { enabled, config, priority, mode } = req.body ?? {};
  if (enabled != null) p.enabled = !!enabled;
  if (config) p.config = config;
  if (priority != null) p.priority = Number(priority);
  if (mode === "observe" || mode === "enforce") p.mode = mode;
  savePolicies();
  res.json(p);
});

router.delete("/api/policies/:id", (req, res) => {
  if (!gate(res, anyKey(req), "admin")) return;
  const i = db.policies.findIndex((x) => x.id === req.params.id);
  if (i === -1) return bad(res, 404, "policy not found");
  db.policies.splice(i, 1);
  savePolicies();
  res.json({ ok: true });
});

router.get("/api/decisions", (req, res) => {
  if (!gate(res, anyKey(req), "dashboard")) return;
  const { agent_id, limit } = req.query as any;
  let rows = ledgerEvents((e) => e.type === "decision" && (!agent_id || e.agent_id === agent_id));
  rows = rows.slice(-Math.min(Number(limit ?? 30), 200)).reverse();
  res.json({ decisions: rows });
});

router.get("/api/approvals", (req, res) => {
  if (!gate(res, anyKey(req), "dashboard")) return;
  const { status } = req.query as any;
  const rows = [...db.approvals]
    .filter((a) => !status || a.status === status)
    .sort((a, b) => (a.requested_at < b.requested_at ? 1 : -1));
  res.json({ approvals: rows });
});

router.get("/api/approvals/:id", (req, res) => {
  if (!gate(res, anyKey(req), "dashboard")) return;
  const a = db.approvals.find((x) => x.id === req.params.id);
  if (!a) return bad(res, 404, "approval not found");
  res.json(a);
});

router.post("/api/approvals/:id/resolve", (req, res) => {
  if (!gate(res, anyKey(req), "dashboard")) return;
  const a = db.approvals.find((x) => x.id === req.params.id);
  if (!a) return bad(res, 404, "approval not found");
  if (a.status !== "pending") return bad(res, 409, "already resolved");
  const by = String(req.body?.by ?? "").trim();
  if (!by) return bad(res, 400, "approver identity (by) is required");
  const approved = !!req.body?.approved;
  a.status = approved ? "approved" : "denied";
  a.resolved_at = new Date().toISOString();
  a.resolved_by = by;
  saveApprovals();
  // bind the approval to the exact args hash of the require_human decision
  const requ = ledgerEvents((e) => e.type === "decision" && e.decision_id === a.decision_id).pop();
  const binding_verified = !!requ && requ.args_hash === a.args_hash;
  appendEvent({
    type: "outcome",
    decision_id: a.decision_id,
    agent_id: a.agent_id,
    tool: a.tool,
    status: approved ? "approved" : "denied_human",
    cost_usd: 0,
    tokens: 0,
    actor: by,
    args_hash: a.args_hash,
    binding_verified,
    result_preview: (approved ? "human approved" : "human denied") + (binding_verified ? "" : " (BINDING MISMATCH)"),
  });
  res.json(a);
});

/* ---------------- credential broker registry (admin) ---------------- */

router.get("/api/credentials", (req, res) => {
  if (!gate(res, anyKey(req), "dashboard")) return;
  res.json({ credentials: db.credentials });
});

router.post("/api/credentials", (req, res) => {
  if (!gate(res, anyKey(req), "admin")) return;
  const b = req.body ?? {};
  if (!b.name || !["http", "shell"].includes(b.kind)) return bad(res, 400, "name and kind(http|shell) are required");
  if (db.credentials.some((c) => c.name === b.name)) return bad(res, 409, "tool exists");
  db.credentials.push(b);
  saveCredentials();
  res.json(b);
});

router.delete("/api/credentials/:name", (req, res) => {
  if (!gate(res, anyKey(req), "admin")) return;
  const i = db.credentials.findIndex((c) => c.name === req.params.name);
  if (i === -1) return bad(res, 404, "tool not found");
  db.credentials.splice(i, 1);
  saveCredentials();
  res.json({ ok: true });
});

/* ---------------- metering catalog (admin) ---------------- */

router.get("/api/pricing", (req, res) => {
  if (!gate(res, anyKey(req), "dashboard")) return;
  res.json({ pricing: db.pricing });
});

router.post("/api/pricing", (req, res) => {
  if (!gate(res, anyKey(req), "admin")) return;
  const b = req.body ?? {};
  if (!b.model) return bad(res, 400, "model is required");
  const row = { model: String(b.model), input_per_mtok: Number(b.input_per_mtok ?? 0), output_per_mtok: Number(b.output_per_mtok ?? 0) };
  db.pricing.push(row);
  savePricing();
  res.json(row);
});

/* ---------------- API key management (admin) ---------------- */

router.get("/api/keys", (req, res) => {
  if (!gate(res, anyKey(req), "admin")) return;
  res.json({ keys: listKeys() });
});

router.post("/api/keys", (req, res) => {
  if (!gate(res, anyKey(req), "admin")) return;
  const name = String(req.body?.name ?? "key");
  const scopes: string[] = Array.isArray(req.body?.scopes) ? req.body.scopes.map(String) : ["dashboard"];
  res.json(createKey(name, scopes));
});

router.delete("/api/keys/:id", (req, res) => {
  if (!gate(res, anyKey(req), "admin")) return;
  res.json({ ok: revokeKey(req.params.id) });
});

/* ---------------- evidence pack ---------------- */

router.get("/api/evidence", (req, res) => {
  if (!gate(res, anyKey(req), "dashboard")) return;
  const q = req.query as unknown as EvidenceQuery;
  res.json(buildEvidence({ agent_id: q.agent_id || undefined, from: q.from || undefined, to: q.to || undefined }));
});

router.get("/api/evidence/export", (req, res) => {
  if (!gate(res, anyKey(req), "dashboard")) return;
  const q = req.query as unknown as EvidenceQuery;
  const ev = buildEvidence({ agent_id: q.agent_id || undefined, from: q.from || undefined, to: q.to || undefined });
  if (String(q.format ?? "json") === "pdf") {
    const pdf = simplePDF("Shomer Evidence Pack", [evidenceToText(ev).join("\n")]);
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `attachment; filename="shomer-evidence-${ev.subject.agent_id ?? "all"}.pdf"`);
    return res.send(pdf);
  }
  res.setHeader("Content-Type", "application/json");
  res.setHeader("Content-Disposition", `attachment; filename="shomer-evidence-${ev.subject.agent_id ?? "all"}.json"`);
  res.send(JSON.stringify(ev, null, 2));
});

/* ---------------- settings ---------------- */

router.patch("/api/settings", (req, res) => {
  if (!gate(res, anyKey(req), "dashboard")) return;
  if (req.body?.global_kill != null) db.settings.global_kill = !!req.body.global_kill;
  saveSettings();
  res.json(db.settings);
});