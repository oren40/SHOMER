import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { db, DATA_DIR, saveAgents, savePolicies, saveSettings, saveApiKeys } from "./store";
import { createKey, hashKey } from "./auth";

/**
 * Seeds two demo agents + policies so the dashboard is alive on first boot,
 * and bootstraps the first API key.
 * Budgets are deliberately tiny ($1/day) so the demo can show budget enforcement
 * within a couple of minutes of simulated traffic.
 */
export function seedIfEmpty() {
  if (db.agents.length > 0) return;

  db.agents.push(
    {
      id: "refunds-prod",
      name: "Customer Refunds Agent",
      owner: "support-ops",
      status: "active",
      daily_budget_usd: 1.0,
      enforcement: "enforce",
      created_at: new Date().toISOString(),
    },
    {
      id: "support-triage",
      name: "Support Triage Agent",
      owner: "support-ops",
      status: "active",
      daily_budget_usd: 2.0,
      enforcement: "enforce",
      created_at: new Date().toISOString(),
    }
  );

  const P = (agent_id: string | null, type: any, config: Record<string, any>, priority: number, mode: "enforce" | "observe" = "enforce") => ({
    id: crypto.randomUUID(),
    agent_id,
    type,
    config,
    mode,
    priority,
    enabled: true,
  });

  db.policies.push(
    // refunds-prod
    P("refunds-prod", "pii_redaction", {}, 5),
    P("refunds-prod", "rate_limit", { max_per_minute: 120 }, 10),
    P("refunds-prod", "loop_detection", { max_repeats: 1, window_minutes: 5 }, 20),
    P("refunds-prod", "threshold", { field: "amount_usd", threshold: 1000, action: "deny", reason: "hard_cap_exceeded" }, 30),
    P("refunds-prod", "tool_allowlist", { tools: ["lookup_order", "issue_refund", "notify_customer"] }, 40),
    P("refunds-prod", "max_call_cost", { max_usd: 0.5 }, 50),
    P("refunds-prod", "budget_daily", {}, 60),
    P("refunds-prod", "threshold", { field: "amount_usd", threshold: 100, action: "require_human", reason: "refund_above_100" }, 70),
    // support-triage
    P("support-triage", "pii_redaction", {}, 5),
    P("support-triage", "tool_allowlist", { tools: ["classify_ticket", "draft_reply"] }, 40),
    P("support-triage", "budget_daily", {}, 60)
  );

  saveAgents();
  savePolicies();
  saveSettings();

  if (db.apiKeys.length === 0) {
    const scopes = ["admin", "dashboard", "agent:*"];
    if (process.env.SHOMER_ADMIN_KEY) {
      const plaintext = process.env.SHOMER_ADMIN_KEY;
      db.apiKeys.push({
        id: crypto.randomUUID(),
        name: "admin-env",
        key_hash: hashKey(plaintext),
        scopes,
        created_at: new Date().toISOString(),
        revoked: false,
      });
      saveApiKeys();
      console.log("[seed] admin key from SHOMER_ADMIN_KEY env");
    } else {
      const created = createKey("dev-bootstrap", scopes);
      const p = path.join(DATA_DIR, "DEV_KEY.txt");
      try {
        fs.mkdirSync(DATA_DIR, { recursive: true });
        fs.writeFileSync(p, created.key + "\n");
        console.log(`[seed] DEV API KEY (also in ${p}): ${created.key}`);
      } catch {
        console.log(`[seed] DEV API KEY (store not writable): ${created.key}`);
      }
    }
  }
  console.log("[seed] created demo agents: refunds-prod, support-triage");
}