import fs from "node:fs";
import path from "node:path";

export const DATA_DIR =
  process.env.SHOMER_DATA_DIR || path.join(process.cwd(), "data");

export type EnforcementMode = "enforce" | "observe";

export interface Agent {
  id: string;
  name: string;
  owner: string;
  status: "active" | "paused" | "killed";
  daily_budget_usd: number;
  enforcement: EnforcementMode;
  created_at: string;
}

export interface Policy {
  id: string;
  agent_id: string | null;
  type:
    | "pii_redaction"
    | "rate_limit"
    | "loop_detection"
    | "threshold"
    | "tool_allowlist"
    | "max_call_cost"
    | "budget_daily";
  config: Record<string, any>;
  mode: EnforcementMode; // enforce = block; observe = log the would-be decision only
  priority: number;
  enabled: boolean;
}

export interface Approval {
  id: string;
  decision_id: string;
  agent_id: string;
  tool: string;
  args: any;
  args_hash: string;
  reason: string;
  status: "pending" | "approved" | "denied";
  requested_at: string;
  resolved_at?: string;
  resolved_by?: string;
  resolved_by_key_id?: string;
}

/** Credential broker registry: the control plane holds the secret, the agent never does. */
export interface ToolCredential {
  name: string;
  kind: "http" | "shell";
  url?: string;
  method?: string;
  auth_header?: string; // http: header the broker injects
  auth_env?: string; // name of the env var holding the secret (set on the control plane, not the agent)
  cmd?: string; // shell: command template
  timeout_ms?: number;
  description?: string;
  allowed_hosts?: string[];
  allow_private?: boolean;
  optional_auth?: boolean;
}

/** Metering catalog: model -> price per 1M tokens. The broker computes real cost from usage. */
export interface ModelPrice {
  model: string;
  input_per_mtok: number;
  output_per_mtok: number;
}

export interface ApiKey {
  id: string;
  name: string;
  key_hash: string; // sha256; the plaintext key is shown exactly once at creation
  scopes: string[]; // "admin" | "dashboard" | "agent:<id>" | "agent:*"
  created_at: string;
  last_used_at?: string;
  revoked: boolean;
}

export interface Settings {
  global_kill: boolean;
}

interface DB {
  agents: Agent[];
  policies: Policy[];
  approvals: Approval[];
  credentials: ToolCredential[];
  pricing: ModelPrice[];
  apiKeys: ApiKey[];
  settings: Settings;
}

export const db: DB = {
  agents: [],
  policies: [],
  approvals: [],
  credentials: [],
  pricing: [],
  apiKeys: [],
  settings: { global_kill: false },
};

const file = (name: string) => path.join(DATA_DIR, name);

function readJSON<T>(name: string, fallback: T): T {
  try {
    return JSON.parse(fs.readFileSync(file(name), "utf8")) as T;
  } catch {
    return fallback;
  }
}

function writeJSON(name: string, data: unknown) {
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    const tmp = file(name + ".tmp");
    fs.writeFileSync(tmp, JSON.stringify(data, null, 2));
    fs.renameSync(tmp, file(name));
  } catch {
    /* read-only or unwritable store: callers degrade to in-memory + fail-closed paths */
  }
}

export function initStore() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  db.agents = readJSON<Agent[]>("agents.json", []);
  db.policies = readJSON<Policy[]>("policies.json", []);
  db.approvals = readJSON<Approval[]>("approvals.json", []);
  db.credentials = readJSON<ToolCredential[]>("credentials.json", []);
  db.pricing = readJSON<ModelPrice[]>("pricing.json", []);
  db.apiKeys = readJSON<ApiKey[]>("api_keys.json", []);
  db.settings = readJSON<Settings>("settings.json", { global_kill: false });
}

export const saveAgents = () => writeJSON("agents.json", db.agents);
export const savePolicies = () => writeJSON("policies.json", db.policies);
export const saveApprovals = () => writeJSON("approvals.json", db.approvals);
export const saveCredentials = () => writeJSON("credentials.json", db.credentials);
export const savePricing = () => writeJSON("pricing.json", db.pricing);
export const saveApiKeys = () => writeJSON("api_keys.json", db.apiKeys);
export const saveSettings = () => writeJSON("settings.json", db.settings);

export function appendJSONL(name: string, obj: unknown) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.appendFileSync(file(name), JSON.stringify(obj) + "\n");
}

export function readJSONL(name: string): any[] {
  try {
    return fs
      .readFileSync(file(name), "utf8")
      .split("\n")
      .filter((l) => l.trim().length > 0)
      .map((l) => JSON.parse(l));
  } catch {
    return [];
  }
}

export const LEDGER_FILE = "ledger.jsonl";