import crypto from "node:crypto";
import { db, saveApiKeys } from "./store";

/**
 * v0.2 auth model:
 *  - Bearer token (or x-api-key) on every call.
 *  - Scopes: "admin" | "dashboard" | "agent:<id>" | "agent:*"
 *  - Keys are stored as sha256 hashes; the plaintext is shown exactly once.
 *  - mTLS is the documented upgrade path for high-assurance deployments.
 */
export function newKeyPlaintext(): string {
  return "sk_live_" + crypto.randomBytes(24).toString("hex");
}

export function hashKey(plaintext: string): string {
  return crypto.createHash("sha256").update(plaintext).digest("hex");
}

export function createKey(name: string, scopes: string[]) {
  const plaintext = newKeyPlaintext();
  const key = {
    id: crypto.randomUUID(),
    name,
    key_hash: hashKey(plaintext),
    scopes,
    created_at: new Date().toISOString(),
    revoked: false,
  };
  db.apiKeys.push(key);
  saveApiKeys();
  return { id: key.id, name, scopes, key: plaintext };
}

export function listKeys() {
  return db.apiKeys.map((k) => ({
    id: k.id,
    name: k.name,
    scopes: k.scopes,
    created_at: k.created_at,
    last_used_at: k.last_used_at ?? null,
    revoked: k.revoked,
  }));
}

export function revokeKey(id: string): boolean {
  const k = db.apiKeys.find((x) => x.id === id);
  if (!k) return false;
  k.revoked = true;
  saveApiKeys();
  return true;
}

export function keyFromRequest(req: any): string | null {
  const auth = req.headers?.["authorization"];
  if (typeof auth === "string" && auth.startsWith("Bearer ")) return auth.slice(7).trim();
  const x = req.headers?.["x-api-key"];
  return typeof x === "string" && x.length > 0 ? x : null;
}

export function scopesFor(plaintext: string | null): string[] | null {
  if (!plaintext) return null;
  const k = db.apiKeys.find((x) => x.key_hash === hashKey(plaintext) && !x.revoked);
  if (!k) return null;
  k.last_used_at = new Date().toISOString();
  return k.scopes;
}

export function hasScope(scopes: string[] | null, need: string): boolean {
  if (!scopes) return false;
  if (scopes.includes("admin")) return true;
  if (scopes.includes(need)) return true;
  if (need.startsWith("agent:"))
    return scopes.some((s) => s.startsWith("agent:") && s.endsWith(":*"));
  return false;
}