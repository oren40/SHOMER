import crypto from "node:crypto";
import path from "node:path";
import fs from "node:fs";
import { appendJSONL, readJSONL, LEDGER_FILE, DATA_DIR } from "./store";

/** Deterministic JSON: sorted keys, no whitespace. The backbone of the evidence chain. */
export function canonical(value: any): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value))
    return "[" + value.map(canonical).join(",") + "]";
  const keys = Object.keys(value).sort();
  return (
    "{" +
    keys.map((k) => JSON.stringify(k) + ":" + canonical(value[k])).join(",") +
    "}"
  );
}

export function sha256(s: string): string {
  return crypto.createHash("sha256").update(s).digest("hex");
}

export interface LedgerEvent {
  seq: number;
  ts: string;
  type: "decision" | "outcome";
  decision_id: string;
  agent_id: string;
  tool: string;
  [k: string]: any;
  prev_hash: string;
  hash: string;
}

const GENESIS = "0".repeat(64);

/* ---------------- signed checkpoints (written OUTSIDE the data dir) ---------------- */

const CHECKPOINT_DIR =
  process.env.SHOMER_CHECKPOINT_DIR || path.resolve(DATA_DIR, "..", "shomer-checkpoints");
const CHECKPOINT_EVERY = Number(process.env.SHOMER_CHECKPOINT_EVERY || 25);
const CHECKPOINT_KEY_ENV = process.env.SHOMER_CHECKPOINT_KEY;

function checkpointKey(): string {
  if (CHECKPOINT_KEY_ENV) return CHECKPOINT_KEY_ENV;
  try {
    const p = path.join(DATA_DIR, "checkpoint_key");
    const existing = fs.readFileSync(p, "utf8").trim();
    if (existing) return existing;
    const k = crypto.randomBytes(32).toString("hex");
    fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.writeFileSync(p, k);
    return k;
  } catch {
    return "unwritable-checkpoint-key"; // Degrades to signature-vs-mutation, not key secrecy
  }
}

function checkpointFile(): string {
  return path.join(CHECKPOINT_DIR, "checkpoints.jsonl");
}

function readCheckpoints(): any[] {
  try {
    return fs
      .readFileSync(checkpointFile(), "utf8")
      .split("\n")
      .filter((l) => l.trim().length > 0)
      .map((l) => JSON.parse(l));
  } catch {
    return [];
  }
}

export function writeCheckpoint(seq: number, last_hash: string) {
  const ts = new Date().toISOString();
  const sig = crypto
    .createHmac("sha256", checkpointKey())
    .update(`${seq}|${last_hash}|${ts}`)
    .digest("hex");
  const rec = { seq, ts, last_hash, sig };
  try {
    fs.mkdirSync(CHECKPOINT_DIR, { recursive: true });
    fs.appendFileSync(checkpointFile(), JSON.stringify(rec) + "\n");
  } catch {
    /* checkpoint dir unwritable: chain verification still works, rollback detection degrades */
  }
  return rec;
}

/* ---------------- hash chain ---------------- */

let tail: { seq: number; hash: string } | null = null;

function loadTail() {
  if (!tail) {
    const rows = readJSONL(LEDGER_FILE);
    const last = rows[rows.length - 1];
    tail = last
      ? { seq: last.seq, hash: last.hash }
      : { seq: 0, hash: GENESIS };
  }
  return tail;
}

/** Append a tamper-evident event. Throws (never swallows) when the ledger cannot be written. */
export function appendEvent(payload: Record<string, any>): LedgerEvent {
  const cur = loadTail();
  const rec: any = { ...payload, seq: cur.seq + 1, prev_hash: cur.hash };
  rec.ts = rec.ts ?? new Date().toISOString();
  delete rec.hash;
  rec.hash = sha256(canonical(rec));
  appendJSONL(LEDGER_FILE, rec);
  tail = { seq: rec.seq, hash: rec.hash };
  if (rec.seq % CHECKPOINT_EVERY === 0) writeCheckpoint(rec.seq, rec.hash);
  return rec as LedgerEvent;
}

export function ledgerEvents(filter?: (e: any) => boolean): LedgerEvent[] {
  const rows = readJSONL(LEDGER_FILE);
  return filter ? rows.filter(filter) : rows;
}

/** Recompute the entire chain + validate the latest checkpoint signature and detect rollback. */
export function verifyLedger() {
  const rows = readJSONL(LEDGER_FILE);
  let prev = GENESIS;
  for (const r of rows) {
    const { hash, ...rest } = r;
    if (sha256(canonical(rest)) !== hash)
      return { valid: false, length: rows.length, first_invalid_seq: r.seq, why: "record_hash_mismatch" };
    if (r.prev_hash !== prev)
      return { valid: false, length: rows.length, first_invalid_seq: r.seq, why: "broken_link" };
    prev = hash;
  }
  tail = rows.length ? { seq: rows[rows.length - 1].seq, hash: prev } : { seq: 0, hash: GENESIS };

  const cps = readCheckpoints();
  if (cps.length === 0)
    return { valid: true, length: rows.length, checkpoint: null };

  const cp = cps[cps.length - 1];
  const sigOk =
    crypto
      .createHmac("sha256", checkpointKey())
      .update(`${cp.seq}|${cp.last_hash}|${cp.ts}`)
      .digest("hex") === cp.sig;
  if (!sigOk)
    return { valid: false, length: rows.length, checkpoint: cp, why: "checkpoint_bad_signature" };
  if (cp.seq > rows.length)
    return { valid: false, length: rows.length, checkpoint: cp, why: "ledger_behind_checkpoint" };
  const anchor = rows.find((r) => r.seq === cp.seq);
  if (anchor && anchor.hash !== cp.last_hash)
    return { valid: false, length: rows.length, checkpoint: cp, why: "history_rewrite_at_checkpoint" };
  return { valid: true, length: rows.length, checkpoint: cp };
}

export function latestCheckpointInfo() {
  const cps = readCheckpoints();
  if (cps.length === 0) return null;
  const cp = cps[cps.length - 1];
  const sigOk =
    crypto
      .createHmac("sha256", checkpointKey())
      .update(`${cp.seq}|${cp.last_hash}|${cp.ts}`)
      .digest("hex") === cp.sig;
  return { ...cp, signature_valid: sigOk };
}

const today = () => new Date().toISOString().slice(0, 10);

export function spentToday(agent_id: string): number {
  const t = today();
  const sum = ledgerEvents(
    (e) =>
      e.type === "outcome" &&
      e.agent_id === agent_id &&
      e.status === "succeeded" &&
      e.ts.slice(0, 10) === t
  ).reduce((s, e) => s + (e.cost_usd || 0), 0);
  return Math.round(sum * 10000) / 10000;
}

export function countDecisions(agent_id: string, windowMs: number): number {
  const cutoff = Date.now() - windowMs;
  return ledgerEvents(
    (e) =>
      e.type === "decision" &&
      e.agent_id === agent_id &&
      new Date(e.ts).getTime() >= cutoff
  ).length;
}

export function countLoops(
  agent_id: string,
  tool: string,
  argsHash: string,
  windowMs: number
): number {
  const cutoff = Date.now() - windowMs;
  return ledgerEvents(
    (e) =>
      e.type === "decision" &&
      e.agent_id === agent_id &&
      e.tool === tool &&
      e.args_hash === argsHash &&
      new Date(e.ts).getTime() >= cutoff
  ).length;
}