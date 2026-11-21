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

/* ---------------- Ed25519-signed checkpoints ----------------
 * The private key lives OUTSIDE the data dir (env: SHOMER_CHECKPOINT_KEY_PATH).
 * The public key is exportable, so an external reviewer can verify checkpoints
 * without trusting the operator. Every record pins (seq, last record hash, ts).
 */
const CHECKPOINT_DIR =
  process.env.SHOMER_CHECKPOINT_DIR || path.resolve(DATA_DIR, "..", "shomer-checkpoints");
const KEY_PATH =
  process.env.SHOMER_CHECKPOINT_KEY_PATH ||
  path.resolve(DATA_DIR, "..", "shomer-keys", "checkpoint_ed25519.pem");
const CHECKPOINT_EVERY = Number(process.env.SHOMER_CHECKPOINT_EVERY || 25);
const CHECKPOINT_INTERVAL_S = Number(process.env.SHOMER_CHECKPOINT_INTERVAL_S || 300);
const SINK_URL = process.env.SHOMER_CHECKPOINT_SINK_URL || "";

let privateKey: crypto.KeyObject | null = null;
let publicPem: string | null = null;

function loadKeys() {
  if (privateKey && publicPem) return { privateKey, publicPem };
  let pk: crypto.KeyObject | null = null;
  try {
    pk = crypto.createPrivateKey(fs.readFileSync(KEY_PATH, "utf8"));
  } catch {
    const gen = crypto.generateKeyPairSync("ed25519");
    pk = gen.privateKey;
    try {
      fs.mkdirSync(path.dirname(KEY_PATH), { recursive: true });
      fs.writeFileSync(KEY_PATH, gen.privateKey.export({ type: "pkcs8", format: "pem" }).toString(), { mode: 0o600 });
    } catch {
      /* unwritable key path: signatures still verify locally, key portability degrades */
    }
  }
  privateKey = pk;
  publicPem = crypto.createPublicKey(pk).export({ type: "spki", format: "pem" }).toString();
  return { privateKey, publicPem };
}

/** Exportable public key: hand this to auditors / SIEM verifiers. */
export function publicKeyPem(): string {
  return loadKeys().publicPem!;
}
export function publicKeyFingerprint(): string {
  return sha256(publicKeyPem()).slice(0, 16);
}

function signCheckpoint(seq: number, last_hash: string, ts: string): string {
  const { privateKey: pk } = loadKeys();
  return crypto.sign(null, Buffer.from(`${seq}|${last_hash}|${ts}`), pk).toString("hex");
}

export function verifyCheckpointSignature(cp: any, pem?: string): boolean {
  try {
    const key = pem ? crypto.createPublicKey(pem) : crypto.createPublicKey(publicKeyPem());
    return crypto.verify(null, Buffer.from(`${cp.seq}|${cp.last_hash}|${cp.ts}`), key, Buffer.from(String(cp.sig), "hex"));
  } catch {
    return false;
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
  const rec = {
    seq,
    ts,
    last_hash,
    alg: "ed25519",
    pub_fp: publicKeyFingerprint(),
    sig: signCheckpoint(seq, last_hash, ts),
  };
  try {
    fs.mkdirSync(CHECKPOINT_DIR, { recursive: true });
    fs.appendFileSync(checkpointFile(), JSON.stringify(rec) + "\n");
  } catch {
    /* checkpoint dir unwritable: chain verification still works; rollback detection degrades */
  }
  return rec;
}

let lastExport: { at: string; ok: boolean; detail: string } | null = null;
export function lastExportStatus() {
  return lastExport;
}

/** Best-effort export to an external sink (SIEM / customer WORM). Never blocks the ledger. */
async function exportCheckpoint(cp: any) {
  if (!SINK_URL) return;
  try {
    const res = await fetch(SINK_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(cp),
      signal: AbortSignal.timeout(2000),
      redirect: "error",
    });
    lastExport = { at: new Date().toISOString(), ok: res.ok, detail: `HTTP ${res.status}` };
  } catch (e: any) {
    lastExport = { at: new Date().toISOString(), ok: false, detail: String(e?.message || e).slice(0, 120) };
  }
}

/* ---------------- serialized hash-chain appends ----------------
 * Concurrent appends are queued so every caller honors log-before-act and the
 * chain never sees duplicate seqs. writeCheckpoint + sink export run inside
 * the same serialized critical section.
 */
let tail: { seq: number; hash: string } | null = null;
let queue: Promise<unknown> = Promise.resolve();
let cpSeq = -1;
let cpAt = 0;

function ensureCheckpointState() {
  if (cpSeq >= 0) return;
  const cps = readCheckpoints();
  const last = cps[cps.length - 1];
  cpSeq = last ? last.seq : 0;
  cpAt = last ? new Date(last.ts).getTime() : Date.now();
}

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

async function maybeCheckpoint(seq: number, hash: string) {
  ensureCheckpointState();
  const now = Date.now();
  if (seq - cpSeq >= CHECKPOINT_EVERY || now - cpAt >= CHECKPOINT_INTERVAL_S * 1000) {
    const cp = writeCheckpoint(seq, hash);
    cpSeq = seq;
    cpAt = now;
    await exportCheckpoint(cp);
  }
}

async function appendLocked(payload: Record<string, any>): Promise<LedgerEvent> {
  const cur = loadTail();
  const rec: any = { ...payload, seq: cur.seq + 1, prev_hash: cur.hash };
  rec.ts = rec.ts ?? new Date().toISOString();
  delete rec.hash;
  rec.hash = sha256(canonical(rec));
  appendJSONL(LEDGER_FILE, rec);
  tail = { seq: rec.seq, hash: rec.hash };
  await maybeCheckpoint(rec.seq, rec.hash);
  return rec as LedgerEvent;
}

/** Append a tamper-evident event. Rejects (never swallows) when the write fails. */
export function appendEvent(payload: Record<string, any>): Promise<LedgerEvent> {
  const run = queue.then(() => appendLocked(payload));
  queue = run.catch(() => {});
  return run;
}

export function ledgerEvents(filter?: (e: any) => boolean): LedgerEvent[] {
  const rows = readJSONL(LEDGER_FILE);
  return filter ? rows.filter(filter) : rows;
}

/** Recompute the entire chain + validate the latest checkpoint and detect rollback/rewrite. */
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
    return { valid: true, length: rows.length, checkpoint: null, public_key_fp: publicKeyFingerprint() };

  const cp = cps[cps.length - 1];
  if (!verifyCheckpointSignature(cp))
    return { valid: false, length: rows.length, checkpoint: cp, why: "checkpoint_bad_signature" };
  if (cp.seq > rows.length)
    return { valid: false, length: rows.length, checkpoint: cp, why: "ledger_behind_checkpoint" };
  const anchor = rows.find((r) => r.seq === cp.seq);
  if (anchor && anchor.hash !== cp.last_hash)
    return { valid: false, length: rows.length, checkpoint: cp, why: "history_rewrite_at_checkpoint" };
  return { valid: true, length: rows.length, checkpoint: cp, public_key_fp: publicKeyFingerprint() };
}

export function latestCheckpointInfo() {
  const cps = readCheckpoints();
  if (cps.length === 0) return null;
  const cp = cps[cps.length - 1];
  return { ...cp, signature_valid: verifyCheckpointSignature(cp) };
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