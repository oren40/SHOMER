/**
 * Evidence Pack: a verifiable export of what an agent was allowed to do,
 * what it actually did, what it cost, and who approved what.
 *
 * Framing: "evidence for your internal controls" - the pack documents
 * enforcement, approvals and cost attribution so internal audit / risk teams
 * can review agent deployments. It does not assert regulatory conformity.
 */
import { db } from "./store";
import { ledgerEvents, verifyLedger, latestCheckpointInfo, spentToday } from "./ledger";

export interface EvidenceQuery {
  agent_id?: string;
  from?: string; // ISO
  to?: string; // ISO
}

export function buildEvidence(q: EvidenceQuery) {
  const events = ledgerEvents((e) => {
    if (q.agent_id && e.agent_id !== q.agent_id) return false;
    if (q.from && e.ts < q.from) return false;
    if (q.to && e.ts > q.to) return false;
    return true;
  });

  const decisions = events.filter((e) => e.type === "decision").map((d) => ({
    ...d,
    outcomes: events.filter((o) => o.type === "outcome" && o.decision_id === d.decision_id),
  }));

  const approvals = db.approvals.filter(
    (a) => (!q.agent_id || a.agent_id === q.agent_id) &&
      (!q.from || a.requested_at >= q.from) &&
      (!q.to || a.requested_at <= q.to)
  );

  const byDecision = (pred: (d: any) => boolean) => decisions.filter(pred).length;
  const spend = new Set(decisions.map((d) => d.agent_id));

  const summary = {
    actions_governed: decisions.length,
    allowed: byDecision((d) => d.decision === "allow"),
    sanitized: byDecision((d) => d.decision === "sanitize"),
    blocked: byDecision((d) => d.decision === "deny"),
    human_reviews: byDecision((d) => d.decision === "require_human"),
    observe_only: byDecision((d) => d.decision === "observe_blocked"),
    metered_spend_usd:
      Math.round(
        decisions
          .flatMap((d) => d.outcomes)
          .filter((o) => o.status === "succeeded")
          .reduce((s, o) => s + (o.cost_usd || 0), 0) * 1e4
      ) / 1e4,
    spend_today_usd: q.agent_id ? spentToday(q.agent_id) : undefined,
    agents_touched: [...spend],
  };

  return {
    schema: "shomer.evidence/1.0",
    generated_at: new Date().toISOString(),
    subject: {
      agent_id: q.agent_id ?? null,
      agent: q.agent_id ? db.agents.find((a) => a.id === q.agent_id) ?? null : null,
      policies: db.policies.filter(
        (p) => !q.agent_id || p.agent_id === null || p.agent_id === q.agent_id
      ),
    },
    integrity: {
      chain_verification: verifyLedger(),
      checkpoint: latestCheckpointInfo(),
    },
    approvals,
    summary,
    decisions,
  };
}

/* ---------------- minimal, dependency-free PDF writer ---------------- */

function pdfEscape(s: string): string {
  return s.replace(/\\/g, "\\\\").replace(/\(/g, "\\(").replace(/\)/g, "\\)");
}

export function simplePDF(title: string, chunks: string[]): Buffer {
  const lines: string[] = [title, ""];
  for (const c of chunks) lines.push(...c.split("\n"));
  const perPage = 46;
  const pages: string[][] = [];
  for (let i = 0; i < lines.length; i += perPage) pages.push(lines.slice(i, i + perPage));

  const pageObjs: number[] = [];
  const contentObjs: number[] = [];
  for (let i = 0; i < pages.length; i++) {
    pageObjs.push(3 + i * 2);
    contentObjs.push(4 + i * 2);
  }
  const fontObj = 3 + pages.length * 2;

  const stream = (pageLines: string[]) => {
    let s = "BT\n/F1 8 Tf\n14 770 Td\n12 TL\n";
    for (const l of pageLines) s += `(${pdfEscape(l.slice(0, 110))}) Tj\nT*\n`;
    return s + "ET\n";
  };

  const objects: string[] = [
    "", // 0 reserved
    "<< /Type /Catalog /Pages 2 0 R >>",
    `<< /Type /Pages /Count ${pages.length} /Kids [${pageObjs.map((n) => `${n} 0 R`).join(" ")}] >>`,
  ];
  pages.forEach((pageLines, i) => {
    const s = stream(pageLines);
    objects[contentObjs[i]] = `<< /Length ${Buffer.byteLength(s, "latin1")} >>\nstream\n${s}endstream`;
    objects[pageObjs[i]] =
      `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] ` +
      `/Resources << /Font << /F1 ${fontObj} 0 R >> >> /Contents ${contentObjs[i]} 0 R >>`;
  });
  objects[fontObj] = "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>";

  let pdf = "%PDF-1.4\n";
  const offsets: number[] = [];
  for (let i = 1; i < objects.length; i++) {
    offsets[i] = Buffer.byteLength(pdf, "latin1");
    pdf += `${i} 0 obj\n${objects[i]}\nendobj\n`;
  }
  const xrefStart = Buffer.byteLength(pdf, "latin1");
  pdf += `xref\n0 ${objects.length}\n0000000000 65535 f \n`;
  for (let i = 1; i < objects.length; i++)
    pdf += `${String(offsets[i]).padStart(10, "0")} 00000 n \n`;
  pdf += `trailer\n<< /Size ${objects.length} /Root 1 0 R >>\nstartxref\n${xrefStart}\n%%EOF`;
  return Buffer.from(pdf, "latin1");
}

/** Human-readable text form of an evidence pack (used for the PDF body). */
export function evidenceToText(ev: ReturnType<typeof buildEvidence>): string[] {
  const s = ev.summary;
  const i = ev.integrity;
  const chunks: string[] = [];
  chunks.push(
    [
      "SHOMER EVIDENCE PACK",
      `subject agent: ${ev.subject.agent_id ?? "(all agents)"}`,
      `generated at:    ${ev.generated_at}`,
      "",
      "SUMMARY",
      `  actions governed: ${s.actions_governed}`,
      `  allowed / sanitized / blocked: ${s.allowed} / ${s.sanitized} / ${s.blocked}`,
      `  human reviews: ${s.human_reviews}`,
      `  observe-only (would-be blocks): ${s.observe_only}`,
      `  metered spend (USD): ${s.metered_spend_usd}`,
      "",
      "INTEGRITY",
      `  chain verification: ${i.chain_verification.valid ? "VALID" : "INVALID: " + i.chain_verification.why}`,
      `  ledger length: ${i.chain_verification.length}`,
      `  checkpoint: ${i.checkpoint ? `seq ${i.checkpoint.seq} sig ${i.checkpoint.signature_valid ? "valid" : "INVALID"}` : "none yet"}`,
      "",
      "POLICIES IN FORCE",
    ].join("\n")
  );
  for (const p of ev.subject.policies)
    chunks.push(
      `  [${p.agent_id ?? "ALL"}] ${p.type} mode=${p.mode ?? "enforce"} prio=${p.priority} ${JSON.stringify(p.config)}`
    );
  chunks.push("");
  chunks.push("APPROVALS (human-in-the-loop)");
  if (ev.approvals.length === 0) chunks.push("  none");
  for (const a of ev.approvals)
    chunks.push(
      `  ${a.requested_at} ${a.agent_id} ${a.tool} ${a.status} by ${a.resolved_by ?? "-"} args_sha256=${a.args_hash?.slice(0, 16)}`
    );
  chunks.push("");
  chunks.push("DECISION LEDGER (decision + outcomes)");
  for (const d of ev.decisions) {
    chunks.push(
      `  ${d.ts.slice(0, 19)} ${d.agent_id} ${d.tool} -> ${d.decision}${d.would_deny_reason ? " (would: " + d.would_deny_reason + ")" : ""}`
    );
    for (const o of d.outcomes)
      chunks.push(
        `      outcome: ${o.status} cost=${o.cost_usd ?? 0} src=${o.cost_source ?? "-"} ${o.result_preview ? "| " + o.result_preview : ""}`
      );
  }
  return chunks;
}