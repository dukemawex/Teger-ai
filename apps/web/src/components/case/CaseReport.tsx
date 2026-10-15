"use client";

import Link from "next/link";
import { METHOD_LABEL, VERDICT_NOTE, ACTION_STATE_LABEL, TOOL_LABEL, shortTime } from "@/lib/cases";
import { VerdictSeal } from "@/components/VerdictSeal";
import { useCase } from "./useCaseApi";

/** A clean, printable case report built from the same case data as the workspace. */
export function CaseReport({ base, caseId, backHref, mode }: {
  base: string; caseId: string; backHref: string; mode: "demo" | "live";
}) {
  const { data, events, error, refresh } = useCase(base, caseId);
  if (error && !data) {
    return <div className="report"><p className="notice notice-danger" role="alert">{error}</p>
      <button className="btn" onClick={refresh}>Try again</button></div>;
  }
  if (!data) return <div className="report"><span className="spinner" /> Loading report…</div>;
  const a = data.assessment;
  return (
    <article className="report">
      <div className="btn-row no-print">
        <Link className="btn btn-small" href={backHref}>← Back to case</Link>
        <button className="btn btn-small" onClick={() => window.print()}>Print or save as PDF</button>
      </div>
      <p className="eyebrow mt">Teger investigation report{mode === "demo" ? " · DEMO — SYNTHETIC EVIDENCE" : ""}</p>
      <h1>{data.title}</h1>
      <p className="small muted">Case <span className="mono">{data.id}</span> · version {data.version} · opened {new Date(data.created_at).toUTCString()} · planner: {data.planner}</p>
      {a ? <><VerdictSeal verdict={a.verdict} /> <p className="mt"><strong>{a.headline}.</strong> {VERDICT_NOTE[a.verdict]}</p></> :
        <p>No assessment ({data.status}).</p>}

      <h2>1. What was submitted</h2>
      <p className="small">
        {data.input.sender && <>Sender: <span className="mono">{data.input.sender}</span><br /></>}
        {data.input.subject && <>Subject: {data.input.subject}<br /></>}
        {data.input.url && <>URL: <span className="mono">{data.input.url}</span></>}
      </p>
      {data.input.message && <div className="untrusted">{data.input.message}</div>}

      <h2>2. Checks performed</h2>
      <ol>{data.tools.map((t) => (
        <li key={t.seq}><strong>{TOOL_LABEL[t.tool] ?? t.tool}</strong> — {t.state}. {t.purpose} <span className="muted small">({t.selected_by})</span></li>
      ))}</ol>

      <h2>3. Evidence</h2>
      <ol>{data.evidence.map((e) => (
        <li key={e.id}><span className="mono">{e.id}</span> [{METHOD_LABEL[e.method]}] {e.summary}
          <span className="muted small"> — {e.source}, {shortTime(e.collected_at)} UTC</span></li>
      ))}</ol>

      {a && <>
        <h2>4. Findings and business context</h2>
        <ul>{a.findings.map((f) => <li key={f.id}>{f.statement} <span className="mono small">({f.evidence_ids.join(", ")})</span></li>)}</ul>
        {a.contradictions.length > 0 && <><p><strong>Contradictory evidence</strong></p>
          <ul>{a.contradictions.map((f) => <li key={f.id}>{f.statement} <span className="mono small">({f.evidence_ids.join(", ")})</span></li>)}</ul></>}
        {a.uncertainties.length > 0 && <><p><strong>Remaining uncertainty</strong></p><ul>{a.uncertainties.map((u) => <li key={u}>{u}</li>)}</ul></>}
        <p><strong>Effect of approved context:</strong> {a.context_effect}</p>
        <p><strong>Recommended next action:</strong> {a.recommended_next_action}</p>
      </>}

      <h2>5. Proposed responses and approvals</h2>
      <ul>{data.actions.map((x) => (
        <li key={x.id}><strong>{x.title}</strong> — {ACTION_STATE_LABEL[x.state]}{x.decided_by ? ` (decision by ${x.decided_by})` : ""}.
          {" "}{x.execution_result ?? ""} <span className="muted small">Scope: {x.enforcement_scope}</span></li>
      ))}</ul>
      {data.resolution && <p>Outcome recorded: <strong>{data.resolution.outcome.replace(/_/g, " ")}</strong> by {data.resolution.recorded_by}.</p>}

      <h2>6. Case history</h2>
      <ol className="small">{events.map((e) => <li key={e.seq}><span className="mono">{shortTime(e.ts)}</span> {e.message}</li>)}</ol>
      <p className="tiny muted mt">Policy {a?.policy_version ?? "—"}. Verdicts are produced by deterministic rules; model output never changes them.
        {mode === "demo" && " All organizations, domains and people in this report are fictional."}</p>
    </article>
  );
}
