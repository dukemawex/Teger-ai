"use client";

import Link from "next/link";
import { useEffect, useMemo, useRef, useState } from "react";
import {
  ACTION_STATE_LABEL,
  METHOD_LABEL,
  ROUTE_STAGES,
  TOOL_LABEL,
  VERDICT_NOTE,
  isActive,
  newIdempotencyKey,
  shortTime,
  type CaseSummary,
  type InvestigationCase,
  type ProposedAction,
  type StageKey,
} from "@/lib/cases";
import { VerdictSeal } from "@/components/VerdictSeal";
import { CaseRoute } from "./CaseRoute";
import { useCase } from "./useCaseApi";

type Tab = "evidence" | "findings" | "actions" | "timeline";

function useNarrow(): boolean {
  const [narrow, setNarrow] = useState(false);
  useEffect(() => {
    const mq = window.matchMedia("(max-width: 900px)");
    const update = () => setNarrow(mq.matches);
    update();
    mq.addEventListener("change", update);
    return () => mq.removeEventListener("change", update);
  }, []);
  return narrow;
}

function toolStateLabel(state: string): string {
  return { completed: "Completed", failed: "Failed", skipped: "Skipped", unavailable: "Unavailable",
    running: "Running", pending: "Pending" }[state] ?? state;
}

function ToolGlyph({ state }: { state: string }) {
  const p = { width: 18, height: 18, viewBox: "0 0 20 20", "aria-hidden": true as const };
  if (state === "completed") return <svg {...p}><path d="m4 10.5 4 4 8-9" fill="none" stroke="currentColor" strokeWidth="2.2" /></svg>;
  if (state === "failed") return <svg {...p}><path d="m5 5 10 10M15 5 5 15" stroke="currentColor" strokeWidth="2.2" /></svg>;
  if (state === "unavailable" || state === "skipped") return <svg {...p}><path d="M4 10h12" stroke="currentColor" strokeWidth="2.4" /></svg>;
  return <span className="spinner" aria-hidden="true" />;
}

export function CaseWorkspace({ base, caseId, mode, homeHref, casePrefix }: {
  base: string;
  caseId: string;
  mode: "demo" | "live";
  homeHref: string;
  casePrefix: string;
}) {
  const caseHref = (id: string) => `${casePrefix}/${id}`;
  const reportHref = `${casePrefix}/${caseId}/report`;
  const { api, data, events, error, refresh } = useCase(base, caseId);
  const [cases, setCases] = useState<CaseSummary[]>([]);
  const [stage, setStage] = useState<StageKey | null>(null);
  const [highlight, setHighlight] = useState<string | null>(null);
  const [tab, setTab] = useState<Tab>("evidence");
  const [busy, setBusy] = useState<string>("");
  const [actionError, setActionError] = useState<string>("");
  const [announce, setAnnounce] = useState("");
  const idemKeys = useRef<Record<string, string>>({});
  const narrow = useNarrow();
  const lastStatus = useRef<string>("");

  useEffect(() => {
    api.get<CaseSummary[]>("cases").then(setCases).catch(() => setCases([]));
  }, [api, data?.status, data?.actions.length]);

  useEffect(() => {
    if (!data) return;
    const running = data.tools.find((t) => t.state === "running");
    if (running) setAnnounce(`Running: ${running.purpose}`);
    if (data.status !== lastStatus.current) {
      if (data.status === "completed" && data.assessment) {
        setAnnounce(`Investigation complete. Verdict: ${data.assessment.verdict.replace(/_/g, " ")}. ${data.assessment.headline}.`);
      } else if (data.status === "cancelled") setAnnounce("Investigation cancelled.");
      lastStatus.current = data.status;
    }
  }, [data]);

  const visibleEvidence = useMemo(() => {
    if (!data) return [];
    if (!stage) return data.evidence;
    const tools = ROUTE_STAGES.find((s) => s.key === stage)!.tools as readonly string[];
    const ids = new Set(data.tools.filter((t) => tools.includes(t.tool)).flatMap((t) => t.evidence_ids));
    if (stage === "decision" && data.assessment) {
      data.assessment.findings.forEach((f) => f.evidence_ids.forEach((id) => ids.add(id)));
    }
    return data.evidence.filter((e) => ids.has(e.id));
  }, [data, stage]);

  function focusEvidence(id: string) {
    setStage(null);
    setTab("evidence");
    setHighlight(id);
    setTimeout(() => document.getElementById(`ev-${caseId}-${id}`)?.scrollIntoView({ behavior: "smooth", block: "center" }), 50);
    setTimeout(() => setHighlight(null), 2200);
  }

  async function run(label: string, fn: () => Promise<unknown>) {
    setBusy(label);
    setActionError("");
    try {
      await fn();
      refresh();
    } catch (err) {
      setActionError(err instanceof Error ? err.message : "That did not work.");
    } finally {
      setBusy("");
    }
  }

  async function decide(action: ProposedAction, decision: "approve" | "reject") {
    await run(`${decision}-${action.id}`, () => api.post(`actions/${action.id}/${decision}`, {
      case_version: data!.version, params_hash: action.params_hash,
    }));
    setAnnounce(decision === "approve" ? `Approved: ${action.title}` : `Rejected: ${action.title}`);
  }

  async function execute(action: ProposedAction) {
    idemKeys.current[action.id] ??= newIdempotencyKey();
    await run(`execute-${action.id}`, () => api.post(`actions/${action.id}/execute`, {
      idempotency_key: idemKeys.current[action.id],
    }));
    setAnnounce(`Executed: ${action.title}`);
  }

  async function exportJson() {
    await run("export", async () => {
      const body = await api.get<unknown>(`cases/${caseId}/export`);
      const blob = new Blob([JSON.stringify(body, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `teger-${caseId}.json`;
      a.click();
      URL.revokeObjectURL(url);
    });
  }

  if (error && !data) {
    return (
      <div className="page">
        <p className="notice notice-danger" role="alert">{error}</p>
        <div className="btn-row"><button className="btn" onClick={refresh}>Try again</button>
          <Link className="btn" href={homeHref}>Back</Link></div>
      </div>
    );
  }
  if (!data) return <div className="page"><p className="muted"><span className="spinner" /> Loading case…</p></div>;

  const active = isActive(data.status);
  const a = data.assessment;
  const panel = (name: Tab) => ({ "data-tab-panel": name, hidden: narrow && tab !== name, id: `panel-${name}`,
    role: narrow ? "tabpanel" : undefined, "aria-labelledby": narrow ? `tab-${name}` : undefined });

  return (
    <div className="page">
      <div aria-live="polite" className="visually-hidden">{announce}</div>
      <div className="workspace">
        {/* ------------------------------------------------ case rail */}
        <aside className="rail" aria-label="Cases">
          <div className="panel">
            <div className="panel-title"><h2>Cases</h2><Link className="small" href={homeHref}>New</Link></div>
            <ul className="case-list">
              {cases.map((c) => (
                <li key={c.id}>
                  <Link href={caseHref(c.id)} aria-current={c.id === caseId ? "page" : undefined}>
                    <span className="t">{c.title}</span>
                    <span className="tiny muted">{c.verdict ? c.verdict.replace(/_/g, " ") : c.status}</span>
                    {c.pending_approvals > 0 && <span className="tiny">{c.pending_approvals} awaiting approval</span>}
                  </Link>
                </li>
              ))}
              {!cases.length && <li className="panel-pad small muted">No cases yet.</li>}
            </ul>
          </div>
        </aside>

        {/* ------------------------------------------------ centre */}
        <section aria-labelledby="case-title">
          <span className="eyebrow">{mode === "demo" ? "Demo case · synthetic evidence" : "Investigation"}</span>
          <h1 id="case-title" className="case-title">{data.title}</h1>
          <div className="meta-row">
            <VerdictSeal verdict={a?.verdict ?? null} label={active ? "Investigating…" : undefined} />
            <span>Status: <strong>{data.status}</strong></span>
            <span>Version {data.version}</span>
            <span>Planner: {data.planner}</span>
            <span className="mono">{data.id}</span>
          </div>

          <div className="tabs" role="tablist" aria-label="Case sections">
            {(["evidence", "findings", "actions", "timeline"] as Tab[]).map((t) => (
              <button key={t} id={`tab-${t}`} role="tab" aria-selected={tab === t} aria-controls={`panel-${t}`}
                onClick={() => setTab(t)}>{t[0].toUpperCase() + t.slice(1)}</button>
            ))}
          </div>

          <div {...panel("evidence")}>
            <div className="panel panel-pad">
              <h2 className="serif">Submitted material</h2>
              <p className="small muted">
                {mode === "demo" ? `Synthetic fixture “${data.fixture_id}”, submitted by the demo visitor.` :
                  "Pasted by a reviewer in this tenant."} Received {new Date(data.created_at).toUTCString()}.
              </p>
              <dl className="submitted">
                {data.input.sender && <><dt>Sender</dt><dd className="mono">{data.input.sender}</dd></>}
                {data.input.subject && <><dt>Subject</dt><dd>{data.input.subject}</dd></>}
                {data.input.url && <><dt>Website URL</dt><dd className="mono">{data.input.url}</dd></>}
              </dl>
              {data.input.message && (
                <>
                  <div className="untrusted-label">Message text · untrusted content, shown as data</div>
                  <div className="untrusted">{data.input.message}</div>
                </>
              )}
            </div>

            <div className="panel">
              <div className="panel-title">
                <h2>Evidence route</h2>
                <span className="small muted">Select a stage to filter evidence</span>
              </div>
              <div className="panel-pad"><CaseRoute data={data} selected={stage} onSelect={setStage} /></div>
            </div>

            <div className="panel">
              <div className="panel-title"><h2>Tool activity</h2>
                <span className="small muted">Limit: {data.limits.max_tool_calls} calls · {data.limits.deadline_seconds}s</span>
              </div>
              <ol className="tools panel-pad" aria-live="off">
                {data.tools.map((t) => (
                  <li key={t.seq}>
                    <span className={`tool-state state-${t.state}`}><ToolGlyph state={t.state} /></span>
                    <div>
                      <div><strong>{TOOL_LABEL[t.tool] ?? t.tool}</strong> <span className="name muted">{t.tool}</span>{" "}
                        <span className={`tool-state state-${t.state}`}>{toolStateLabel(t.state)}</span></div>
                      <div className="why">{t.purpose}</div>
                      {t.detail && <div className="small">{t.detail}</div>}
                      <div className="by">Selected by {t.selected_by}
                        {t.evidence_ids.length > 0 && <> · {t.evidence_ids.map((id) => (
                          <button key={id} className="evid" onClick={() => focusEvidence(id)}>{id}</button>
                        )).reduce<React.ReactNode[]>((acc, el, i) => (i ? [...acc, " ", el] : [el]), [])}</>}
                      </div>
                    </div>
                  </li>
                ))}
                {active && !data.tools.some((t) => t.state === "running") && (
                  <li><span className="spinner" aria-hidden="true" /><div className="why">Choosing the next check…</div></li>
                )}
                {data.status === "cancelled" && <li><span /><div className="why">Cancelled before completion. No assessment was made.</div></li>}
              </ol>
            </div>

            <div className="panel">
              <div className="panel-title">
                <h2>Evidence {stage ? `· ${ROUTE_STAGES.find((s) => s.key === stage)!.label}` : ""}</h2>
                {stage && <button className="linklike small" onClick={() => setStage(null)}>Show all</button>}
              </div>
              <ol className="evidence">
                {visibleEvidence.map((e) => (
                  <li key={e.id} id={`ev-${caseId}-${e.id}`} className={highlight === e.id ? "highlight" : undefined}>
                    <div className="ehead">
                      <span className="mono evid">{e.id}</span>
                      <span className={`chip chip-${e.method === "model_inference" ? "model" : e.method}`}>{METHOD_LABEL[e.method]}</span>
                      {e.stance !== "neutral" && (
                        <span className={`chip chip-${e.stance}`}>{e.stance === "risk" ? "▲ Risk" : "● Supports legitimacy"}</span>
                      )}
                      {e.severity !== "info" && <span className="chip">{e.severity}</span>}
                    </div>
                    <div>{e.summary}</div>
                    <div className="src">
                      Source: {e.source} · {shortTime(e.collected_at)} UTC · via <span className="mono">{e.tool}</span>
                    </div>
                    {e.untrusted_excerpt && (
                      <>
                        <div className="untrusted-label">Untrusted excerpt</div>
                        <div className="untrusted">{e.untrusted_excerpt}</div>
                      </>
                    )}
                  </li>
                ))}
                {!visibleEvidence.length && <li className="muted small">{active ? "Collecting evidence…" : "No evidence for this stage."}</li>}
              </ol>
            </div>
          </div>
        </section>

        {/* ------------------------------------------------ findings & actions */}
        <aside className="side-right" aria-label="Assessment and response">
          <div {...panel("findings")}>
            <div className="panel findings">
              <div className="panel-title"><h2>Assessment</h2><span className="tiny muted">{a?.policy_version}</span></div>
              <div className="panel-pad">
                {!a && <p className="muted">{active ? "The assessment appears when the checks finish." :
                  data.status === "cancelled" ? "Cancelled — no assessment." : data.error ?? "No assessment."}</p>}
                {a && (
                  <>
                    <VerdictSeal verdict={a.verdict} />
                    <p className="serif"><strong className="serif">{a.headline}</strong></p>
                    <p className="small muted">{VERDICT_NOTE[a.verdict]}</p>
                    {a.findings.length > 0 && <h3>Supported findings</h3>}
                    <ul>{a.findings.map((f) => (
                      <li key={f.id}>{f.statement} {f.evidence_ids.map((id) => (
                        <button key={id} className="evid" onClick={() => focusEvidence(id)}>{id}</button>
                      ))}</li>
                    ))}</ul>
                    {a.contradictions.length > 0 && <h3>Contradictory evidence</h3>}
                    <ul>{a.contradictions.map((f) => (
                      <li key={f.id}>{f.statement} {f.evidence_ids.map((id) => (
                        <button key={id} className="evid" onClick={() => focusEvidence(id)}>{id}</button>
                      ))}</li>
                    ))}</ul>
                    {a.uncertainties.length > 0 && <h3>Remaining uncertainty</h3>}
                    <ul>{a.uncertainties.map((u) => <li key={u}>{u}</li>)}</ul>
                    <h3>How business context affected this</h3>
                    <p className="small">{a.context_effect}</p>
                    <div className="next-action">
                      <div className="label-caps">Recommended next action</div>
                      <div>{a.recommended_next_action}</div>
                    </div>
                  </>
                )}
              </div>
            </div>
          </div>

          <div {...panel("actions")}>
            <div className="panel">
              <div className="panel-title"><h2>Response</h2><span className="tiny muted">Human approval required</span></div>
              {actionError && <p className="notice notice-danger" role="alert">{actionError}</p>}
              {!data.actions.length && <p className="panel-pad muted small">No responses proposed yet.</p>}
              {data.actions.map((act) => (
                <div className="action" key={act.id}>
                  <div className="action-state">{ACTION_STATE_LABEL[act.state]}{act.demo_only ? " · demo only" : ""}</div>
                  <h4>{act.title}</h4>
                  <div className="scope"><strong>Scope:</strong> {act.enforcement_scope}</div>
                  {act.state === "proposed" && (
                    <div className="btn-row">
                      <button className="btn btn-primary btn-small" disabled={!!busy || act.case_version !== data.version}
                        onClick={() => decide(act, "approve")}>Approve</button>
                      <button className="btn btn-small" disabled={!!busy} onClick={() => decide(act, "reject")}>Reject</button>
                    </div>
                  )}
                  {act.state === "approved" && (
                    <button className="btn btn-primary btn-small" disabled={!!busy} onClick={() => execute(act)}>
                      {busy === `execute-${act.id}` ? "Executing…" : "Execute approved action"}
                    </button>
                  )}
                  {act.execution_result && <p className="small">{act.execution_result}</p>}
                  <ul className="trail">
                    <li>Proposed by {act.proposed_by} · {shortTime(act.proposed_at)}</li>
                    {act.decided_at && <li>{act.state === "rejected" ? "Rejected" : "Approved"} by {act.decided_by} · {shortTime(act.decided_at)}</li>}
                    {act.executed_at && <li>{act.state === "failed" ? "Failed" : "Executed"} · {shortTime(act.executed_at)}</li>}
                    {act.state === "expired" && <li>{act.decision_note ?? "Expired"}</li>}
                  </ul>
                </div>
              ))}
              <p className="panel-pad tiny muted">
                Email quarantine and browser-wide blocking are not available: no mail or enforcement integration is
                connected{mode === "demo" ? " in this demo" : ""}.
              </p>
            </div>

            <div className="panel panel-pad">
              <h3 className="serif">Case controls</h3>
              <div className="btn-row">
                <button className="btn btn-small" disabled={!active || !!busy}
                  onClick={() => run("cancel", () => api.post(`cases/${caseId}/cancel`))}>Cancel</button>
                <button className="btn btn-small" disabled={active || !!busy}
                  onClick={() => run("retry", () => api.post(`cases/${caseId}/retry`))}>Re-run</button>
                <button className="btn btn-small" disabled={!!busy} onClick={exportJson}>Export JSON</button>
                <Link className="btn btn-small" href={reportHref}>Report</Link>
              </div>
              {data.status === "completed" && !data.resolution && (
                <OutcomeForm initial={a?.verdict === "malicious" ? "confirmed_phishing" : a?.verdict === "no_threat_detected" ? "confirmed_legitimate" : "unresolved"} onSubmit={(outcome, note) => run("resolve", () => api.post(`cases/${caseId}/resolution`, { outcome, note: note || null }))} busy={!!busy} />
              )}
              {data.resolution && (
                <p className="small">Outcome: <strong>{data.resolution.outcome.replace(/_/g, " ")}</strong> — recorded by {data.resolution.recorded_by}.</p>
              )}
            </div>
          </div>

          <div {...panel("timeline")}>
            <div className="panel">
              <div className="panel-title"><h2>Case history</h2></div>
              <ol className="timeline panel-pad">
                {events.map((e) => (
                  <li key={e.seq}><time dateTime={e.ts}>{shortTime(e.ts)}</time><span>{e.message}</span></li>
                ))}
              </ol>
            </div>
          </div>
        </aside>
      </div>
    </div>
  );
}

function OutcomeForm({ onSubmit, busy, initial }: {
  onSubmit: (outcome: string, note: string) => void; busy: boolean; initial: string;
}) {
  const [outcome, setOutcome] = useState(initial);
  const [note, setNote] = useState("");
  return (
    <form className="form" onSubmit={(e) => { e.preventDefault(); onSubmit(outcome, note); }}>
      <label htmlFor="outcome">Record the outcome</label>
      <select id="outcome" value={outcome} onChange={(e) => setOutcome(e.target.value)}>
        <option value="confirmed_phishing">Confirmed phishing</option>
        <option value="confirmed_legitimate">Confirmed legitimate</option>
        <option value="unresolved">Unresolved</option>
      </select>
      <label htmlFor="outcome-note">Note (optional)</label>
      <input id="outcome-note" type="text" value={note} maxLength={500} onChange={(e) => setNote(e.target.value)} />
      <button className="btn btn-small" disabled={busy}>Record outcome</button>
    </form>
  );
}
