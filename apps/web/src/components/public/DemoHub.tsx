"use client";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { useEffect, useState } from "react";
import { caseApi } from "@/components/case/useCaseApi";
import { VerdictSeal } from "@/components/VerdictSeal";
import type { CaseSummary, InvestigationCase } from "@/lib/cases";

interface CatalogItem { id: string; label: string; teaser: string; subject: string; sender: string }

const api = caseApi("/api/demo");
const NUMERALS = ["I", "II", "III", "IV", "V"];

export function DemoHub() {
  const router = useRouter();
  const params = useSearchParams();
  const [catalog, setCatalog] = useState<CatalogItem[] | null>(null);
  const [cases, setCases] = useState<CaseSummary[]>([]);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState("");
  const [tick, setTick] = useState(0);
  const preferred = params.get("case");

  useEffect(() => {
    Promise.all([api.get<CatalogItem[]>("catalog"), api.get<CaseSummary[]>("cases")])
      .then(([c, s]) => { setCatalog(c); setCases(s); setError(""); })
      .catch((err) => setError(err instanceof Error ? err.message : "The demo service is unavailable."));
  }, [tick]);

  async function start(id: string) {
    setBusy(id);
    setError("");
    try {
      const created = await api.post<InvestigationCase>("cases", { fixture_id: id });
      router.push(`/demo/cases/${created.id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not start the case.");
      setBusy("");
    }
  }

  async function reset() {
    if (!window.confirm("Reset your demo? This clears only your own demo cases and approvals.")) return;
    setBusy("reset");
    try {
      await api.post("session/reset");
      setTick((t) => t + 1);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Reset failed.");
    } finally {
      setBusy("");
    }
  }

  return (
    <div className="page">
      <header className="page-head row-head">
        <div>
          <span className="eyebrow">Interactive demo</span>
          <h1>Choose a case to investigate</h1>
          <p className="muted">You play the reviewer at Harbor &amp; Quill Ltd, a fictional company. Teger opens a case,
            runs its checks, and proposes responses that only you can approve.</p>
        </div>
        <div className="btn-row">
          <Link className="btn btn-small" href="/demo/context">View approved context</Link>
          <button className="btn btn-small" onClick={reset} disabled={!!busy}>Reset demo</button>
        </div>
      </header>

      {error && (
        <div className="notice notice-danger" role="alert">
          <p>{error}</p>
          <button className="btn btn-small" onClick={() => setTick((t) => t + 1)}>Try again</button>
        </div>
      )}

      <ol className="catalogue" aria-label="Demonstration cases">
        {(catalog ?? []).map((c, i) => (
          <li key={c.id} className={preferred === c.id ? "preferred" : undefined}>
            <span className="numeral" aria-hidden="true">{NUMERALS[i]}</span>
            <div>
              <h2 className="serif"><span className="visually-hidden">Case {NUMERALS[i]}: </span>{c.label}</h2>
              <p className="small muted">{c.teaser}</p>
              <p className="tiny mono">{c.sender} — “{c.subject}”</p>
            </div>
            <button className={`btn ${preferred === c.id ? "btn-primary" : ""}`} disabled={!!busy}
              onClick={() => start(c.id)} aria-label={`Investigate case ${NUMERALS[i]}: ${c.label}`}>
              {busy === c.id ? "Opening…" : "Investigate"}
            </button>
          </li>
        ))}
        {!catalog && !error && <li><span className="spinner" /> <span className="muted">Loading cases…</span></li>}
      </ol>

      {cases.length > 0 && (
        <section className="panel mt" aria-labelledby="yours">
          <div className="panel-title"><h2 id="yours">Your demo cases</h2><span className="small muted">Visible only in this browser</span></div>
          <ul className="case-list">
            {cases.map((c) => (
              <li key={c.id}><Link href={`/demo/cases/${c.id}`}>
                <span className="t">{c.title}</span>
                <span><VerdictSeal verdict={c.verdict} label={c.verdict ? undefined : c.status} /></span>
              </Link></li>
            ))}
          </ul>
        </section>
      )}
    </div>
  );
}
