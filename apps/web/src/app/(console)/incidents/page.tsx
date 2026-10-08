import Link from "next/link";
import { apiFetch } from "@/lib/api";
import { humanize, VERDICT_LABEL } from "@/lib/labels";
import type { AnalysisSummary } from "@/lib/types";

export default async function IncidentsPage() {
  const analyses = await apiFetch<AnalysisSummary[]>("/v1/analyses?limit=100");
  return (
    <>
      <header className="page-head">
        <span className="eyebrow">INCIDENT HISTORY</span>
        <h1>Analyses for your tenant</h1>
        <p className="muted">Most recent first. Stored in memory by the experimental v1 API.</p>
      </header>
      <section className="panel">
        {analyses.length === 0 ? (
          <p className="muted">No analyses yet.</p>
        ) : (
          <table>
            <thead>
              <tr><th>When</th><th>Verdict</th><th>Risk</th><th>Action</th><th>Source</th><th>Host</th><th /></tr>
            </thead>
            <tbody>
              {analyses.map((a) => (
                <tr key={a.analysis_id}>
                  <td>{new Date(a.created_at).toLocaleString()}</td>
                  <td>
                    <span className={`pill pill-${a.verdict}`}>{VERDICT_LABEL[a.verdict]}</span>
                    {a.mock_intelligence_used && <span className="chip">mock intel</span>}
                  </td>
                  <td>{a.risk_score}</td>
                  <td>{humanize(a.recommended_action)}</td>
                  <td>{a.content_type}</td>
                  <td>{a.url_host ?? "—"}</td>
                  <td><Link href={`/incidents/${encodeURIComponent(a.analysis_id)}`}>Details</Link></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </>
  );
}
