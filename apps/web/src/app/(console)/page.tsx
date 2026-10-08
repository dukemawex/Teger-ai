import Link from "next/link";
import { StatusBadge } from "@/components/StatusBadge";
import { apiFetch } from "@/lib/api";
import { VERDICT_LABEL } from "@/lib/labels";
import type { AnalysisSummary, CapabilityModule, Verdict } from "@/lib/types";

export default async function OverviewPage() {
  const [caps, analyses] = await Promise.all([
    apiFetch<{ modules: CapabilityModule[] }>("/v1/capabilities"),
    apiFetch<AnalysisSummary[]>("/v1/analyses?limit=100"),
  ]);
  const counts = analyses.reduce<Record<Verdict, number>>(
    (acc, a) => ({ ...acc, [a.verdict]: acc[a.verdict] + 1 }),
    { malicious: 0, suspicious: 0, unknown: 0, no_threat_detected: 0 },
  );

  return (
    <>
      <header className="page-head">
        <span className="eyebrow">SECURITY OVERVIEW</span>
        <h1>Explain the attack, not just the alert.</h1>
        <p className="muted">
          Figures below come only from analyses submitted by your tenant to this API instance. Nothing here is
          simulated.
        </p>
      </header>

      <section className="metrics">
        {(Object.keys(counts) as Verdict[]).map((v) => (
          <article key={v} className={`metric metric-${v}`}>
            <span>{VERDICT_LABEL[v]}</span>
            <strong>{counts[v]}</strong>
          </article>
        ))}
      </section>
      <p className="muted small">
        {analyses.length === 0
          ? "No analyses yet. "
          : `Based on the ${analyses.length} most recent analyses. `}
        The v1 API currently keeps history in memory, so it resets when the API restarts.{" "}
        <Link href="/analyze">Run an analysis →</Link>
      </p>

      <section className="panel">
        <h2>Module status</h2>
        <table>
          <thead>
            <tr><th>Module</th><th>Status</th><th>Detail</th></tr>
          </thead>
          <tbody>
            {caps.modules.map((m) => (
              <tr key={m.id}>
                <td>{m.name}</td>
                <td><StatusBadge status={m.status} /></td>
                <td className="muted">{m.detail}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </>
  );
}
