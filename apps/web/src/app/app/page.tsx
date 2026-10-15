import Link from "next/link";
import { StatusBadge } from "@/components/StatusBadge";
import { VerdictSeal } from "@/components/VerdictSeal";
import { apiFetch } from "@/lib/api";
import type { CaseSummary } from "@/lib/cases";
import type { CapabilityModule } from "@/lib/types";

export default async function OverviewPage() {
  const [cases, caps] = await Promise.all([
    apiFetch<CaseSummary[]>("/v1/cases?limit=50").catch(() => null),
    apiFetch<{ modules: CapabilityModule[] }>("/v1/capabilities"),
  ]);
  const pending = (cases ?? []).reduce((n, c) => n + c.pending_approvals, 0);
  return (
    <div className="page">
      <header className="page-head row-head">
        <div>
          <span className="eyebrow">Investigation overview</span>
          <h1>Cases for your tenant</h1>
          <p className="muted small">Only investigations submitted by your tenant appear here. Nothing is simulated.</p>
        </div>
        <Link className="btn btn-primary" href="/app/analyze">Start an investigation</Link>
      </header>

      {cases === null && (
        <p className="notice notice-warn">This API key cannot read investigations (it needs the <code>cases:read</code> scope).</p>
      )}
      {pending > 0 && <p className="notice notice-warn">{pending} proposed response(s) are awaiting approval.</p>}

      <section className="panel">
        <div className="panel-title"><h2>Recent cases</h2></div>
        <div className="table-wrap">
          <table className="table">
            <thead><tr><th>Case</th><th>Assessment</th><th>Status</th><th>Approvals</th><th>Opened</th></tr></thead>
            <tbody>
              {(cases ?? []).map((c) => (
                <tr key={c.id}>
                  <td><Link href={`/app/cases/${c.id}`}>{c.title}</Link></td>
                  <td><VerdictSeal verdict={c.verdict} /></td>
                  <td>{c.status}</td>
                  <td>{c.pending_approvals ? `${c.pending_approvals} awaiting` : "—"}</td>
                  <td className="mono small">{new Date(c.created_at).toISOString().slice(0, 16).replace("T", " ")}</td>
                </tr>
              ))}
              {cases && !cases.length && <tr><td colSpan={5} className="muted">No investigations yet.</td></tr>}
            </tbody>
          </table>
        </div>
      </section>

      <section className="panel mt">
        <div className="panel-title"><h2>Capability status</h2><span className="small muted">From the API&apos;s capability report</span></div>
        <div className="table-wrap">
          <table className="table">
            <thead><tr><th>Module</th><th>Status</th><th>Detail</th></tr></thead>
            <tbody>
              {caps.modules.map((m) => (
                <tr key={m.id}><td>{m.name}</td><td><StatusBadge status={m.status} /></td><td className="muted">{m.detail}</td></tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
