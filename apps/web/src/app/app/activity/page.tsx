import Link from "next/link";
import { apiFetch } from "@/lib/api";
import type { ActivityItem } from "@/lib/cases";
import type { AuditEvent } from "@/lib/types";

export default async function ActivityPage() {
  const [activity, events, blocklist] = await Promise.all([
    apiFetch<ActivityItem[]>("/v1/activity?limit=200").catch(() => []),
    apiFetch<AuditEvent[]>("/v1/events?limit=200").catch(() => []),
    apiFetch<{ domain: string; added_by: string; added_at: string; case_id: string }[]>("/v1/blocklist").catch(() => []),
  ]);
  return (
    <div className="page">
      <header className="page-head">
        <span className="eyebrow">Activity &amp; audit</span>
        <h1>Responses, approvals and decisions</h1>
        <p className="muted">Proposed → approved or rejected → executed or failed, with who did what. Stored durably when
          the API runs with <code>TEGER_DB_PATH</code>.</p>
      </header>
      <section className="panel">
        <div className="panel-title"><h2>Investigation activity</h2></div>
        <div className="table-wrap"><table className="table">
          <thead><tr><th>Time (UTC)</th><th>Event</th><th>Actor</th><th>Detail</th></tr></thead>
          <tbody>
            {activity.map((a) => (
              <tr key={a.seq}>
                <td className="mono small">{a.ts.slice(0, 19).replace("T", " ")}</td>
                <td className="mono small">{a.type}</td>
                <td className="small">{a.actor}</td>
                <td>{a.message} {a.case_id && <Link className="small" href={`/app/cases/${a.case_id}`}>case</Link>}</td>
              </tr>
            ))}
            {!activity.length && <tr><td colSpan={4} className="muted">No activity yet.</td></tr>}
          </tbody>
        </table></div>
      </section>
      <section className="panel mt">
        <div className="panel-title"><h2>Teger blocklist</h2><span className="small muted">Used by future Teger investigations only — not enforced in browsers, DNS or email.</span></div>
        <div className="table-wrap"><table className="table">
          <thead><tr><th>Domain</th><th>Added by</th><th>When</th></tr></thead>
          <tbody>
            {blocklist.map((b) => <tr key={b.domain}><td className="mono">{b.domain}</td><td className="small">{b.added_by}</td><td className="mono small">{b.added_at.slice(0, 16)}</td></tr>)}
            {!blocklist.length && <tr><td colSpan={3} className="muted">Empty.</td></tr>}
          </tbody>
        </table></div>
      </section>
      <section className="panel mt">
        <div className="panel-title"><h2>API audit events</h2><span className="small muted">Message content is never logged.</span></div>
        <div className="table-wrap"><table className="table">
          <thead><tr><th>Time</th><th>Event</th><th>Outcome</th><th>Key</th></tr></thead>
          <tbody>
            {events.map((e) => (
              <tr key={`${e.request_id}-${e.event}-${e.ts}`}><td className="mono small">{e.ts.slice(0, 19).replace("T", " ")}</td>
                <td className="mono small">{e.event}</td><td>{e.outcome}</td><td className="mono small">{e.key_id ?? "—"}</td></tr>
            ))}
            {!events.length && <tr><td colSpan={4} className="muted">No events yet.</td></tr>}
          </tbody>
        </table></div>
      </section>
    </div>
  );
}
