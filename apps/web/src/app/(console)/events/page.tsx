import { apiFetch } from "@/lib/api";
import type { AuditEvent } from "@/lib/types";

export default async function EventsPage() {
  const events = await apiFetch<AuditEvent[]>("/v1/events?limit=200");
  return (
    <>
      <header className="page-head">
        <span className="eyebrow">SECURITY EVENTS</span>
        <h1>Audit trail</h1>
        <p className="muted">Events recorded by the API for your tenant. Message content is never logged.</p>
      </header>
      <section className="panel">
        {events.length === 0 ? <p className="muted">No events yet.</p> : (
          <table>
            <thead><tr><th>Time</th><th>Event</th><th>Outcome</th><th>Key</th><th>Details</th></tr></thead>
            <tbody>
              {events.map((e) => (
                <tr key={`${e.request_id}-${e.event}`}>
                  <td>{new Date(e.ts).toLocaleString()}</td>
                  <td><code>{e.event}</code></td>
                  <td>{e.outcome}</td>
                  <td>{e.key_id ?? "—"}</td>
                  <td className="muted small">
                    {Object.entries(e.details).map(([k, v]) => `${k}=${String(v)}`).join(" · ")}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </>
  );
}
