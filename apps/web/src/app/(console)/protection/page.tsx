import { StatusBadge } from "@/components/StatusBadge";
import { apiFetch } from "@/lib/api";
import type { CapabilityModule } from "@/lib/types";

const GROUPS: { title: string; anchor: string; ids: string[] }[] = [
  { title: "Browser protection", anchor: "browser", ids: ["browser_message_scan", "browser_url_protection", "url_reputation"] },
  { title: "Email protection", anchor: "email", ids: ["email_protection", "ai_explanations"] },
  { title: "Endpoint protection", anchor: "endpoint", ids: ["endpoint_protection", "mobile_protection"] },
];

export default async function ProtectionPage() {
  const { modules } = await apiFetch<{ modules: CapabilityModule[] }>("/v1/capabilities");
  const byId = new Map(modules.map((m) => [m.id, m]));
  return (
    <>
      <header className="page-head">
        <span className="eyebrow">PROTECTION STATUS</span>
        <h1>What is actually protecting you today</h1>
        <p className="muted">Statuses come from the API&apos;s capability report. Planned modules are not active.</p>
      </header>
      <div className="cards">
        {GROUPS.map((group) => (
          <section key={group.anchor} id={group.anchor} className="panel">
            <h2>{group.title}</h2>
            <ul className="status-list">
              {group.ids.map((id) => byId.get(id)).filter((m): m is CapabilityModule => Boolean(m)).map((m) => (
                <li key={m.id}>
                  <div><strong>{m.name}</strong><p className="muted small">{m.detail}</p></div>
                  <StatusBadge status={m.status} />
                </li>
              ))}
            </ul>
          </section>
        ))}
      </div>
    </>
  );
}
