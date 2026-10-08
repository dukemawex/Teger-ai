import { Nav } from "@/components/Nav";
import { apiFetch } from "@/lib/api";
import type { WhoAmI } from "@/lib/types";

export const dynamic = "force-dynamic";

export default async function ConsoleLayout({ children }: { children: React.ReactNode }) {
  const me = await apiFetch<WhoAmI>("/v1/whoami");
  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark">T</span>
          <div>
            <span className="eyebrow">TEGER AI</span>
            <strong>Security Console</strong>
          </div>
        </div>
        <Nav />
        <div className="tenant">
          <span className="eyebrow">Tenant</span>
          <strong>{me.tenant_id}</strong>
          <span className="muted small">key {me.key_id}</span>
        </div>
      </aside>
      <main className="content">{children}</main>
    </div>
  );
}
