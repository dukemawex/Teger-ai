import type { Metadata } from "next";
import { Nav } from "@/components/Nav";
import { Wordmark } from "@/components/Mark";
import { apiFetch } from "@/lib/api";
import type { WhoAmI } from "@/lib/types";

export const dynamic = "force-dynamic";
export const metadata: Metadata = {
  title: "Workspace",
  robots: { index: false, follow: false },
};

export default async function WorkspaceLayout({ children }: { children: React.ReactNode }) {
  const me = await apiFetch<WhoAmI>("/v1/whoami");
  return (
    <div className="app-shell">
      <a className="skip" href="#main">Skip to content</a>
      <aside className="app-side">
        <Wordmark href="/" />
        <Nav />
        <div className="tenant">
          <div className="label-caps">Tenant</div>
          <strong>{me.tenant_id}</strong>
          <div className="tiny">key {me.key_id} · {me.scopes.length} scopes</div>
          <div className="tiny">Experimental private-beta workspace</div>
        </div>
      </aside>
      <main id="main" className="app-main">{children}</main>
    </div>
  );
}
