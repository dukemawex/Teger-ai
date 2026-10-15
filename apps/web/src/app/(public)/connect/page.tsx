import type { Metadata } from "next";
import { ConnectForm } from "./ConnectForm";

export const metadata: Metadata = { title: "Console sign-in", robots: { index: false, follow: false } };

function safeNext(value: string | undefined): string {
  return value && /^\/app(\/[A-Za-z0-9_\-/]*)?$/.test(value) ? value : "/app";
}

export default async function ConnectPage({ searchParams }: { searchParams: Promise<{ expired?: string; next?: string }> }) {
  const { expired, next } = await searchParams;
  return (
    <div className="page">
      <div className="grid-2">
        <section>
          <span className="eyebrow">Teger console · private beta</span>
          <h1 className="case-title">Connect with a tenant API key</h1>
          <p className="muted">During the private beta, access uses an API key issued to your organization
            (<code>tgr_…</code>). The key is checked by the Teger API and kept only in an encrypted, HttpOnly cookie for
            8 hours — never in browser storage.</p>
          <p className="small muted">No key yet? The <a href="/demo">interactive demo</a> shows the full workflow with
            synthetic evidence and needs no account.</p>
        </section>
        <section className="panel panel-pad">
          {expired && <p className="notice notice-warn">Your session ended. Please reconnect.</p>}
          <ConnectForm next={safeNext(next)} />
        </section>
      </div>
    </div>
  );
}
