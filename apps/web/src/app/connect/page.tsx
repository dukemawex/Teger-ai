import { ConnectForm } from "./ConnectForm";

export default async function ConnectPage({ searchParams }: { searchParams: Promise<{ expired?: string }> }) {
  const { expired } = await searchParams;
  return (
    <main className="connect">
      <div className="panel connect-card">
        <div className="brand">
          <span className="brand-mark">T</span>
          <div>
            <span className="eyebrow">TEGER AI</span>
            <strong>Security Console</strong>
          </div>
        </div>
        <h1>Connect with an API key</h1>
        {expired && <p className="notice">Your session ended. Please reconnect.</p>}
        <p className="muted small">
          Paste a tenant API key (<code>tgr_…</code>). It is checked by the Teger API and kept in an encrypted, HttpOnly
          cookie — never in browser storage.
        </p>
        <ConnectForm />
      </div>
    </main>
  );
}
