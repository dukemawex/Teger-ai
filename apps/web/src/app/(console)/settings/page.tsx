import { apiFetch, apiBase } from "@/lib/api";
import type { WhoAmI } from "@/lib/types";
import { DisconnectButton } from "./DisconnectButton";

export default async function SettingsPage() {
  const me = await apiFetch<WhoAmI>("/v1/whoami");
  return (
    <>
      <header className="page-head">
        <span className="eyebrow">ACCOUNT SETTINGS</span>
        <h1>Connection</h1>
      </header>
      <section className="panel">
        <dl className="facts">
          <dt>Tenant</dt><dd>{me.tenant_id}</dd>
          <dt>API key ID</dt><dd><code>{me.key_id}</code></dd>
          <dt>Scopes</dt><dd>{me.scopes.join(", ")}</dd>
          <dt>Cloud AI explanations</dt>
          <dd>{me.cloud_ai_allowed ? "Allowed for this key (still requires per-analysis consent)" : "Not allowed for this key"}</dd>
          <dt>API endpoint</dt><dd><code>{apiBase()}</code></dd>
        </dl>
        <p className="muted small">
          Your API key is stored only in an encrypted, HttpOnly cookie for this browser session (8 hours). User accounts
          and single sign-on are planned.
        </p>
        <DisconnectButton />
      </section>
    </>
  );
}
