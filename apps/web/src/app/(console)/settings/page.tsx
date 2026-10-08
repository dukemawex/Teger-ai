import { apiFetch, apiBase, byokStatus } from "@/lib/api";
import type { CapabilityModule, WhoAmI } from "@/lib/types";
import { ByokForm } from "./ByokForm";
import { DisconnectButton } from "./DisconnectButton";

export default async function SettingsPage() {
  const [me, caps, byok] = await Promise.all([
    apiFetch<WhoAmI>("/v1/whoami"),
    apiFetch<{ ai?: { byok_allowed: boolean }; modules: CapabilityModule[] }>("/v1/capabilities"),
    byokStatus(),
  ]);
  const byokAllowed = Boolean(caps.ai?.byok_allowed);
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
          <dt>Teger&apos;s AI key</dt>
          <dd>{me.cloud_ai_allowed ? "Allowed for this API key (still requires per-analysis consent)" : "Not enabled for this API key"}</dd>
          <dt>API endpoint</dt><dd><code>{apiBase()}</code></dd>
        </dl>
        <p className="muted small">
          Your API key is stored only in an encrypted, HttpOnly cookie for this browser session (8 hours). User accounts
          and single sign-on are planned.
        </p>
        <DisconnectButton />
      </section>
      <section className="panel">
        <h2>Teger Intelligence — bring your own key</h2>
        <ByokForm initialHint={byok.hint} byokAllowed={byokAllowed} />
      </section>
    </>
  );
}
