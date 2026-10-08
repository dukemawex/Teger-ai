import { apiFetch } from "@/lib/api";

interface Policy {
  policy_version: string;
  malicious_threshold: number;
  suspicious_threshold: number;
  unknown_when_required_intelligence_unavailable: boolean;
  ai_can_change_verdict: boolean;
  reputation_provider: string;
}

export default async function PoliciesPage() {
  const p = await apiFetch<Policy>("/v1/policy");
  return (
    <>
      <header className="page-head">
        <span className="eyebrow">SECURITY POLICIES</span>
        <h1>Detection policy {p.policy_version}</h1>
        <p className="muted">Read-only. Tenant-specific policies are planned for Teger Enterprise.</p>
      </header>
      <section className="panel">
        <dl className="facts">
          <dt>Malicious when risk score ≥</dt><dd>{p.malicious_threshold}</dd>
          <dt>Suspicious when risk score ≥</dt><dd>{p.suspicious_threshold} (or any critical indicator)</dd>
          <dt>Missing required intelligence</dt>
          <dd>{p.unknown_when_required_intelligence_unavailable ? "Verdict is Unknown, never safe" : "—"}</dd>
          <dt>Can AI change a verdict?</dt><dd>{p.ai_can_change_verdict ? "Yes" : "No — explanation only"}</dd>
          <dt>Reputation provider</dt>
          <dd>{p.reputation_provider === "mock" ? "Mock fixture (test data only)" : p.reputation_provider === "none"
            ? "None configured" : p.reputation_provider}</dd>
        </dl>
      </section>
    </>
  );
}
