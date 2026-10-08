# Roadmap

Milestones are small and reviewable. Nothing ships to production without explicit
owner approval. Statuses follow `docs/architecture/target-state.md`.

## M1 — Platform foundation (this change)

- [x] Repository audit and architecture docs
- [x] `packages/contracts`: verdict/evidence/analysis contracts, future-module contracts + JSON Schemas
- [x] `packages/security-core`: URL normalization, SSRF/network guard, detectors, policy engine, redaction, file-hash adapters
- [x] `services/api`: v1 FastAPI with API-key auth, tenant isolation, scopes, rate limits, audit log, safe errors, OpenAPI
- [x] `services/ai-analyst`: Claude explanation adapter (consent-gated, redacted, grounded, mocked tests)
- [x] Bring-your-own Anthropic key (BYOK) across API and console
- [x] `ml/evaluation`: phishing evaluation harness with provenance + leakage checks
- [x] `apps/web`: Next.js dashboard with honest capability states
- [x] CI: lint, tests (Python 3.11/3.12), eval harness, dependency audit, web checks

Not in M1: browser-extension changes (moved to M2 so the published extension is not
disturbed in the same review), live reputation intelligence, persistent storage.

## M2 — Browser protection on v1 (next)

- Migrate `extension/` from the legacy `/analyze` to `/v1/analyses` (keep legacy until cut-over)
- URL reputation lookup with local TTL cache and privacy controls (hash-prefix or opt-in)
- Interstitial warning page + explicit user override (logged locally)
- `declarativeNetRequest` rules for a small, signed blocklist
- Offline behavior: show "unknown — offline", never "safe"
- Extension unit tests (Vitest/jsdom) + Playwright smoke test against a local fixture page

## M3 — Production hardening

- PostgreSQL storage with tenant row isolation; retention + deletion API
- Redis rate limiting; API-key management endpoints (create/rotate/revoke)
- Live reputation provider adapter(s) behind a vendor-neutral interface
- Dashboard user authentication (OIDC) replacing API-key session
- Pin all GitHub Actions to commit SHAs; SBOM generation
- Decide AI provider policy (see target-state §6)

## M4 — Teger Mail

- Gmail/Microsoft 365 integration via OAuth (read-only, user-consented)
- SPF/DKIM/DMARC result parsing from headers, display-name spoofing checks
- Attachment hashing via `packages/security-core` file adapters (no detonation on host)

## M5+ — Endpoint, mobile, enterprise

- Windows agent (`agents/windows`): event telemetry per `packages/contracts` endpoint
  contract; user-mode only; quarantine/restore requires signed policy + human approval
- Android app: URL check + notification scanning per Android event contract
- Enterprise: policy distribution, multi-admin RBAC, SIEM export

## Explicitly out of scope until reviewed separately

Kernel drivers, privileged remediation, malware detonation on developer hosts,
automatic deletion of user files or mail.
