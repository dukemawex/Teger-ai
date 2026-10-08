# Known Limitations and Implementation Backlog

## Known limitations of the platform foundation (M1)

**Not deployed.** The v1 API (`services/api`) and the new console (`apps/web`) run
locally and in CI only. Production remains the legacy `backend/` + `extension/` v0.2.

| Area | Limitation |
|---|---|
| Storage | Analyses, rate-limit windows, audit buffers and AI usage ledgers are in process memory. Restart loses them; multiple instances do not share them. |
| API keys | Configured via env/file; no create/rotate/revoke API; no expiry. SHA-256 of a 256-bit random secret (no pepper/KMS). |
| Reputation | No live provider. URL analyses without strong heuristic evidence return `unknown`. The mock provider is test data only. |
| Detection quality | Rule-based heuristics with unmeasured real-world precision/recall. Brand list has 17 brands; registrable-domain logic uses a small suffix list, not the full Public Suffix List. English-only language rules. |
| Confidence | `confidence` is a rule-agreement score, not a calibrated probability. |
| AI explanations | Disabled by default; never exercised against the live Anthropic API in this milestone. Cost figures are list-price estimates. |
| Redaction | Pattern-based, best-effort; names, addresses and free-form secrets are not detected. |
| Dashboard | No user accounts/SSO; anyone with a tenant key can use it. No automated end-to-end tests in CI. |
| Email | Text analysis only: no mailbox integration, header parsing, or SPF/DKIM/DMARC evaluation. |
| Files | Hashing and local blocklist adapter only; no signature engine integration, no endpoint. |
| Governance | `CONTRIBUTING.md` says OpenAI-only; the Claude adapter conflicts with it pending an owner decision. |
| Legacy | `SECURITY.md` supported-version table (1.x) does not match shipped 0.2. Per-IP limits in the legacy backend may see only the proxy address. |

## Backlog (prioritized)

### P0 — before any production use of the v1 API
1. Owner decision on the AI-provider policy (keep Claude adapter or remove it); check grant terms.
2. PostgreSQL storage with tenant row isolation, retention, and deletion.
3. Redis-backed rate limiting and shared AI usage budgets.
4. API key lifecycle: create/rotate/revoke endpoints, expiry, pepper held in a secrets manager.
5. Pin all GitHub Actions to commit SHAs (TruffleHog currently uses `@main`).
6. Deployment pipeline for `services/api` with staging; production only after approval.

### P1 — M2 browser protection
7. Migrate `extension/` to `/v1/analyses` behind a feature flag; keep legacy path until cut-over.
8. URL check on navigation with local TTL cache, privacy mode (no history upload), offline = `unknown`.
9. Warning interstitial with explicit, locally logged user override.
10. Minimal `declarativeNetRequest` blocklist distributed as a signed bundle.
11. Extension unit tests and a Playwright smoke test on fixture pages.

### P2 — detection quality
12. Integrate at least one live reputation provider behind `ReputationProvider`.
13. Full Public Suffix List (vendored, versioned) for registrable domains.
14. Expand the evaluation set with independently sourced, licensed data; add per-tactic metrics and CI regression thresholds on the dev split only.
15. Address the held-out miss class (reward/lottery lures requesting bank details) using dev-split examples only.
16. Non-English social-engineering rules.

### P3 — product modules
17. Teger Mail: OAuth mailbox connectors, header and SPF/DKIM/DMARC analysis, attachment hashing.
18. Dashboard: OIDC sign-in, roles, per-tenant settings, Playwright tests in CI.
19. File scanning endpoint (hash-first) with a sandboxed scan-worker using `netguard`.
20. Windows agent (user-mode telemetry only) and Android app per `packages/contracts`.
21. Enterprise policy distribution with signed, versioned bundles.
