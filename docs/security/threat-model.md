# Platform Threat Model (v1 API, security-core, AI analyst, web dashboard)

Scope: the components added in the platform-foundation milestone. The legacy v0.2
threat model remains in `docs/threat-model.md` and still applies to `backend/`,
`dashboard/`, and `extension/`.

Method: STRIDE per trust boundary, with requirements traced to OWASP ASVS 5.0
chapters (V-numbers refer to ASVS 5.0 chapter numbering; verify exact requirement IDs
against the published standard before using this table for compliance claims — this
project makes **no** ASVS conformance claim).

## 1. Assets

| Asset | Why it matters |
|---|---|
| Tenant API keys | Grant analysis and history access for a tenant |
| Submitted content (URLs, message text) | May contain personal data, credentials, business secrets |
| Analysis records | Reveal what a tenant is investigating |
| Verdict integrity | A wrong "no threat" verdict can lead a user to a phishing page |
| Anthropic API key / spend | Cost abuse, data egress to a third party |
| Detector rules and policy version | Integrity of enforcement |

## 2. Trust boundaries

1. Internet client → `services/api`
2. `services/api` → `services/ai-analyst` → Anthropic API (third-party cloud)
3. `services/api` → reputation provider (third-party, future)
4. Browser → `apps/web` server (Next.js route handlers) → `services/api`
5. Untrusted content → any model prompt
6. Developer machine / CI → evaluation samples

## 3. Threats and controls

| ID | Threat (STRIDE) | Control | Test | ASVS 5.0 area |
|---|---|---|---|---|
| T1 | Spoofed client / stolen key (S) | Opaque `tgr_<id>_<secret>` keys; only SHA-256 digests stored; constant-time compare; generic 401 | `test_api_auth.py` | V6 Authentication, V9 Tokens |
| T2 | Cross-tenant read of analyses (I) | Repository keyed by `(tenant_id, id)`; other-tenant IDs return 404 (no existence oracle) | `test_api_tenancy.py` | V8 Authorization |
| T3 | Privilege misuse (E) | Per-key scopes `analyses:write`, `analyses:read`; 403 on missing scope | `test_api_auth.py` | V8 |
| T4 | SSRF via submitted URL (I/E) | API performs **no** outbound fetch of submitted URLs; `netguard` denies private, loopback, link-local, metadata, CGNAT, multicast, reserved, IPv4-mapped IPv6, and legacy numeric IP forms; DNS answers re-validated; redirect hops re-validated | `test_netguard.py`, `test_api_ssrf.py` (sockets patched to fail) | V1 Encoding/Sanitization, V12 Secure Communication |
| T5 | Dangerous schemes (`javascript:`, `file:`, `data:`) (T) | `normalize_url` accepts only http/https; rejects control chars, >2048 chars | `test_urls.py` | V1, V2 Validation |
| T6 | Prompt injection in content (T/E) | Content redacted, wrapped in per-request nonce delimiters, closing-tag spoofing neutralised; system prompt frames it as data; model output is explanation-only, schema-validated, grounded to evidence IDs; verdict fixed before the model runs | `test_ai_analyst.py`, `test_api_ai.py` | V1, V2 |
| T7 | Sensitive data sent to cloud AI (I) | Explicit per-request `cloud_ai_consent`, tenant allow-list, feature flag; redaction of emails, phones, card numbers (Luhn), IBANs, JWTs, API-key shapes, password assignments, one-time codes | `test_redaction.py` | V14 Data Protection |
| T8 | Content in logs (I) | Audit events carry IDs, tenant, verdict, host — never content; validation errors stripped of submitted input | `test_api_audit.py` | V16 Logging |
| T9 | Brute force / quota exhaustion (D) | Sliding-window limits per key and per client IP; body size cap (64 KiB); field length limits; Claude timeouts, bounded retries, max tokens | `test_api_ratelimit.py` | V2, V13 Configuration |
| T10 | Mock intelligence mistaken for live (T) | `mock_intelligence_used` flag; mock provider refused at startup when `TEGER_ENV=production` | `test_api_analysis.py` | V13 |
| T11 | Unavailable intelligence treated as benign (T) | Policy yields `unknown` when a required detector is unavailable | `test_policy.py` | — |
| T12 | Error detail leakage (I) | Global handler returns generic message + request ID; provider errors never echoed | `test_api_errors.py` | V16 |
| T13 | Dashboard key theft via XSS (I) | Key held only in an `HttpOnly; SameSite=Strict` cookie set by the Next.js server; browser JS never sees it; CSP | Playwright run + curl CSRF checks (test-report §3); `session.test.ts`, `csrf.test.ts` | V3 Web Frontend |
| T14 | Evaluation leakage / live malware in samples (T) | Leakage checks across splits and against `dataset/patterns`; malicious samples must use reserved domains | `ml/evaluation` checks run in CI | — |
| T15 | Supply chain (T) | `pip-audit` in CI, TruffleHog secret scan; actions pinned to SHAs is backlog | CI | V15 Secure Coding & Architecture |

## 4. Residual risks (accepted for this milestone)

- In-memory key store, rate limiter, and analysis store: single-process only; restart
  loses history; limits not shared across replicas.
- Heuristic detectors have unmeasured real-world false-positive/negative rates. The
  evaluation set is small and synthetic.
- Registrable-domain extraction uses a small built-in suffix list, not the full Public
  Suffix List, so some brand-impersonation checks can be wrong on uncommon suffixes.
- No live reputation provider is integrated; URL verdicts without a provider are
  `unknown` unless heuristics are conclusive.
- Dashboard has no user accounts; anyone holding a tenant API key can use it.
- `TEGER_TRUST_PROXY_HEADERS=true` must only be enabled behind a proxy that overwrites
  `X-Forwarded-For`; otherwise per-IP limits can be spoofed.
