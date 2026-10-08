# Security Test Report — Platform Foundation (M1)

Date: 2026-10-08 · Branch: `ccr-116e65d9-2ul0k0` · Environment: Linux container,
Python 3.13 (platform suites also run on 3.11 and 3.12), Node 22.

Everything below was executed in this environment. Nothing was deployed.

## 1. Automated results

| Suite | Command | Result |
|---|---|---|
| Contracts | `pytest packages/contracts` | 5 passed |
| Security core | `pytest packages/security-core` | 111 passed |
| AI analyst (mocked Anthropic) | `pytest services/ai-analyst` | 23 passed |
| v1 API | `pytest services/api` | 81 passed |
| Evaluation harness | `pytest ml/evaluation` | 11 passed |
| Legacy backend (unchanged) | `pytest backend` | 8 passed |
| Dataset (unchanged) | `pytest dataset` | 5 passed |
| Python 3.11 / 3.12 (fresh venv) | `pytest packages services ml/evaluation` | 231 passed on each |
| Web unit tests | `npm test` (apps/web) | 10 passed |
| Web typecheck / build | `npm run typecheck && npm run build` | pass |
| Lint | `flake8 packages services ml backend --max-line-length=120` | clean |
| Contract schemas | `python -m teger_contracts.export_schemas --check` | up to date |
| Python dependency audit | `pip-audit -r backend/requirements.txt`; platform deps | no known vulnerabilities |
| npm dependency audit | `npm audit --omit=dev` (apps/web) | 0 vulnerabilities (after fixes in §4) |
| Secret scan | `detect-secrets scan` over 118 changed files | 8 hits, all false positives (§4) |

Total automated tests: **254** (244 Python + 10 TypeScript).

## 2. Coverage of the required security test areas

| Area | Where | What is asserted |
|---|---|---|
| Unit tests | `packages/*/tests`, `services/ai-analyst/tests` | URL normalization, detectors, policy, redaction, hashing |
| API integration | `services/api/tests/*` | full request → verdict flow through FastAPI |
| Authentication / authorization | `test_api_auth.py` | missing/malformed/forged tokens → 401 with generic body; scope enforcement → 403; config validation; secrets stored only as SHA-256 |
| SSRF regression | `test_netguard.py`, `test_api_ssrf.py` | private, loopback, link-local/metadata, CGNAT, IPv4-mapped/NAT64/6to4 IPv6, decimal/hex/octal IPv4, internal hostnames, DNS answers to private space, mixed answers, scoped IPv6, redirects to private targets, HTTPS→HTTP downgrade, redirect limits; **API analysis runs with sockets patched to fail** |
| Tenant isolation | `test_api_tenancy.py` | other tenant's analysis → 404 identical to "not found"; list and events tenant-scoped; tenant not injectable via body; bounded store |
| Prompt injection | `test_ai_analyst.py`, `test_api_ai.py` | per-request nonce delimiters; forged closing tag defanged; evidence excerpts kept inside the untrusted block; system prompt never contains content; model output schema has no verdict; mocked model claiming "safe" does not change verdict; ungrounded evidence IDs removed |
| Redaction / data protection | `test_redaction.py`, `test_ai_analyst.py`, `test_api_audit.py` | emails, secrets, cards (Luhn), IBAN (mod-97), phones, OTPs, tokens in URLs redacted before AI calls; audit log contains no content, paths, queries or senders |
| Rate limiting / DoS | `test_api_ratelimit.py`, `test_api_errors.py` | per-key and per-IP limits with Retry-After; spoofed X-Forwarded-For ignored unless trusted; 413 for oversized bodies with and without Content-Length |
| Safe errors | `test_api_errors.py`, `test_api_analysis.py` | 500s are generic with request ID; validation errors never echo input; request-ID header injection rejected |
| Mock vs live intelligence | `test_detectors.py`, `test_api_analysis.py`, `test_api_health.py` | mock results flagged end to end; mock refused in production; no provider ⇒ `unknown`, never "safe" |
| Browser extension tests | — | **Not done.** Extension work is deferred to milestone M2 (see roadmap). |
| Dependency & secret scanning | CI `dependency-audit`, `secret-scan` | pip-audit and TruffleHog in CI |
| CI build and lint | `.github/workflows/ci.yml` | new jobs: platform-lint, platform-test (3.11/3.12), phishing-eval, dependency-audit, web-check |

## 3. Manual end-to-end verification (dashboard + API)

Run against a local API (`TEGER_REPUTATION_PROVIDER=mock`) and a production build of
`apps/web`, driven with Playwright/Chromium:

- Unauthenticated requests redirect to `/connect`; a forged key is rejected.
- Session cookie is `HttpOnly`, `SameSite=Strict`, does not contain the key in clear,
  and is not readable from `document.cookie`. A tampered cookie redirects to `/connect`.
- Cross-origin `POST /api/session`, `POST /api/analyses`, `DELETE /api/session`
  (curl with forged or missing `Origin`) → 403; same-origin → 201.
- Analysis results show redacted excerpts (`[REDACTED]@victim.test`), mock-intelligence
  warnings, and the `javascript:` URL rejection message.
- All console pages (overview, analyze, incidents + detail, events, protection, devices, policies, settings) return 200; no CSP violations in the browser console with
  the production nonce-based policy.
- Cross-tenant fetch of an analysis ID via the API → 404.

## 4. Findings during this milestone and their resolution

| # | Finding | Severity | Resolution |
|---|---|---|---|
| F1 | Evidence excerpts (copied from attacker text) were placed outside the untrusted-content delimiters in the Claude prompt | Medium | Fixed in `77a2c18`; regression test added |
| F2 | `next@15.5.26` affected by GHSA-4jqv-mc3x-m676 and GHSA-mcj8-r9mp-w47p (cache poisoning) | Moderate | Upgraded to `15.5.27` |
| F3 | Next 15.5 bundles `postcss@8.4.31` (GHSA-qx2v-qp2m-jg93, GHSA-6g55-p6wh-862q, GHSA-fxqj-rqcc-2cmp, GHSA-r28c-9q8g-f849); only our own CSS is processed, so not exploitable here | High (advisory) | `overrides` to `postcss@8.5.28`; build and UI re-verified |
| F4 | `hyphenated_host` rule fired on punycode (`xn--`) hosts | Low (false positive) | Fixed before commit |
| F5 | Chunked bodies over the limit returned 400 instead of 413 | Low | Body is now measured before parsing |
| F6 | detect-secrets hits: variable names (`apiKey`, `api_keys`), RFC test-vector hashes of `"abc"`, and deliberately fake key-shaped strings in redaction tests | Info | False positives; no real secrets in the repository |

## 5. Evaluation harness snapshot

Deterministic layer only, **no reputation provider**, 32 synthetic samples:

| split | n | TP | FP | TN | FN | unknown (mal/ben) | precision | recall | FPR |
|---|---|---|---|---|---|---|---|---|---|
| dev | 16 | 8 | 0 | 6 | 0 | 0 / 2 | 1.00 | 1.00 | 0.00 |
| test | 16 | 7 | 0 | 6 | 0 | 1 / 2 | 1.00 | 0.875 | 0.00 |

These numbers are a regression signal, **not** a measure of real-world accuracy: the
set is tiny, synthetic, and written by the same maintainers who wrote the rules. The
held-out miss (`MAL-009`, a lottery/bank-details lure) was deliberately not tuned for.
Benign URL-only samples are `unknown` because no live reputation provider exists.

## 6. Not tested / out of scope

- Live Anthropic API calls (no key in this environment; adapter verified with mocked
  responses and the real SDK over a mock HTTP transport).
- Load and performance testing; multi-instance behavior (rate limits are per process).
- The legacy `backend/` OpenAI path beyond its existing tests.
- Browser extension (M2), Windows/Android agents (planned, contracts only).
- Formal OWASP ASVS 5.0 verification. The threat model maps controls to ASVS chapters
  as a reference only; no conformance level is claimed.
