# Target State — Teger AI Unified Security Suite

This is the architecture the repository is moving toward. Each component carries an
honest status: **Operational** (tested and running in production), **Experimental**
(implemented and tested in this repo, not yet in production), **Planned** (designed,
contract may exist, no implementation), **Unavailable** (not designed yet).

## 1. Principles

1. **Deterministic enforcement, AI explanation.** The verdict comes from versioned,
   testable rules and intelligence lookups. An LLM may *explain* evidence; it never
   overrides a verdict.
2. **Unknown is not benign.** If a required intelligence source is unavailable, the
   verdict is `unknown`, never "safe".
3. **Mock is labelled.** Offline/mock providers are flagged in every response
   (`mock_intelligence_used: true`) and refused when `TEGER_ENV=production`.
4. **Untrusted content is data.** Web pages, emails, and documents never become
   instructions to any model or component.
5. **Minimum data.** Raw content is not logged, not persisted, and redacted before any
   cloud AI call; cloud AI requires explicit per-request consent.
6. **Static analysis by default.** The API does not fetch user-supplied URLs. Any future
   fetcher (scan-worker) must pass through `teger_security_core.netguard`.

## 2. Repository layout (monorepo)

Only directories that hold real implementation are created.

```
apps/
  web/                    Next.js security dashboard            Experimental (this milestone)
  (browser-extension)     → currently `extension/` (v0.2)        Operational (private beta)
  desktop/, android/      not created                            Planned
services/
  api/                    v1 typed security API (FastAPI)        Experimental (this milestone)
  ai-analyst/             Claude explanation adapter             Experimental, disabled by default
  (threat-engine)         → lives in packages/security-core      Experimental
  email-security/, scan-worker/, policy-engine/  not created     Planned
agents/windows/           not created                            Planned (contract only)
packages/
  contracts/              Pydantic contracts + JSON Schemas      Experimental
  security-core/          URL safety, detectors, policy, redaction  Experimental
  ui/                     not created (single web app today)     Planned
ml/evaluation/            phishing evaluation harness            Experimental
backend/                  legacy v0.2 API (OpenAI)                Operational — unchanged
dashboard/                legacy CRA console                      Operational — unchanged
dataset/                  open pattern dataset + taxonomy         Operational
```

`backend/`, `dashboard/`, and `extension/` stay in place so the production Render
deployment and the published extension are not disturbed. Migration of the extension
to the v1 API is the next milestone (see roadmap).

## 3. Request flow (v1 API)

```
client ──Bearer tgr_<key_id>_<secret>──▶ services/api
   │  request-id, size limit, security headers
   │  API-key auth → Principal{tenant, scopes}
   │  rate limit (key + client IP)
   ▼
packages/security-core
   normalize_url()  ── reject non-http(s), control chars, oversize
   detectors:  url_heuristics · brand_impersonation · credential_harvesting
               · social_engineering · reputation(provider)
   policy.decide() ── verdict, score, confidence, recommended_action, policy_version
   ▼
services/ai-analyst (optional; consent + tenant allow-list + API key required)
   redact() → nonce-delimited untrusted block → Claude structured output
   → grounding check (evidence IDs must exist) → explanation only
   ▼
tenant-scoped store  →  audit log (no content)  →  response
```

## 4. Module status matrix

| Product | Status | What exists |
|---|---|---|
| Teger Shield (browser) | Operational (beta) for Gmail/Slack message scans via `extension/` | URL protection / blocking: Planned (next milestone) |
| Teger Intelligence (Claude analyst) | Experimental, off by default | `services/ai-analyst` with mocked tests; no production key configured |
| Teger Mail | Experimental | Message-text analysis via v1 API; no mailbox integration, no SPF/DKIM/DMARC checks |
| Teger Guard (Windows) | Planned | Event / scan / quarantine contracts only |
| Teger Mobile (Android) | Planned | Event contract only |
| Teger Enterprise | Planned | Tenant-scoped API keys exist; policy-distribution contract only |

## 5. Data stores (target)

| Data | Today | Target |
|---|---|---|
| API keys | env/file, SHA-256 hashed | database + KMS-backed pepper, rotation API |
| Analyses | in-memory, per-tenant, bounded | PostgreSQL with row-level tenant isolation, retention policy |
| Rate-limit windows | in-memory | Redis |
| Audit log | JSON to stdout | append-only sink (e.g. SIEM) |

## 6. AI provider policy — decided: bring your own key

The owner decided that users can bring their own Anthropic key (BYOK).
`CONTRIBUTING.md` was updated accordingly:

- the legacy production path (`backend/`, OpenAI) is unchanged;
- Claude explanations run on the **user's** Anthropic key, sent per request as
  `X-Anthropic-Api-Key` (the console keeps it in an encrypted HttpOnly cookie). Teger
  never stores or logs it, and BYOK usage is billed to the user's Anthropic account;
- per-request consent (`cloud_ai_consent`) is still required; operators can turn BYOK
  off with `TEGER_AI_ALLOW_BYOK=false`;
- a Teger-owned key path still exists but stays disabled unless `TEGER_AI_ENABLED=true`,
  `ANTHROPIC_API_KEY` is set, and the API key has `cloud_ai_allowed`.
