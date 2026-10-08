# Teger AI Security Console (apps/web) — Experimental

Next.js 15 dashboard for the v1 API (`services/api`). It replaces nothing yet: the
legacy CRA console in `dashboard/` keeps serving the v0.2 backend until cut-over.

## Run locally

```bash
# terminal 1 — API with the MOCK reputation provider (dev only)
python -m teger_api.keys --tenant acme --cloud-ai-allowed > /tmp/key.txt   # keep the token line
export TEGER_API_KEYS='[<record JSON from /tmp/key.txt>]'
make api                                        # http://127.0.0.1:8100

# terminal 2 — dashboard
cd apps/web && cp .env.example .env.local && npm ci && npm run dev   # http://localhost:3100
```

Open the console, paste the `tgr_…` token on the Connect screen.

## Security design

- The browser never sees the API key. `/api/session` validates it against `/v1/whoami`
  and stores it AES-256-GCM-encrypted (key derived from `TEGER_DASHBOARD_SECRET`) in an
  `HttpOnly; SameSite=Strict` cookie that expires after 8 hours.
- All API calls happen server-side. Mutating route handlers reject requests whose
  `Origin` does not match the host (CSRF).
- Per-request nonce Content-Security-Policy (`src/middleware.ts`), `frame-ancestors 'none'`,
  `nosniff`, `no-referrer`.
- Every number shown comes from the tenant's own analyses. Module states come from
  `/v1/capabilities` (Operational / Experimental / Planned / Unavailable). Mock
  reputation results are labelled on every verdict.

## Checks

```bash
npm run typecheck && npm test && npm run build && npm audit --omit=dev
```

`postcss` is pinned via `overrides` to a patched 8.5.x because Next 15.5 bundles an
older version with published advisories.

## Known limitations

No user accounts or SSO (API-key session only); history depends on the API's in-memory
store; no end-to-end test suite in CI yet (manual Playwright run documented in
`docs/security/test-report.md`).
