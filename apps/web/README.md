# Teger AI public website and security console (apps/web)

Next.js 15 public website and investigation desk, plus the experimental private
console for the v1 API (`services/api`). The separately hosted marketing site and
legacy CRA console are not changed by a repository commit. See
[public launch guide](../../docs/public-launch.md) for deployment and cut-over.

## Public scanner

Run the API with `TEGER_PUBLIC_SCAN_ENABLED=true TEGER_REPUTATION_PROVIDER=none`.
Set `TEGER_API_URL` in the web app, then visit `/scan`. No account or AI key is needed.
The scanner calls the real Python engine through a same-origin, size-limited server
route; it never substitutes synthetic results when the backend is unavailable.
Public analyses are not saved to private tenant history and cannot use cloud AI.

Public routes: `/`, `/scan`, `/method`, `/privacy`. The private console now starts at
`/overview`; its existing `/analyze`, `/incidents`, and other routes remain protected.

## Run locally

```bash
# terminal 1 — API with the MOCK reputation provider (dev only)
python -m teger_api.keys --tenant acme --cloud-ai-allowed > /tmp/key.txt   # keep the token line
export TEGER_API_KEYS='[<record JSON from /tmp/key.txt>]'
make api                                        # http://127.0.0.1:8100

# terminal 2 — dashboard
cd apps/web && cp .env.example .env.local && npm ci && npm run dev   # http://localhost:3100
```

Open `/connect`, paste the `tgr_…` token, and continue to `/overview`.

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

End-to-end smoke test (requires platform dependencies in the root `.venv`):

```bash
npx playwright install chromium
npm run build
npm run test:e2e
```

The smoke test starts its own production web server and real Python API on ports
3199/8199, verifies actual scans, report download, input rendering, protected routes,
legacy redirects, 320/390px layouts, CSP and backend outages, then stops both servers.
Set `TEGER_TEST_BROWSER` to use an existing Chromium executable, or
`TEGER_TEST_ARTIFACTS` to save screenshots. `TEGER_TEST_PYTHON` overrides the Python path.

`postcss` is pinned via `overrides` to a patched 8.5.x because Next 15.5 bundles an
older version with published advisories.

## Known limitations

No user accounts or SSO (API-key session only); private history depends on the API's
in-memory store. The public smoke test is available locally; it is not yet a CI job.
