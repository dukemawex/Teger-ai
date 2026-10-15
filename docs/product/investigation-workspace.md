# Investigation workspace (milestone M2): architecture, status and handover

> **Status:** implemented and tested locally on branch `ccr-0d8f6f38-3tmof2`. **Not deployed.**
> The public website at `tegerai.tech` is a separate v0/Vercel project that is **not in this
> repository**, so nothing here changes that site until the owner points the Vercel project at
> `apps/web` (see "Release" below).

Proposition demonstrated: *Teger investigates suspicious emails and websites in the context of
your business, explains the evidence, and helps your team respond.*

## 1. What was there before

| Surface | Before this change |
|---|---|
| `apps/web` | Experimental console behind a tenant key: one-shot URL/message analysis, module status. Not deployed. |
| `services/api` | v1 API: deterministic single-shot analysis, BYOK Claude explanations, in-memory history. |
| Public website | `tegerai.tech` — built in v0.app, hosted on Vercel, **not in this repo**. |
| `backend/` + `extension/` | Legacy v0.2 private beta (Render). Unchanged by this work except an additive popup feature. |

Baseline before editing: 264 Python tests, 13 web unit tests, flake8, schema check, typecheck and
`next build` all passed.

## 2. What was added

```
Browser ──> apps/web (Next.js)                         services/api (FastAPI, v1)
  /            public site (recorded demo plate)          /v1/demo/*   fixtures only, per-visitor namespace
  /demo        fixture demo ──/api/demo/*──────────────>  /v1/cases, /v1/actions, /v1/context, /v1/activity
  /app/*       workspace ─────/api/live/* (session key)─>      │
                                                              ▼
                                         teger_investigator (services/investigator)
                                           orchestrator ─ planner (deterministic | Claude, BYOK + consent)
                                           tools: extract_message · static_analysis · resolve_redirects ·
                                                  inspect_page · compare_context · check_reputation ·
                                                  propose_response
                                           policy.assess (deterministic verdict)
                                           approvals (tenant+case+version+params-hash bound, expiry, idempotent)
                                           SQLite store (cases, events, actions, context, blocklist, activity)
                                                              │ live fetches only
                                                              ▼
                                         fetch worker (separate process: teger_investigator.worker)
                                           IsolatedHttpFetcher: DNS-checked, IP-pinned sockets, no auto-redirects,
                                           no cookies, no scripts, no subresources, size/time/hop caps
```

**Separation of duties**

| Concern | Where | Can a model affect it? |
|---|---|---|
| Evidence collection | `tools.py` (fixture or configured live capability only) | Only which allowed tool runs next, and only among submitted URLs |
| Interpretation / planning | `planner.py` | Claude planner is optional, consent-gated, redacted, allow-listed; invalid choices are rejected and logged |
| Verdict | `policy.py` | No — deterministic rules, versioned (`investigation-2026.10.1`) |
| Execution authorization | `service.py` approvals | No — human approval bound to tenant, case, case version and exact parameters |

Verdicts: `malicious`, `suspicious`, `inconclusive`, `no_threat_detected` (never shown as a guarantee).
No numeric confidence is displayed for investigations.

## 3. Real versus demo-only

| Capability | Live (tenant key) | Demo (`/demo`) |
|---|---|---|
| Case creation from URL and/or pasted message | Yes | Fixture catalogue only (4 cases) |
| Redirect following / page reading | Only via a configured fetch worker; otherwise **reported unavailable** | Inert fixtures, no network |
| Approved business context | Read/write (`context:write` scope), approver + source recorded | Seeded fictional records, read-only |
| Reputation | `none` → reported unavailable; `mock` → labelled test fixture | Not used |
| Model-assisted planning | BYOK or server key + explicit consent | Not used (deterministic) |
| Blocklist action | Tenant Teger blocklist; **not** enforced in browsers, DNS or mail | Demo-only blocklist |
| Warning action | Recorded in Teger activity; not sent to inboxes | Demo-only |
| Verification task | Recorded with the contact from the approved record | Same, synthetic |
| Email quarantine / company-wide blocking | **Not available** (no integration) | Not available |
| Persistence | SQLite at `TEGER_DB_PATH` (required in production) | In the same store, namespaced `demo:<session>`, purged after 24 h |
| Extension "Check this page" | Opens `/app/analyze?url=…` in the reviewer's console | — |

## 4. Run it locally

Requirements: Python 3.11+, Node 20+ (CI uses 22), optional Chromium for browser tests.

```bash
make install                                   # Python packages incl. services/investigator
cd apps/web && npm ci && cd ../..

# API with the demo and durable local storage
python -m teger_api.keys --tenant harbor-quill \
  --scopes analyses:read,analyses:write,cases:read,cases:write,context:write,actions:approve
export TEGER_API_KEYS='[<record JSON printed above>]'
TEGER_ENV=development TEGER_DB_PATH=.data/teger.db make api      # :8100

# Web
cd apps/web && npm run dev                                       # :3100 → /, /demo, /connect, /app
```

Optional live inspection (separate process; run it in its own network-restricted container in
any shared environment):

```bash
export TEGER_FETCH_WORKER_TOKEN=$(python -c "import secrets;print(secrets.token_urlsafe(32))")
uvicorn teger_investigator.worker:app --port 8200
# API side:
TEGER_FETCH_WORKER_URL=http://127.0.0.1:8200 TEGER_FETCH_WORKER_TOKEN=$TEGER_FETCH_WORKER_TOKEN make api
```

Regenerate the landing-page recording after changing fixtures, tools or policy (a test fails
otherwise): `python -m teger_investigator.demo apps/web/src/demo/recorded.json`.

### New environment variables (API)

| Variable | Default | Purpose |
|---|---|---|
| `TEGER_DB_PATH` | empty = in-memory | SQLite file; **required** when `TEGER_ENV=production` |
| `TEGER_FETCH_WORKER_URL` / `TEGER_FETCH_WORKER_TOKEN` | unset | Enables live destination inspection via the worker (token ≥ 32 chars) |
| `TEGER_DEMO_ENABLED` | `true` | Public fixture demo routes |
| `TEGER_DEMO_STEP_DELAY_MS` | `700` | Demo pacing (readability only) |
| `TEGER_DEMO_IP_RATE_LIMIT_PER_MINUTE` | `600` | Per-IP limit on demo routes (the UI polls while a case runs) |
| `TEGER_INVESTIGATION_MAX_STEPS` / `_DEADLINE_SECONDS` / `_CONCURRENCY` | `10` / `60` / `4` | Orchestrator bounds |

Web: `NEXT_PUBLIC_SITE_URL` (canonical/sitemap host, default `https://www.tegerai.tech`) plus the
existing `TEGER_API_URL` and `TEGER_DASHBOARD_SECRET`.

New API key scopes: `cases:read`, `cases:write`, `context:write`, `actions:approve`. Existing keys
keep working for `/v1/analyses`.

### URL changes in the console

The console moved under `/app`; old links redirect (`/analyze`→`/app/analyses/new`,
`/incidents[/id]`→`/app/analyses[/id]`, `/events`→`/app/activity`, `/settings`→`/app/settings`,
`/protection`·`/devices`·`/policies`→`/app`). `/` is now the public landing page.

## 5. Tests (actual results on this branch)

| Suite | Command | Result |
|---|---|---|
| Python (platform + legacy + dataset) | `make test` | 315 passed (baseline 264) |
| Lint / schemas / eval checks | `make lint`, `harness.py --check-only` | pass |
| Web unit | `npm test` | 15 passed |
| Web typecheck / build | `npm run typecheck`, `npm run build` | pass |
| Browser (Playwright, desktop + 390 px mobile) | `npm run build && npm run e2e` | 7 passed |
| Extension helpers | `node --test extension/pagecheck.test.cjs` | 2 passed |

Coverage highlights: every demo verdict; message→redirect→page→context linkage; legitimate
approved-service exception vs. the same case without the record; timeout/unavailable fetchers
(never replaced by fixtures); tool choices that differ with evidence — including **two live-tool
integration tests** that run the real `IsolatedHttpFetcher` against a local HTTP server and take
different paths (page inspected vs. unreachable); Claude planner rejection of unknown tools and
non-submitted URLs; prompt injection leaving trusted context unchanged; SSRF (loopback, metadata,
private, rebinding answers, credentials, ports, encodings, HTTPS downgrade, no subresource
fetches, size cap); worker token auth; cross-tenant and scope rejection; approval version/hash
binding, replay, rejection, expiry, idempotent and single execution; demo session isolation and
scoped reset; persistence across restart (service and API).

The demo cases are synthetic and **measure product behaviour, not detection accuracy**. No
real-world accuracy figure is claimed anywhere.

## 6. Known limitations and blockers

* **Website not in repo.** Publishing the new landing page on `tegerai.tech` needs the owner to
  change the Vercel project (see §7). DNS is untouched.
* **No live model-driven run was recorded.** The Claude planner is tested with a scripted fake
  client (choices, rejections, fallback). Adaptive behaviour against live tools is proven with the
  deterministic planner. A real Claude-planned run needs an Anthropic key and consent.
* **Fetch worker isolation is application-level in this repo.** The worker must additionally run
  with network egress restricted to the public internet (no RFC1918, link-local/metadata, or
  internal service access). That network policy is deployment configuration and has not been
  tested here. No headless browser is used: pages are read as HTML only (no JavaScript, no
  screenshots).
* **Single API instance.** SQLite and the in-process executor assume one API instance; rate
  limits and cancellation are process-local. A case running during a restart is left `running`
  until cancelled (cancel handles this).
* **Reputation** is unconfigured (reported as unavailable). **Screenshot / .eml input** is not
  implemented, so the UI does not offer it.
* **Identity of approvers** is the API key, not a named user (no user accounts/SSO yet).
* The OpenAI Cybersecurity Grant mention in `README.md` predates this work; the new site does
  not repeat it because no verification record is in the repository.

## 7. Release and rollback

Nothing has been deployed. To preview, with owner approval:

1. Deploy `services/api` with `TEGER_ENV=production`, `TEGER_DB_PATH` on a **persistent volume**
   (not an ephemeral container filesystem), `TEGER_DEMO_ENABLED=true`, one instance.
2. Optionally deploy the fetch worker as a separate service with restricted egress; set the two
   `TEGER_FETCH_WORKER_*` variables on the API.
3. Create a **new** Vercel project (or a preview deployment) with root directory `apps/web`, env
   `TEGER_API_URL`, `TEGER_DASHBOARD_SECRET`, `NEXT_PUBLIC_SITE_URL`. Do not attach the
   `tegerai.tech` domain until the preview is reviewed.

Approval needed: the owner (DUKERS LTD) must approve (a) any hosting spend for the API/worker,
(b) attaching `tegerai.tech` to the new Vercel project, replacing the current v0 site.

Rollback: re-attach the domain to the previous v0 Vercel project (instant in the Vercel
dashboard); the API and worker are additive and can simply be stopped. The legacy extension and
Render backend are unaffected, so no extension rollback is needed. Database migrations are
additive (`schema_version` table); keep the SQLite file to preserve case history.
