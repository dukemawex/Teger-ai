# Deployment Guide

> **Status:** nothing in this milestone has been deployed. Production today is the
> legacy v0.2 stack (`backend/` on Render, `extension/` private beta), which this
> change does not modify. Deploying the v1 API or the new console requires explicit
> owner approval.

## 1. Local development

Prerequisites: Python 3.11+, Node 20+.

```bash
make install            # editable install of contracts, security-core, ai-analyst, api + legacy deps
make test lint eval     # 244 Python tests, flake8 + schema check, evaluation harness

# Generate a development key (prints a token once, plus a record to configure)
python -m teger_api.keys --tenant dev --cloud-ai-allowed
export TEGER_API_KEYS='[<record JSON>]'
make api                # v1 API on :8100 with the MOCK reputation provider

cd apps/web && cp .env.example .env.local && npm ci && npm run dev   # console on :3100
```

OpenAPI docs: <http://127.0.0.1:8100/docs> (disabled by default when `TEGER_ENV=production`).

## 2. v1 API — production checklist (when approved)

Run with `uvicorn teger_api.main:app --host 0.0.0.0 --port $PORT --workers 1`.

| Setting | Production value |
|---|---|
| `TEGER_ENV` | `production` (refuses the mock provider, hides docs, adds HSTS) |
| `TEGER_API_KEYS_FILE` | path to a secret-mounted JSON file of key records |
| `TEGER_REPUTATION_PROVIDER` | `none` until a live provider is integrated |
| `TEGER_TRUST_PROXY_HEADERS` | `true` **only** behind a proxy that overwrites `X-Forwarded-For` |
| `TEGER_CORS_ORIGINS` | empty (the console calls the API server-side) |
| `TEGER_AI_ENABLED` / `ANTHROPIC_API_KEY` | leave disabled until the AI-provider policy is decided |

Constraints until the P0 backlog items land: run **one** worker/instance (in-memory
state), expect history loss on restart, and keep the API behind TLS.

Health checks: liveness `GET /healthz`; readiness `GET /readyz` (503 without keys).

## 3. Console (`apps/web`) — production checklist (when approved)

```bash
cd apps/web && npm ci && npm run build && npm start   # port 3100
```

| Variable | Value |
|---|---|
| `TEGER_API_URL` | internal URL of the v1 API |
| `TEGER_DASHBOARD_SECRET` | 32+ random characters from a secrets manager (startup fails without it) |

Serve over HTTPS only (the session cookie is `Secure` in production).

## 4. Legacy stack (unchanged)

See the README sections for `backend/`, `dashboard/`, and `extension/`. The Render
blueprint remains `backend/render.yaml`.

## 5. Things that must not happen without approval

- Changing DNS for `tegerai.tech` or the Render service.
- Pointing the published extension at the v1 API.
- Enabling cloud AI explanations in any shared environment.
