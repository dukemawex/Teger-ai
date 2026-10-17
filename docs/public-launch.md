# Public investigation desk

## What this change delivers

- A public site at `/`, with an investigation desk at `/scan` and method/privacy pages.
- Real message and URL analysis using `packages/security-core`; no canned verdicts.
- Evidence excerpts, rule risk score, detection coverage, recommended action, report
  download and a user-controlled verification note.
- An opt-in, stateless `/v1/public/analyses` endpoint; no account or provider key.
- The existing authenticated console at `/overview` (previously `/`).

The current `www.tegerai.tech` marketing site is built separately from this repo.
Changing this repo does not by itself replace that site. On 17 October 2026 its home
page described an interactive prototype with synthetic evidence. Deploy and verify
this app before assigning the domain. Grant eligibility is not certified by code
completion; reviewers must be able to use the deployed product at the .tech address.

## Run the complete public flow locally

From the repository root (Python 3.11+ and Node 22+):

```bash
python -m venv .venv
.venv/bin/pip install -r requirements-platform.txt
TEGER_PUBLIC_SCAN_ENABLED=true TEGER_REPUTATION_PROVIDER=none \
  .venv/bin/uvicorn teger_api.main:app --host 127.0.0.1 --port 8100 --workers 1
```

In a second terminal:

```bash
cd apps/web
npm ci
TEGER_API_URL=http://127.0.0.1:8100 npm run dev
```

Open `http://localhost:3100/scan`. Enter your own text or select a fictional example,
then press Investigate. No tenant key, Anthropic key, OpenAI key, or database is
required for this public flow. The public route always uses local rules even if the
private console uses a mock reputation fixture in development.

## Deploy the API

Use a separate Python service from the legacy v0.2 backend; do not overwrite the
extension's production backend. Build from the repository root:

```bash
pip install ./packages/contracts ./packages/security-core ./services/ai-analyst ./services/api
uvicorn teger_api.main:app --host 0.0.0.0 --port "$PORT" --workers 1
```

| Setting | Value |
| --- | --- |
| `TEGER_ENV` | `production` |
| `TEGER_PUBLIC_SCAN_ENABLED` | `true` |
| `TEGER_PUBLIC_SCAN_LIMIT_PER_MINUTE` | `60` (global budget shared by all public visitors) |
| `TEGER_REPUTATION_PROVIDER` | `none` |
| `TEGER_AI_ENABLED` | `false` |
| `TEGER_CORS_ORIGINS` | empty; the web server makes the API call |
| `TEGER_TRUST_PROXY_HEADERS` | `false` unless needed by the private API behind a trusted proxy |

Use `/v1/public/status` as the public scanner's readiness check. `/readyz` still
checks readiness for the **private** API and reports 503 if no tenant keys exist.
Public scanning intentionally works without tenant keys.

The public endpoint shares a fixed 60-request/minute process budget. It does not
trust client IP headers. This is a deliberately conservative abuse limit, not a
distributed limiter. Run one worker/instance; add edge abuse protection or a shared
limiter before scaling. The existing body middleware rejects requests over 64 KiB.
The public API never fetches submitted URLs or calls paid AI services.

Do not enable body capture or request-payload logging in hosting/observability
systems. The app does not persist public submissions. Infrastructure may still log
request metadata; ensure provider retention settings match the public privacy notice.

## Deploy the website on Vercel

1. Import `dukemawex/Teger-ai` and choose `apps/web` as Root Directory, Next.js as
   framework, `npm ci` as install command, and `npm run build` as build command.
2. Set server-side `TEGER_API_URL` to the HTTPS origin of the v1 service above.
   Do not point it to the legacy v0.2 API. No `NEXT_PUBLIC_` credential is needed.
3. If enabling the private console as well, set a randomly generated
   `TEGER_DASHBOARD_SECRET` (at least 32 characters) and provision tenant keys on the
   API. Public scanning does not require this secret.
4. Test the Vercel preview against the deployed API. Missing/disabled API access must
   show an unavailable error, never a successful or synthetic verdict.
5. Once verified, attach the existing .tech domain to this project's production
   environment. Use `www.tegerai.tech` as canonical, matching the existing site and
   this app's metadata. The apex can redirect to `www.tegerai.tech`; neither should
   redirect to a `.vercel.app` primary address. Preserve existing email DNS records.
6. Keep the previous Vercel project available for rollback. Known prototype links
   `/demo`, `/demo/context`, `/features`, `/how-it-works`, `/security`, and `/tactics`
   redirect to the scanner or method page. Blog content remains outside this repo;
   migrate any existing articles before changing their live links.

## Verification before domain cut-over

- Home, scanner, method, privacy, robots and sitemap load without an API key.
- A custom credential-harvesting message produces evidence based on its actual text.
- An ordinary message is not presented as verified safe; a URL with missing live
  reputation produces an uncertain result when no other strong evidence exists.
- A sample is visibly labeled fictional and is evaluated when submitted.
- Downloaded reports contain the actual result and its limitations; suspicious URLs
  and message content are rendered as text, never executable markup or live links.
- A disconnected API produces a clear unavailable error. Confirm rate limiting,
  invalid-input handling, keyboard use, and mobile layout.
- `/overview`, `/api/analyses`, and credential settings remain protected.
- Confirm HTTPS and application behavior while the browser stays on the .tech domain.

## Product boundaries

The public workflow uses deterministic detection, not an autonomous agent or cloud
model. It cannot visit a website, verify its contents, read an inbox, validate an
organization's approved supplier list, block a site, quarantine a message, or send
an email. Those claims must not appear as shipped features. Brand coverage and URL
suffix recognition remain limited by the existing engine. See `/method` and the
existing threat model for details.
