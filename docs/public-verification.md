# Public investigation desk — verification

Verified locally on 17 October 2026 against the production Next.js build and the
actual Python detection engine. These results do not establish a production deployment.

| Check | Result |
| --- | --- |
| Python platform, security core, contracts, AI analyst and evaluation tests | 265 passed |
| Web unit tests, including public routing, input limits and gateway failures | 22 passed |
| TypeScript check | Passed |
| Production Next.js build | Passed |
| Platform flake8 and contract schema consistency | Passed |
| Browser integration smoke | Passed |

The browser run exercised public pages; real analysis of a fictional credential
attack and a separately entered message; instruction-injection detection; inert
HTML rendering; download of the actual report; uncertain results when URL reputation
is unavailable; private route protection; prototype URL redirects; 320px and 390px
layouts; backend failure handling; and production CSP/hydration checks. Desktop and
mobile screenshots were visually inspected. No horizontal overflow was found.

The browser run used Playwright 1.62.1 with an externally supplied headless Chromium
153 executable after the environment's default browser download failed. The
committed smoke script accepts `TEGER_TEST_BROWSER` for this purpose and otherwise
uses Playwright's installed Chromium.

Reproduce with the commands in `apps/web/README.md`. Public deployment requires the
opt-in API endpoint and `TEGER_API_URL`; see `docs/public-launch.md`. The separately
hosted live marketing site has not been changed by these checks.
