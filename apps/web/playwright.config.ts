import { defineConfig, devices } from "@playwright/test";

// Browser tests for the public site and the fixture demo. They start an in-memory API with
// the demo enabled (fast pacing) and a production build of the web app; nothing contacts
// the internet. Run: npm run build && npm run e2e
const API_PORT = 8199;
const WEB_PORT = 3199;
const executablePath = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;

export default defineConfig({
  testDir: "./e2e",
  timeout: 60_000,
  fullyParallel: false,
  workers: 1,
  reporter: [["list"]],
  use: { baseURL: `http://127.0.0.1:${WEB_PORT}`, trace: "retain-on-failure", launchOptions: { executablePath } },
  projects: [
    { name: "desktop", use: { ...devices["Desktop Chrome"], viewport: { width: 1280, height: 900 } }, grepInvert: /@mobile/ },
    { name: "mobile", use: { ...devices["Pixel 7"], viewport: { width: 390, height: 844 } }, grep: /@mobile/ },
  ],
  webServer: [
    {
      command: `python3 -m uvicorn teger_api.main:app --port ${API_PORT}`,
      cwd: "../..",
      env: { TEGER_ENV: "test", TEGER_DEMO_STEP_DELAY_MS: "60", TEGER_REPUTATION_PROVIDER: "none" },
      url: `http://127.0.0.1:${API_PORT}/healthz`,
      reuseExistingServer: false,
    },
    {
      command: `npx next start -p ${WEB_PORT}`,
      env: { TEGER_API_URL: `http://127.0.0.1:${API_PORT}`, TEGER_DASHBOARD_SECRET: "e2e-only-secret-0123456789abcdef0123" },
      url: `http://127.0.0.1:${WEB_PORT}/`,
      reuseExistingServer: false,
    },
  ],
});
