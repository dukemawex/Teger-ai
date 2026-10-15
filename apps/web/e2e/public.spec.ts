import { expect, test } from "@playwright/test";

test("landing page explains the product and the primary CTA opens the demo", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { level: 1 })).toContainText("Decide with evidence");
  await expect(page.getByText("Private beta · interactive demo")).toBeVisible();
  await expect(page.locator("footer")).toContainText("Teger AI — operated by DUKERS LTD.");
  await page.getByRole("link", { name: "Try an investigation" }).click();
  await expect(page).toHaveURL(/\/demo$/);
  await expect(page.getByText("DEMO — SYNTHETIC EVIDENCE.")).toBeVisible();
});

test("atlas plate nodes reveal recorded evidence for the selected case", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: /^Destination:/ }).click();
  await expect(page.locator(".plate-evidence")).toContainText("redirected");
  await page.getByRole("button", { name: "II. Approved service" }).click();
  await page.getByRole("button", { name: /^Decision:/ }).click();
  await expect(page.locator(".plate-evidence")).toContainText("No threat detected");
});

test("secondary CTA requires sign-in; private pages are not indexable", async ({ page, request }) => {
  await page.goto("/");
  await page.getByRole("link", { name: "Check a website" }).click();
  await expect(page).toHaveURL(/\/connect\?next=%2Fapp%2Fanalyze/);
  const robots = await (await request.get("/robots.txt")).text();
  expect(robots).toContain("Disallow: /app");
  const app = await request.get("/app/analyze", { maxRedirects: 0 });
  expect(app.headers()["x-robots-tag"]).toContain("noindex");
  const sitemap = await (await request.get("/sitemap.xml")).text();
  expect(sitemap).toContain("/demo");
});
