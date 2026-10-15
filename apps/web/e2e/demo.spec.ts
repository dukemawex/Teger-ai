import { expect, test, type Page } from "@playwright/test";

async function startCase(page: Page, numeral: string) {
  await page.goto("/demo");
  await page.getByRole("button", { name: new RegExp(`Investigate case ${numeral}:`) }).click();
  await expect(page).toHaveURL(/\/demo\/cases\/case_[a-f0-9]{16}$/);
  await expect(page.locator(".meta-row")).toContainText("Status: completed", { timeout: 30_000 });
}

test("supplier impersonation: inspect, approve, execute, export, report, outcome", async ({ page }) => {
  await startCase(page, "I");
  await expect(page.locator(".findings .seal").first()).toContainText("Malicious");
  // Evidence route stage filters evidence.
  await page.getByRole("button", { name: /^Identity check:/ }).click();
  await expect(page.locator(".evidence")).toContainText("is not among Northwind Freight's approved domains");
  // Finding citations jump to evidence.
  await page.locator(".findings .evid").first().click();
  await expect(page.locator(".evidence li.highlight")).toHaveCount(1);
  // Approve and execute the blocklist proposal.
  const block = page.locator(".action", { hasText: "to the blocklist" });
  await block.getByRole("button", { name: "Approve" }).click();
  await expect(block).toContainText("Approved — not yet executed");
  await block.getByRole("button", { name: "Execute approved action" }).click();
  await expect(block).toContainText("added to the demo-only blocklist");
  await expect(block).toContainText("Approved by Demo reviewer (you)");
  // Reject another proposal.
  const warn = page.locator(".action", { hasText: "Record a warning" });
  await warn.getByRole("button", { name: "Reject" }).click();
  await expect(warn).toContainText("Rejected");
  // Export JSON.
  const download = page.waitForEvent("download");
  await page.getByRole("button", { name: "Export JSON" }).click();
  expect((await download).suggestedFilename()).toMatch(/^teger-case_[a-f0-9]{16}\.json$/);
  // Record the outcome and open the report.
  await page.getByRole("button", { name: "Record outcome" }).click();
  await expect(page.getByText(/Outcome: confirmed phishing/)).toBeVisible();
  await page.getByRole("link", { name: "Report" }).click();
  await expect(page.getByRole("heading", { level: 1 })).toContainText("Supplier impersonation");
  await expect(page.getByText("DEMO — SYNTHETIC EVIDENCE").first()).toBeVisible();
  await expect(page.locator(".report")).toContainText("Executed (decision by Demo reviewer (you))");
});

test("legitimate exception, inconclusive and prompt-injection cases", async ({ page }) => {
  await startCase(page, "II");
  await expect(page.locator(".findings .seal").first()).toContainText("No threat detected");
  await expect(page.locator(".findings")).toContainText("not a guarantee");
  await startCase(page, "III");
  await expect(page.locator(".findings .seal").first()).toContainText("Inconclusive");
  await expect(page.locator(".tools")).toContainText("Destination timed out");
  await startCase(page, "IV");
  await expect(page.locator(".evidence")).toContainText("tries to instruct an AI or security tool");
  await page.goto("/demo/context");
  await expect(page.locator("table")).not.toContainText("ostrava-docs.example");
});

test("reset clears only this visitor's demo cases", async ({ page, browser }) => {
  await startCase(page, "III");
  const other = await browser.newContext();
  const otherPage = await other.newPage();
  await startCase(otherPage, "III");
  await page.goto("/demo");
  page.once("dialog", (d) => d.accept());
  await page.getByRole("button", { name: "Reset demo" }).click();
  await expect(page.getByText("Your demo cases")).toHaveCount(0);
  await otherPage.goto("/demo");
  await expect(otherPage.getByText("Your demo cases")).toBeVisible();
  await other.close();
});

test("mobile: stacked tabs keep evidence and approvals reachable @mobile", async ({ page }) => {
  await startCase(page, "I");
  const widths = await page.evaluate(() => [document.documentElement.scrollWidth, window.innerWidth]);
  expect(widths[0]).toBeLessThanOrEqual(widths[1]);
  await page.getByRole("tab", { name: "Actions" }).click();
  await expect(page.getByRole("button", { name: "Approve" }).first()).toBeVisible();
  await page.getByRole("tab", { name: "Findings" }).click();
  await expect(page.getByText("Recommended next action")).toBeVisible();
  await page.getByRole("tab", { name: "Evidence" }).click();
  await expect(page.getByText("Submitted material")).toBeVisible();
});
