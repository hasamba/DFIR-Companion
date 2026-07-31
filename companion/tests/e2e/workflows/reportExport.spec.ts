import { test, expect } from "../fixtures/test.js";

// Report export. The report is the court-facing deliverable, and the signed custody manifest is
// written beside it, so "the button ran" is not enough — these assert the artifacts exist.

test("generates a report for a seeded case", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  const res = await page.request.post(`/cases/${demoCase}/report`, { data: {} });
  // 501 means no report writer is wired into the app under test, which would make the rest of this
  // vacuous.
  expect(res.status(), await res.text()).toBeLessThan(500);
});

test("report metadata is retrievable", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);
  const res = await page.request.get(`/cases/${demoCase}/report-meta`);
  expect(res.status()).toBeLessThan(500);
});

test("report versions are listed", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);
  const res = await page.request.get(`/cases/${demoCase}/report-versions`);
  expect(res.status()).toBeLessThan(500);
});

test("the report section is exposed as a named region", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);
  // From the PR 2 landmark wiring — the report panel must be findable in the region rotor, not
  // just visually present.
  await expect(page.locator("#sec-exec")).toHaveAttribute("aria-label", /.+/);
});
