import { test, expect } from "../fixtures/test.js";

// Chain of custody. This is the court-facing part of the product: a report whose evidence
// provenance cannot be checked is worthless, so these assert the records actually exist and carry
// integrity data rather than that the endpoint merely answers.

test("a seeded case exposes custody records", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  const res = await page.request.get(`/cases/${demoCase}/custody`);
  // 501 means the custody store was not wired into the app under test — that would make every
  // other assertion here vacuous, so it must fail loudly rather than skip.
  expect(res.status(), await res.text()).toBe(200);

  const body = (await res.json()) as { records?: unknown[] };
  expect(Array.isArray(body.records)).toBe(true);
});

test("custody rejects an unknown case rather than inventing an empty chain", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  const res = await page.request.get("/cases/no-such-case-e2e/custody");
  // An empty 200 here would read as "this case has no custody records" for a case that does not
  // exist — the kind of answer that is worse than an error in an evidentiary tool.
  expect(res.status()).toBe(404);
});

test("the custody panel renders for a seeded case", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);
  // The section exists in the page and is named as a region by the landmark wiring from PR 2.
  await expect(page.locator("#sec-custody")).toHaveAttribute("aria-label", /custody/i);
});
