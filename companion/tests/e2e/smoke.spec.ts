import { test, expect } from "./fixtures/test.js";

// These exist to prove the harness, not the product. If they pass, the server boots against a temp
// root, the dashboard is served, the fixture seeds a case, and Playwright can drive it — which is
// everything the accessibility and workflow specs build on.

test("serves the dashboard", async ({ page }) => {
  // GET / redirects to /dashboard; Playwright follows it. Query strings do NOT survive that
  // redirect, which is why every case-bearing navigation goes straight to /dashboard.
  await page.goto("/");
  expect(page.url()).toContain("/dashboard");
  await expect(page.locator("body")).toBeVisible();
});

test("the case store is wired, not a skeleton app", async ({ request }) => {
  // createApp(store) with no options answers this route but returns "state store not configured",
  // and the dashboard then hangs forever on its loading overlay. Asserting a real 200 here is what
  // catches a server-entry.ts that has drifted back to a bare createApp.
  const res = await request.get("/cases");
  expect(res.status()).toBe(200);
});

test("a seeded case is listed", async ({ page, demoCase }) => {
  const res = await page.request.get("/cases");
  expect(res.status()).toBe(200);
  expect(await res.text()).toContain(demoCase);
});

test("the dashboard picks up the caseId query parameter", async ({ page, demoCase }) => {
  // Guards the redirect/param trap directly: if this navigation ever stops carrying the case
  // through, every downstream spec would fail confusingly instead of pointing here.
  //
  // Asserts the INPUT VALUE, not body text. dashboard.html's restore() puts the id into
  // #caseId.value, and an input's value is not part of textContent — so toContainText() on <body>
  // fails here even when the parameter was picked up perfectly.
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);
  await expect(page.locator("#caseId")).toHaveValue(demoCase);
});
