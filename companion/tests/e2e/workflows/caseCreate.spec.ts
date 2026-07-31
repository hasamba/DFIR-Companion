import { test, expect } from "../fixtures/test.js";
import type { Page } from "@playwright/test";

// Covers: US-002
// (feature-user-stories.csv) — POST /cases through the real dialog, including the id-validation and duplicate refusals.
//

// The ONE spec that creates its case by clicking. Every other spec seeds through the API, so
// without this a broken create-case dialog would ship green.
//
// Deliberately does not use the demoCase fixture: the point is to exercise the path the fixture
// bypasses.

/**
 * Open the dashboard and wait until it can actually respond to a click.
 *
 * #newCaseBtn's handler is bound by an inline script that runs after the page's startup fetches
 * (/cases, /disk-stats). Under a loaded server the button paints before its handler exists, so a
 * click lands on nothing and the dialog never opens — this failed only when the full suite ran four
 * workers against one server, and passed every time in isolation. Waiting for the network to settle
 * fixes the cause; a longer assertion timeout would only have hidden it.
 */
async function openDashboard(page: Page): Promise<void> {
  await page.goto("/dashboard");
  await page.waitForLoadState("networkidle");
  await expect(page.locator("#newCaseBtn")).toBeEnabled();
}

/** Unique per test run; POST /cases rejects ids outside [A-Za-z0-9._-]. */
function freshCaseId(prefix: string, testId: string): string {
  return `${prefix}-${testId.replace(/[^\w.-]/g, "").slice(0, 10)}`;
}

test("creates a case through the dialog and connects to it", async ({ page }, testInfo) => {
  const caseId = freshCaseId("e2e-ui", testInfo.testId);
  await openDashboard(page);

  await page.locator("#newCaseBtn").click();
  const dialog = page.locator("#newCaseOverlay");
  await expect(dialog).toHaveClass(/\bopen\b/);
  // The dialog semantics from PR 2 must hold on the real user path, not only when a test forces
  // the overlay open.
  await expect(dialog).toHaveAttribute("role", "dialog");
  await expect(dialog).toHaveAttribute("aria-modal", "true");

  await dialog.locator("#ncCaseId").fill(caseId);
  await dialog.locator("#ncName").fill("E2E created case");
  await dialog.locator("#ncInvestigator").fill("e2e");
  await dialog.locator("#ncCreate").click();

  await expect(dialog).not.toHaveClass(/\bopen\b/);
  // The case id lives in an input value, not in body text.
  await expect(page.locator("#caseId")).toHaveValue(caseId);

  // Confirm it actually persisted rather than the UI optimistically rendering it.
  const listed = await page.request.get("/cases");
  expect(listed.status()).toBe(200);
  expect(await listed.text()).toContain(caseId);
});

test("refuses a case id containing path traversal", async ({ page }) => {
  await openDashboard(page);
  await page.locator("#newCaseBtn").click();
  const dialog = page.locator("#newCaseOverlay");

  await dialog.locator("#ncCaseId").fill("../escape");
  await dialog.locator("#ncName").fill("bad");
  await dialog.locator("#ncCreate").click();

  // POST /cases answers 400 for this. The dialog must stay open and say why — silently doing
  // nothing would read as a dead button, and this is the validation that keeps a case id from
  // escaping the cases root.
  await expect(dialog).toHaveClass(/\bopen\b/);
  await expect(dialog.locator("#ncMsg")).not.toBeEmpty();
});

test("refuses a duplicate case id", async ({ page, demoCase }) => {
  await openDashboard(page);
  await page.locator("#newCaseBtn").click();
  const dialog = page.locator("#newCaseOverlay");

  await dialog.locator("#ncCaseId").fill(demoCase);
  await dialog.locator("#ncName").fill("duplicate");
  await dialog.locator("#ncCreate").click();

  // POST /cases answers 409. Overwriting an existing case is the outcome that must never happen
  // silently — it would destroy evidence.
  await expect(dialog).toHaveClass(/\bopen\b/);
  await expect(dialog.locator("#ncMsg")).not.toBeEmpty();
});

test("Cancel closes the dialog and restores focus to the button that opened it", async ({ page }) => {
  await openDashboard(page);
  const opener = page.locator("#newCaseBtn");
  await opener.focus();
  await opener.press("Enter");

  const dialog = page.locator("#newCaseOverlay");
  await expect(dialog).toHaveClass(/\bopen\b/);

  await dialog.locator("#ncCancel").click();
  await expect(dialog).not.toHaveClass(/\bopen\b/);
  await expect(opener).toBeFocused();
});
