import { test, expect } from "../fixtures/test.js";
import type { Page } from "@playwright/test";
import { revealSections } from "../fixtures/sections.js";

// Covers: US-361
// (feature-user-stories.csv) — the Sigma rule → Velociraptor hunt card in the hunt modal (#798).
// The harness has no Velociraptor API, which is the point: Compile is offline, so the analyst
// reviews the VQL before the API is ever configured, and the Run button stays away until it is.

const RULE = [
  "title: Certutil download",
  "level: high",
  "tags:",
  "  - attack.t1105",
  "logsource:",
  "  category: process_creation",
  "  product: windows",
  "detection:",
  "  sel:",
  "    Image|endswith: '\\certutil.exe'",
  "    CommandLine|contains: 'urlcache'",
  "  condition: sel",
].join("\n");

/** Reach the hunt modal the way an analyst does: the quick-action tray on a detected value. */
async function openHuntModal(page: Page, caseId: string): Promise<void> {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(caseId)}`);
  await page.waitForLoadState("networkidle");
  await revealSections(page, "sec-timeline");
  await expect(page.locator("#sec-timeline .ev-row").first()).toBeVisible({ timeout: 30_000 });
  await page.locator("#forensicTimeline .qa-val").first().click();
  await page.locator('.qa-tray [data-qa="hunt"]').click();
  await expect(page.locator("#huntOverlay")).toHaveClass(/\bopen\b/);
}

test("US-361: a pasted Sigma rule compiles to VQL with its coverage line, and Run waits for the API", async ({
  page,
  demoCase,
}) => {
  await openHuntModal(page, demoCase);

  const box = page.locator("#sigmaYamlIn");
  await expect(box, "the Sigma card must sit in the hunt modal when Velociraptor is an enabled platform").toBeVisible();
  await box.fill(RULE);
  await page.locator("#sigmaCompileBtn").click();

  const res = page.locator("#sigmaCompileRes");
  await expect(res).toContainText("running processes only, not process history");
  await expect(res).toContainText("Certutil download");
  const vql = page.locator("#sigmaVqlOut");
  await expect(vql).toBeVisible();
  const text = await vql.inputValue();
  expect(text, "the VQL must run on the endpoint's process list").toContain("FROM pslist()");
  expect(text, "the analyst's value must be in the WHERE clause").toMatch(/certutil/);
  expect(text, "the launcher splits on blank lines, so there must be none").not.toMatch(/\n\s*\n/);

  // No Velociraptor API in this harness: the Run button must not appear, and the card must say why.
  await expect(page.locator("#sigmaRunBtn")).toHaveCount(0);
  await expect(res).toContainText(/not configured/i);
});

test("US-361: a rule the Companion cannot express is refused line by line, and nothing is offered to run", async ({
  page,
  demoCase,
}) => {
  await openHuntModal(page, demoCase);

  await page.locator("#sigmaYamlIn").fill(RULE.replace("process_creation", "image_load"));
  await page.locator("#sigmaCompileBtn").click();

  const refusals = page.locator("#sigmaCompileRes .sigma-refusals li");
  await expect(refusals).toHaveCount(1);
  await expect(refusals.first()).toContainText("logsource.category");
  await expect(refusals.first()).toContainText("image_load");
  await expect(page.locator("#sigmaVqlOut")).toHaveCount(0);
  await expect(page.locator("#sigmaRunBtn")).toHaveCount(0);

  await page.locator("#huntClose").click();
  await expect(page.locator("#huntOverlay")).not.toHaveClass(/\bopen\b/);
});
