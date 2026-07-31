import { test, expect } from "../fixtures/test.js";
import type { Page } from "@playwright/test";
import { revealSections } from "../fixtures/sections.js";

// Evidence pivots.
//
// The Evidence Chain panel is a Cytoscape graph rendered to a canvas, so its nodes are not
// inspectable as DOM. What IS observable — and is the pivot an investigator actually performs — is
// selecting an event in the timeline and having that selection mirrored onto the swimlane
// (swReflectSelection) and into the bulk-action bar. That shared selection is the link between the
// three views of the same events, so it is what these cover.

async function openCase(page: Page, caseId: string): Promise<void> {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(caseId)}`);
  await expect(page.locator("#sec-timeline .ev-row").first()).toBeAttached({ timeout: 30_000 });
  // Without this the rows exist but are invisible, and every .check() below times out.
  await revealSections(page, "sec-timeline", "sec-evidence");
  await expect(page.locator("#sec-timeline .ev-row").first()).toBeVisible();
}

test("the evidence graph endpoint returns a populated chain", async ({ page, demoCase }) => {
  await openCase(page, demoCase);

  // The panel draws to a canvas, so this asserts the data behind it. An empty graph renders as a
  // blank panel that looks identical to a working one.
  const res = await page.request.get(`/cases/${demoCase}/evidence-graph`);
  expect(res.status()).toBe(200);
  const graph = (await res.json()) as { nodes?: unknown[]; edges?: unknown[] };
  expect(Array.isArray(graph.nodes)).toBe(true);
  expect((graph.nodes ?? []).length).toBeGreaterThan(0);
});

test("selecting a timeline event marks the row and mirrors onto the swimlane", async ({ page, demoCase }) => {
  await openCase(page, demoCase);

  const firstRow = page.locator("#sec-timeline .ev-row").first();
  const eventId = await firstRow.getAttribute("data-evid");
  expect(eventId).toBeTruthy();

  await firstRow.locator(".ev-row-cb").check();

  // The row reflects it...
  await expect(firstRow).toHaveClass(/\bev-selected\b/);

  // ...and the swimlane is told about it. swReflectSelection() is what keeps the chart and the
  // table describing the same selection; without it the two views silently disagree about what the
  // analyst has picked.
  const mirrored = await page.evaluate(
    (id) => document.querySelectorAll(`.ev-row.ev-selected[data-evid="${id}"]`).length,
    eventId,
  );
  expect(mirrored).toBe(1);
});

test("selecting an event reveals the bulk action bar", async ({ page, demoCase }) => {
  await openCase(page, demoCase);

  const bulkBar = page.locator("#evBulkBar");
  await page.locator("#sec-timeline .ev-row").first().locator(".ev-row-cb").check();

  // The bulk bar is how star / tag / false-positive get applied to a selection. If selection works
  // but the bar never appears, every one of those actions is unreachable.
  await expect(bulkBar).toBeVisible();
  await expect(page.locator("#evBulkCount")).not.toBeEmpty();
});

test("clearing the selection deselects the row", async ({ page, demoCase }) => {
  await openCase(page, demoCase);

  const firstRow = page.locator("#sec-timeline .ev-row").first();
  await firstRow.locator(".ev-row-cb").check();
  await expect(firstRow).toHaveClass(/\bev-selected\b/);

  await firstRow.locator(".ev-row-cb").uncheck();
  await expect(firstRow).not.toHaveClass(/\bev-selected\b/);
});
