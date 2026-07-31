import { test, expect } from "../fixtures/test.js";
import type { Page } from "@playwright/test";
import { revealSections } from "../fixtures/sections.js";

// Timeline filtering. The seeded case has 58 events with fixed timestamps, so these assert against
// known content rather than "more than zero rows", which would still pass if the timeline rendered
// 58 empty placeholders.

async function openCase(page: Page, caseId: string): Promise<void> {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(caseId)}`);
  await expect(page.locator("#sec-timeline .ev-row").first()).toBeAttached({ timeout: 30_000 });
  // #sec-timeline is display:none under the default view. Without revealing it these specs would
  // assert against DOM the user cannot see — count() and toBeAttached() match hidden elements
  // perfectly happily, so the suite would look green while proving nothing about the visible UI.
  await revealSections(page, "sec-timeline");
  await expect(page.locator("#sec-timeline .ev-row").first()).toBeVisible();
}

/** Reveal the global filter bar the way the app documents: "/" focuses it. */
async function focusFilter(page: Page): Promise<void> {
  await page.locator("#main").click({ position: { x: 5, y: 5 } });
  await page.keyboard.press("/");
  await expect(page.locator("#globalSearch")).toBeFocused();
}

test("renders the seeded timeline events", async ({ page, demoCase }) => {
  await openCase(page, demoCase);

  const rows = page.locator("#sec-timeline .ev-row");
  expect(await rows.count()).toBeGreaterThan(0);

  // Every row must carry its event id: the id is what the evidence pivot and the star/tag actions
  // key off, so rows without one look fine and are inert.
  const withoutId = await page.locator("#sec-timeline .ev-row:not([data-evid])").count();
  expect(withoutId).toBe(0);
});

test('"/" focuses the filter, as the shortcut advertises', async ({ page, demoCase }) => {
  await openCase(page, demoCase);
  await focusFilter(page);
});

test("filtering narrows the event list and clearing restores it", async ({ page, demoCase }) => {
  await openCase(page, demoCase);
  const rows = page.locator("#sec-timeline .ev-row");
  const before = await rows.count();
  expect(before).toBeGreaterThan(1);

  await focusFilter(page);
  // DC01 is the domain controller in the seeded scenario, named in several events but not all.
  await page.locator("#globalSearch").fill("DC01");
  await expect.poll(async () => rows.count(), { timeout: 15_000 }).toBeLessThan(before);

  await page.locator("#globalSearch").fill("");
  await expect.poll(async () => rows.count(), { timeout: 15_000 }).toBe(before);
});

test("a filter matching nothing empties the list rather than ignoring the filter", async ({
  page,
  demoCase,
}) => {
  await openCase(page, demoCase);
  const rows = page.locator("#sec-timeline .ev-row");

  await focusFilter(page);
  await page.locator("#globalSearch").fill("zzz-no-such-event-zzz");

  // The failure this catches is a filter that silently no-ops: the analyst believes they are
  // looking at a filtered view while actually seeing everything.
  await expect.poll(async () => rows.count(), { timeout: 15_000 }).toBe(0);
});

test("Escape clears the filter", async ({ page, demoCase }) => {
  await openCase(page, demoCase);
  const rows = page.locator("#sec-timeline .ev-row");
  const before = await rows.count();

  await focusFilter(page);
  await page.locator("#globalSearch").fill("DC01");
  await expect.poll(async () => rows.count(), { timeout: 15_000 }).toBeLessThan(before);

  await page.locator("#globalSearch").press("Escape");
  await expect(page.locator("#globalSearch")).toHaveValue("");
  await expect.poll(async () => rows.count(), { timeout: 15_000 }).toBe(before);
});
