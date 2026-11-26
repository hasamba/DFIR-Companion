import { test, expect } from "../fixtures/test.js";
import { waitForCaseRendered } from "../fixtures/sections.js";

// Covers: NO USER STORY EXISTS.
// feature-user-stories.csv has no accessibility stories — see axe.spec.ts. Gated by the a11y ledger
// and by this behavioral check.
//

// #2923: axe reported scrollable-region-focusable on the Timeline Gaps table in the Analyst view —
// a box that scrolls (max-height 260px) around a plain table, with nothing inside a keyboard can
// land on. The markup fix gives the box a tab stop and a name; axe proves the rule passes. This
// proves the thing the rule stands for: a keyboard user can reach the box and scroll it.
test("keyboard: a scrolling result table can be focused and scrolled", async ({ page, demoCase }) => {
  test.setTimeout(90_000);
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);
  await waitForCaseRendered(page, demoCase);

  // Analyst shows the Timeline Gaps panel, which the default view hides and defers (#2854).
  await page.locator("#dashViewBtn").click();
  const menu = page.locator("#dashViewMenu");
  await expect(menu).toBeVisible();
  await menu.locator('.dv-item[data-view="analyst"]').click();
  await expect(menu).toBeHidden();

  const region = page.locator("#timelineGaps .vql-result-wrap");
  await expect(region).toBeVisible({ timeout: 30_000 });
  await expect(region).toHaveAttribute("role", "region");
  await expect(region).toHaveAccessibleName("Timeline gaps");

  // The demo case's gap table is taller than the box; without that this test would prove nothing.
  const scrollable = await region.evaluate((el) => el.scrollHeight > el.clientHeight + 1);
  expect(scrollable, "the Timeline Gaps table no longer overflows its box on the demo case").toBe(true);

  // In the tab order (tabIndex 0, not -1), and focusing it from the keyboard's side lands on it.
  expect(await region.evaluate((el) => (el as HTMLElement).tabIndex)).toBe(0);
  await region.focus();
  await expect(region).toBeFocused();

  const before = await region.evaluate((el) => el.scrollTop);
  await page.keyboard.press("PageDown");
  await expect.poll(() => region.evaluate((el) => el.scrollTop)).toBeGreaterThan(before);
});
