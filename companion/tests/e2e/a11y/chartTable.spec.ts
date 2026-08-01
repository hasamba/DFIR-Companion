import { test, expect } from "../fixtures/test.js";
import type { Page } from "@playwright/test";
import { revealSections } from "../fixtures/sections.js";

// Covers: NO USER STORY EXISTS.
// feature-user-stories.csv has no accessibility stories — only US-216 and US-220 mention it,
// incidentally, about single controls. The a11y suite is gated by scripts/a11y-ledger.json
// instead. Mapping these to feature ids would misrepresent both.
//

// The swimlane is a <canvas>: its content is not in the accessibility tree at all, so axe reports
// the section as clean while the entire visual timeline is missing for a screen-reader user. Only
// a real browser can confirm the table equivalent is actually built and populated.

/**
 * The swimlane fetches its lanes after page load and the table is rebuilt from that data, so the
 * rows appear a few seconds in. Assert on a locator first — those auto-wait — before any count()
 * or allTextContents(), which take an immediate snapshot and would read an empty table.
 */
async function openCaseWithSwimlane(page: Page, caseId: string): Promise<void> {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(caseId)}`);
  await expect(page.locator("#swimlaneTableAlt tbody tr").first()).toBeAttached({ timeout: 30_000 });
}

/**
 * Force the swimlane section visible so its table can be asserted as keyboard reachable.
 *
 * #sec-swimlane is display:none under the default dashboard view, so nothing inside it can hold
 * focus.
 */
async function revealSwimlane(page: Page): Promise<void> {
  // Shares the fixture rather than repeating its stylesheet trick: this file had its own copy, and
  // when the nonce-based CSP landed it needed the identical fix in two places.
  //
  // This forces the section visible only so keyboard reachability of the table can be asserted at
  // all. That the section is hidden by default is correct — a hidden chart should have a hidden
  // alternative — and is not what this test is about.
  await revealSections(page, "sec-swimlane");
}

/**
 * Wait until the table has stopped being rebuilt.
 *
 * Swimlane data arrives progressively, and each arrival redraws the canvas and regenerates the
 * table — which replaces the <summary> element. Focusing before that settles means the element
 * holding focus is torn out from under the assertion. describe-as-table.js records the rendered
 * data in data-table-signature precisely so "has it changed?" is observable; poll it for a run of
 * identical readings rather than guessing at a sleep.
 */
async function waitForStableTable(page: Page): Promise<void> {
  const read = () =>
    page.locator("#swimlaneTableAlt").evaluate((el) => (el as HTMLElement).dataset.tableSignature ?? "");

  // THREE consecutive identical readings, not two. Swimlane data arrives progressively, so under a
  // loaded server a pause mid-arrival looks identical to "finished" — two matching samples were
  // enough to pass, and then the table rebuilt immediately after focus() and destroyed the element
  // the assertion was about. This failed only in the full suite and never in isolation.
  let previous = "";
  let streak = 0;
  await expect
    .poll(
      async () => {
        const current = await read();
        streak = current !== "" && current === previous ? streak + 1 : 0;
        previous = current;
        return streak;
      },
      { timeout: 30_000, intervals: [400] },
    )
    .toBeGreaterThanOrEqual(2);
}

test("the swimlane canvas has a populated table equivalent", async ({ page, demoCase }) => {
  await openCaseWithSwimlane(page, demoCase);
  const alt = page.locator("#swimlaneTableAlt");

  // An empty <table> would satisfy "an alternative exists" while conveying nothing.
  expect(await alt.locator("tbody tr").count()).toBeGreaterThan(0);

  await expect(alt.locator("thead th")).toHaveText(["lane", "timestamp", "severity", "description"]);
  await expect(alt.locator("caption")).toContainText("chronological");
});

test("the table is reachable by keyboard and announces its size", async ({ page, demoCase }) => {
  await openCaseWithSwimlane(page, demoCase);
  await revealSwimlane(page);
  await waitForStableTable(page);

  const summary = page.locator("#swimlaneTableAlt summary");
  await expect(summary).toContainText(/View as table \(\d+ events\)/);

  // <summary> is focusable and Enter-activatable natively; this confirms the table is genuinely
  // reachable rather than hidden behind a mouse-only affordance.
  await expect
    .poll(
      async () => {
        await summary.focus().catch(() => {});
        return summary.evaluate((el) => el === document.activeElement).catch(() => false);
      },
      { timeout: 15_000, intervals: [300] },
    )
    .toBe(true);
  await page.keyboard.press("Enter");
  await expect(page.locator("#swimlaneTableAlt table")).toBeVisible();
});

test("rows are in chronological order, not lane order", async ({ page, demoCase }) => {
  await openCaseWithSwimlane(page, demoCase);

  const stamps = await page.locator("#swimlaneTableAlt tbody tr td:nth-child(2)").allTextContents();
  expect(stamps.length).toBeGreaterThan(1);

  // The canvas conveys sequence through horizontal position; a table that listed events lane by
  // lane would imply a different order of the attack.
  expect(stamps).toEqual([...stamps].sort());
});
