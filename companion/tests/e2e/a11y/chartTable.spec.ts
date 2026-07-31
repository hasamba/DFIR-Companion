import { test, expect } from "../fixtures/test.js";
import type { Page } from "@playwright/test";

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
  // Forced with a stylesheet, not by clearing the inline style. #sec-swimlane is display:none under
  // the default dashboard view, and the view system REAPPLIES that inline style on every render —
  // so `sec.style.display = ""` is undone before an assertion can run. A rule carrying !important
  // outranks the inline style the app keeps setting.
  //
  // This forces the section visible only so keyboard reachability of the table can be asserted at
  // all. That the section is hidden by default is correct — a hidden chart should have a hidden
  // alternative — and is not what this test is about.
  await page.addStyleTag({
    content:
      "#sec-swimlane { display: block !important; } #sec-swimlane.collapsed > *  { display: revert !important; }",
  });
  await page.evaluate(() => document.getElementById("sec-swimlane")?.classList.remove("collapsed"));
}

/**
 * Wait until the table has stopped being rebuilt.
 *
 * Swimlane data arrives progressively, and each arrival redraws the canvas and regenerates the
 * table — which replaces the <summary> element. Focusing before that settles means the element
 * holding focus is torn out from under the assertion. describe-as-table.js records the rendered
 * data in data-table-signature precisely so "has it changed?" is observable; poll it for two
 * identical readings rather than guessing at a sleep.
 */
async function waitForStableTable(page: Page): Promise<void> {
  const read = () =>
    page.locator("#swimlaneTableAlt").evaluate((el) => (el as HTMLElement).dataset.tableSignature ?? "");
  let previous = await read();
  await expect
    .poll(
      async () => {
        const current = await read();
        const stable = current !== "" && current === previous;
        previous = current;
        return stable;
      },
      { timeout: 30_000, intervals: [500] },
    )
    .toBe(true);
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
  await summary.focus();
  await expect(summary).toBeFocused();
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
