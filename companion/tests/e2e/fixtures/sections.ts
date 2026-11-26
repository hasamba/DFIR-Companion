import { expect, type Page } from "@playwright/test";

/**
 * Wait until a freshly opened, SEEDED case has connected and its forensic timeline has rendered.
 *
 * The timeline renders from the case state even while its section is hidden, so this holds in every
 * built-in view, including the default Now view where most panels are hidden and — since #2854 —
 * never load until shown. It is the readiness signal to use instead of a deferred panel's DOM.
 *
 * It is also the point after which revealSections() is safe: connecting a case clears every
 * palette reveal before it renders, so a reveal made earlier is wiped and its panel stays unloaded.
 *
 * Scope: fresh navigation to a case with events. An empty case has no row, and during a case switch
 * the new id can briefly sit beside the old case's rows.
 *
 * @param page    the page under test
 * @param caseId  the case the page was opened on
 */
export async function waitForCaseRendered(page: Page, caseId: string): Promise<void> {
  await expect(page.locator("#caseId")).toHaveValue(caseId, { timeout: 30_000 });
  await expect(page.locator("#sec-timeline .ev-row").first()).toBeAttached({ timeout: 30_000 });
}

/**
 * Force dashboard sections visible for the duration of a test.
 *
 * Most of the ~49 sections are display:none under the default dashboard view — the triage /
 * deep-dive / hunt-prep / report "views" are shortcuts that show and hide sections of one long
 * page, not separate routes. A spec that does not do this is asserting against DOM the user cannot
 * see: locator.count() and toBeAttached() both happily match hidden elements, so a suite can look
 * green while every assertion is about an invisible panel, and anything needing a real click
 * (a checkbox, a button) times out instead.
 *
 * Applied as a stylesheet with !important rather than by clearing the inline style, because the
 * view system REAPPLIES `style.display = "none"` on every render and would undo a direct
 * assignment before the assertion runs.
 *
 * Delivered as a CONSTRUCTED stylesheet, not page.addStyleTag(). The dashboard serves a
 * nonce-based CSP whose style-src has no 'unsafe-inline', so injecting a <style> element is
 * blocked — correctly, and the test harness is not a reason to weaken it. adoptedStyleSheets goes
 * through CSSOM, which CSP does not police, so the same rules apply with the policy left intact.
 *
 * The stylesheet alone no longer loads a panel (#2854): a heavy panel whose section the active view
 * hides is skipped, and loads only when the dashboard itself counts the section as shown. So each
 * section is ALSO marked revealed through markSectionRevealed() — the command palette's reveal
 * path, which repaints and runs the deferred loaders. Call this only after the case has rendered
 * (waitForCaseRendered): connecting a case clears palette reveals.
 *
 * What this does NOT prove: the stylesheet still overrides closed data gates and outlives a view
 * switch or case connect that clears the real reveal. A test of the analyst's own reveal behavior
 * must use the view menu or the palette without this helper.
 *
 * @param page  the page under test
 * @param ids   section ids, e.g. "sec-timeline"
 */
export async function revealSections(page: Page, ...ids: string[]): Promise<void> {
  await page.waitForFunction(
    () => typeof (window as { markSectionRevealed?: unknown }).markSectionRevealed === "function",
  );
  await page.evaluate((sectionIds) => {
    const selector = sectionIds.map((id) => `#${id}`).join(", ");
    const collapsed = sectionIds.map((id) => `#${id}.collapsed > *`).join(", ");
    const sheet = new CSSStyleSheet();
    sheet.replaceSync(
      `${selector} { display: block !important; } ${collapsed} { display: revert !important; }`,
    );
    document.adoptedStyleSheets = [...document.adoptedStyleSheets, sheet];
    for (const id of sectionIds) document.getElementById(id)?.classList.remove("collapsed");
    const mark = (window as { markSectionRevealed?: (id: string) => void }).markSectionRevealed;
    for (const id of sectionIds) mark?.(id);
  }, ids);
}
