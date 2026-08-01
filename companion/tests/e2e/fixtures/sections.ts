import type { Page } from "@playwright/test";

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
 * @param page  the page under test
 * @param ids   section ids, e.g. "sec-timeline"
 */
export async function revealSections(page: Page, ...ids: string[]): Promise<void> {
  await page.evaluate((sectionIds) => {
    const selector = sectionIds.map((id) => `#${id}`).join(", ");
    const collapsed = sectionIds.map((id) => `#${id}.collapsed > *`).join(", ");
    const sheet = new CSSStyleSheet();
    sheet.replaceSync(
      `${selector} { display: block !important; } ${collapsed} { display: revert !important; }`,
    );
    document.adoptedStyleSheets = [...document.adoptedStyleSheets, sheet];
    for (const id of sectionIds) document.getElementById(id)?.classList.remove("collapsed");
  }, ids);
}
