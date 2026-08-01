import { test, expect } from "../fixtures/test.js";

// Covers: NO USER STORY EXISTS.
// feature-user-stories.csv has no accessibility stories — only US-216 and US-220 mention it,
// incidentally, about single controls. The a11y suite is gated by scripts/a11y-ledger.json
// instead. Mapping these to feature ids would misrepresent both.
//

// Covers the skip link and the section-region naming from Task 10. All of it is behavior a static
// axe scan reports as "passing" whether or not it actually works: axe sees that a link exists, not
// that activating it moves focus.

test("the skip link is the first thing in the tab order and moves focus to main", async ({ page }) => {
  await page.goto("/dashboard");

  await page.keyboard.press("Tab");
  await expect(page.locator(".skip-link")).toBeFocused();

  await page.keyboard.press("Enter");
  // Focus must MOVE, not merely scroll. Without tabindex="-1" on <main> the browser scrolls and
  // leaves focus in the header, dropping the user back into the toolbar they just skipped.
  await expect(page.locator("#main")).toBeFocused();
});

test("the skip link is invisible until focused", async ({ page }) => {
  await page.goto("/dashboard");
  await expect(page.locator(".skip-link")).not.toBeInViewport();
  await page.keyboard.press("Tab");
  await expect(page.locator(".skip-link")).toBeInViewport();
});

test("the document exposes banner, main and contentinfo landmarks", async ({ page }) => {
  await page.goto("/dashboard");
  // Native <header>/<main>/<footer> carry these implicitly, so no redundant role attributes.
  for (const role of ["banner", "main", "contentinfo"]) {
    await expect(page.getByRole(role as "banner" | "main" | "contentinfo")).toHaveCount(1);
  }
});

test("sections are exposed as named regions", async ({ page, demoCase }) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

  const named = await page.evaluate(
    () => [...document.querySelectorAll("main section")].filter((s) => s.hasAttribute("aria-label")).length,
  );
  // An unnamed <section> is not a landmark at all, so this is the difference between a usable
  // region rotor and an empty one.
  expect(named).toBeGreaterThan(20);
});

test("a region name is the heading text alone, not its inline controls", async ({ page }) => {
  await page.goto("/dashboard");
  const label = await page.locator("#sec-timeline").evaluate((el) => el.getAttribute("aria-label"));
  // The Forensic Timeline <h2> also contains the severity filters, source/origin/host pickers and
  // the corroboration select. aria-labelledby would drag all of that into the name.
  expect(label).toBe("Forensic Timeline");
});
