import { test, expect } from "../fixtures/test.js";

// Covers: US-240
// US-240 covers the live-region announcements this suite asserts. The wider a11y suite is still gated by scripts/a11y-ledger.json rather than by
// story ids, because most of what it checks has no single feature to point at.
//

// Proves the #status -> aria-live bridge in public/js/a11y/announcer.js. axe cannot check this:
// it sees whether live regions EXIST, not whether anything is ever announced into them.

/** Write to the status line the way the dashboard's own code does. */
async function setStatus(page: import("@playwright/test").Page, text: string): Promise<void> {
  await page.evaluate((value) => {
    const el = document.getElementById("status");
    if (el) el.textContent = value;
  }, text);
}

test("both live regions exist and are exposed to assistive technology", async ({ page }) => {
  await page.goto("/dashboard");
  await setStatus(page, "priming the regions");

  const polite = page.locator("#a11y-live-polite");
  const assertive = page.locator("#a11y-live-assertive");
  await expect(polite).toHaveAttribute("aria-live", "polite");
  await expect(polite).toHaveAttribute("aria-atomic", "true");
  await expect(assertive).toHaveAttribute("aria-live", "assertive");
});

test("routine progress is announced politely", async ({ page }) => {
  await page.goto("/dashboard");
  await setStatus(page, "running second opinion, refreshing the primary");
  await expect(page.locator("#a11y-live-polite")).toHaveText(
    "running second opinion, refreshing the primary",
  );
});

test("a failure interrupts, in the assertive region", async ({ page }) => {
  await page.goto("/dashboard");
  await setStatus(page, "Correlation profile save failed");
  await expect(page.locator("#a11y-live-assertive")).toHaveText("Correlation profile save failed");
});

test("the live regions are visually hidden but not display:none", async ({ page }) => {
  await page.goto("/dashboard");
  await setStatus(page, "priming the regions");

  // display:none would make screen readers skip the region entirely — the exact bug the
  // .visually-hidden class exists to avoid.
  const display = await page.locator("#a11y-live-polite").evaluate((el) => getComputedStyle(el).display);
  expect(display).not.toBe("none");

  // ...and it must still be invisible to sighted users.
  await expect(page.locator("#a11y-live-polite")).not.toBeInViewport();
});
