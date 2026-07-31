import { test, expect } from "../fixtures/test.js";

// Proves the autowire in public/js/a11y/modal-autowire.js. These are the behaviors axe cannot see:
// it inspects a static DOM snapshot, whereas focus order, focus restoration and Escape handling
// are behavior over time.

/** Open an overlay the way the app does — by toggling the class the whole dashboard uses. */
async function openOverlay(page: import("@playwright/test").Page, id: string): Promise<void> {
  await page.evaluate((overlayId) => {
    document.getElementById(overlayId)?.classList.add("open");
  }, id);
}

test("an opened overlay gains dialog semantics and an accessible name", async ({ page }) => {
  await page.goto("/dashboard");
  await openOverlay(page, "enrichOverlay");

  const overlay = page.locator("#enrichOverlay");
  await expect(overlay).toHaveAttribute("role", "dialog");
  await expect(overlay).toHaveAttribute("aria-modal", "true");

  // The name comes from the heading the dialog already displays, not from a hand-written string.
  const labelledBy = await overlay.getAttribute("aria-labelledby");
  expect(labelledBy).toBeTruthy();
  await expect(page.locator(`#${labelledBy}`)).toContainText(/enrichment/i);
});

test("Tab stays inside an open dialog", async ({ page }) => {
  await page.goto("/dashboard");
  await openOverlay(page, "enrichOverlay");

  // Tab far more times than the dialog has controls; focus must never land outside it.
  for (let i = 0; i < 20; i++) {
    await page.keyboard.press("Tab");
    const inside = await page.evaluate(() => {
      const overlay = document.getElementById("enrichOverlay");
      return !!overlay && overlay.contains(document.activeElement);
    });
    expect(inside, `focus escaped the dialog on Tab #${i + 1}`).toBe(true);
  }
});

test("Escape closes the dialog and restores focus to the invoking control", async ({ page }) => {
  await page.goto("/dashboard");

  // Focus a real control first, so there is something to restore focus TO.
  const invoker = page.locator("#caseId");
  await invoker.focus();

  await openOverlay(page, "enrichOverlay");
  await expect(page.locator("#enrichOverlay")).toHaveAttribute("aria-modal", "true");

  await page.keyboard.press("Escape");

  await expect(page.locator("#enrichOverlay")).not.toHaveClass(/\bopen\b/);
  await expect(page.locator("#enrichOverlay")).not.toHaveAttribute("aria-modal", "true");
  await expect(invoker).toBeFocused();
});

test("closing by the app's own class toggle also restores focus", async ({ page }) => {
  await page.goto("/dashboard");
  const invoker = page.locator("#caseId");
  await invoker.focus();

  await openOverlay(page, "anonOverlay");
  await expect(page.locator("#anonOverlay")).toHaveAttribute("aria-modal", "true");

  // Backdrop clicks and Cancel buttons all funnel through this same class removal.
  await page.evaluate(() => document.getElementById("anonOverlay")?.classList.remove("open"));
  await expect(invoker).toBeFocused();
});
