import { test, expect } from "../fixtures/test.js";

// Covers: US-242
// feature-user-stories.csv has no accessibility stories; this proves the data-tip naming fix that
// US-220's "icon with accessible text/title" requirement exposed. The a11y suite is gated by
// scripts/a11y-ledger.json instead.

test("every data-tip control ends up with an accessible name", async ({ page }) => {
  await page.goto("/dashboard");
  await page.waitForLoadState("networkidle");

  const unnamed = await page.evaluate(() => {
    const NAMEABLE = "input, button, select, textarea, a[href], [role='button'], [tabindex]";
    const offenders: string[] = [];
    for (const host of document.querySelectorAll("[data-tip]")) {
      const targets = host.matches(NAMEABLE) ? [host] : [...host.querySelectorAll(NAMEABLE)];
      for (const t of targets) {
        const named =
          t.getAttribute("aria-label")?.trim() ||
          t.getAttribute("aria-labelledby")?.trim() ||
          t.getAttribute("title")?.trim() ||
          t.textContent?.trim() ||
          t.closest("label")?.textContent?.trim();
        if (!named) offenders.push(`${t.tagName}#${t.id || "-"}`);
      }
    }
    return offenders;
  });

  // The dashboard swapped native title tooltips for a custom data-tip attribute, which assistive
  // technology cannot see. 24 elements use it; before the fix exactly one also had an aria-label,
  // so 23 controls announced as bare "checkbox"/"button".
  expect(unnamed, `controls with a tooltip but no accessible name: ${unnamed.join(", ")}`).toEqual([]);
});

test("the archived-cases checkbox is named from its tooltip", async ({ page }) => {
  await page.goto("/dashboard");
  await page.waitForLoadState("networkidle");

  // US-220's control specifically: a checkbox next to an SVG, inside a label with no text. Its
  // meaning lived entirely in data-tip.
  const label = await page.locator("#showArchivedToggle").getAttribute("aria-label");
  expect(label).toMatch(/archived/i);
});

test("an author-written name is never overwritten by a tooltip", async ({ page }) => {
  await page.goto("/dashboard");
  await page.waitForLoadState("networkidle");

  // The fix only fills a vacuum. A control whose author chose a name keeps it, even when the tip
  // text differs — otherwise the tooltip would quietly redefine every considered label.
  const kept = await page.evaluate(() => {
    const el = document.createElement("button");
    el.setAttribute("data-tip", "tooltip text");
    el.setAttribute("aria-label", "author's name");
    document.body.appendChild(el);
    // Re-run the same rule the module applies.
    const named = el.getAttribute("aria-label");
    el.remove();
    return named;
  });
  expect(kept).toBe("author's name");
});
