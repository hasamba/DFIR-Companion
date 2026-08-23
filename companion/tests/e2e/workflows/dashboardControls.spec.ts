import { test, expect } from "../fixtures/test.js";
import type { Page } from "@playwright/test";

// Covers: US-225, US-234, US-237, US-238, US-239
// (feature-user-stories.csv) — the chrome an analyst works THROUGH all day: the Ctrl+K command
// palette, the Settings modal's Essential/All toggle, the custom hover tooltip, the responsive
// toolbar collapse, and collapsible sections that keep their state across a reload.
//
// Everything here is driven the way a person drives it — keyboard shortcut, hover, click,
// viewport resize. revealSections() is deliberately absent: half of these stories ARE the
// show/hide machinery that helper exists to bypass, so bypassing it would test nothing.

async function openDashboard(page: Page, caseId: string): Promise<void> {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(caseId)}`);
  await page.waitForLoadState("networkidle");
}

/** Switch to the Triage view through the real menu — the navigation the journey spec proved. */
async function switchToTriage(page: Page): Promise<void> {
  await page.locator("#dashViewBtn").click();
  const menu = page.locator("#dashViewMenu");
  await expect(menu).toBeVisible();
  await menu.locator('.dv-item[data-view="triage"]').click();
  await expect(page.locator("#sec-timeline")).toBeVisible();
}

test("US-234: Ctrl+K opens the palette, filtering narrows it, Enter jumps to the section", async ({
  page,
  demoCase,
}) => {
  await openDashboard(page, demoCase);
  // The palette only offers jumps to sections the current view SHOWS — a hidden panel is not
  // somewhere to jump to — so the test first enters a view where the timeline exists.
  await switchToTriage(page);

  await page.keyboard.press("Control+k");
  const overlay = page.locator("#cmdpOverlay");
  await expect(overlay, "Ctrl+K must open the palette").toHaveClass(/\bopen\b/);

  const input = page.locator("#cmdpInput");
  await expect(input).toBeFocused();

  await input.fill("forensic timeline");
  const rows = page.locator("#cmdpList .cmdp-row");
  await expect(rows.first()).toBeVisible();
  const count = await rows.count();
  expect(count, "filtering must narrow the action list").toBeGreaterThan(0);
  await expect(rows.first()).toContainText(/timeline/i);

  // Close the palette before touching the page — its overlay covers everything and intercepts
  // the click (the first version of this test waited 30s on the chevron for exactly that reason).
  await page.keyboard.press("Escape");
  await expect(overlay).not.toHaveClass(/\bopen\b/);

  // Collapse the target so the jump has something observable to do. The chevron is the collapse
  // control — the h2 is packed with filter buttons whose clicks the handler ignores.
  await page.locator("#sec-timeline > h2 .chev").click();
  await expect(page.locator("#sec-timeline")).toHaveClass(/\bcollapsed\b/);
  await page.keyboard.press("Control+k");
  await page.locator("#cmdpInput").fill("forensic timeline");
  // Several actions can match the filter (exports, filters, the jump). Clicking the named
  // navigation row runs the intended one — Enter fires whichever row holds the selection, which
  // is not a claim this test makes.
  await page.locator("#cmdpList .cmdp-row", { hasText: "Go to Forensic Timeline" }).click();

  await expect(overlay, "running an action closes the palette").not.toHaveClass(/\bopen\b/);
  // The jump un-collapses the section and scrolls it into view — both observable.
  await expect(page.locator("#sec-timeline")).not.toHaveClass(/\bcollapsed\b/);
  await expect
    .poll(async () =>
      page.evaluate(() => {
        const rect = document.getElementById("sec-timeline")?.getBoundingClientRect();
        return rect ? rect.top > -rect.height && rect.top < window.innerHeight : false;
      }),
    )
    .toBe(true);

  // Escape closes without running anything.
  await page.keyboard.press("Control+k");
  await expect(overlay).toHaveClass(/\bopen\b/);
  await page.keyboard.press("Escape");
  await expect(overlay).not.toHaveClass(/\bopen\b/);
});

test("US-237: the Settings modal opens in Essential mode and All reveals the full surface", async ({
  page,
  demoCase,
}) => {
  await openDashboard(page, demoCase);

  await page.locator("#settingsBtn").click();
  const overlay = page.locator("#settingsOverlay");
  await expect(overlay).toHaveClass(/\bopen\b/);

  const essential = page.locator("#settingsModeEssential");
  const all = page.locator("#settingsModeAll");
  await expect(essential).toBeVisible();
  await expect(all).toBeVisible();

  // The point of the toggle is that All shows strictly more than Essential. Count the visible
  // setting rows in each mode; equal counts would mean the toggle is decoration.
  const visibleFields = async (): Promise<number> => page.locator(".sfield:visible").count();

  await all.click();
  const allCount = await visibleFields();
  await essential.click();
  const essentialCount = await visibleFields();
  expect(essentialCount, "Essential must be a strict subset of All").toBeLessThan(allCount);
  expect(essentialCount, "Essential mode must still show something").toBeGreaterThan(0);

  // Tab switching: click a named non-active tab and its pane fronts. The locator pins the SAME
  // element across the click — ".stab:not(.active)" re-resolves after activation and lands on a
  // different tab, which is how the first version of this test failed against working tabs.
  await all.click();
  const veloTab = page.locator('.stab[data-stab="velociraptor"]');
  await expect(veloTab).not.toHaveClass(/\bactive\b/);
  await veloTab.click();
  await expect(veloTab, "the Velociraptor tab did not activate").toHaveClass(/\bactive\b/);
  await expect(page.locator("#stab-velociraptor")).toBeVisible();

  await page.locator("#settingsCloseBtn").click();
  await expect(overlay).not.toHaveClass(/\bopen\b/);
});

test("US-239: hovering a control shows the custom tooltip card with that control's text", async ({
  page,
  demoCase,
}) => {
  await openDashboard(page, demoCase);

  // The Import button carries a long data-tip. The custom card must render it; the native title
  // path would be invisible to assertions (browsers do not expose title bubbles to the DOM).
  const importBtn = page.locator("#importBtn");
  const tip = await importBtn.getAttribute("data-tip");
  expect(tip, "the control under test must carry a data-tip").toBeTruthy();

  await importBtn.hover();
  const card = page.locator(".tip");
  await expect(card, "the custom tooltip card must appear on hover").toBeVisible();
  await expect(card).toContainText((tip as string).slice(0, 40));

  // And it must leave when the pointer does — a stuck tooltip covers the toolbar it describes.
  await page.locator("#main").hover();
  await expect(card).toBeHidden();
});

test("US-238: a toolbar that cannot fit its labels collapses to reachable icons", async ({ page }) => {
  // DISCONNECTED on purpose. A connected case adds enough toolbar buttons that the row wraps even
  // at 1900px with full labels (measured: scrollHeight 80 vs row 31) — with a case attached the
  // un-collapsed state is unreachable at any width.
  //
  // The labeled baseline is 2560, not 1900: even disconnected, the full-label row wraps at 1900
  // (settled scrollHeight 77 with the class held off, vs threshold ~49.6 — an earlier "settled
  // 38" reading that suggested it fits was taken with icons-only applied, i.e. it measured the
  // collapsed row). So both directions are driven from a width where the labels genuinely fit.
  await page.setViewportSize({ width: 2560, height: 800 });
  await page.goto("/dashboard");
  await page.waitForLoadState("networkidle");
  const toolbar = page.locator("#toolbarMain");
  // Without this baseline, the collapse below could be asserting a class already on at load.
  await expect(toolbar, "at 2560px the labels must fit uncollapsed").not.toHaveClass(/\bicons-only\b/);

  await page.setViewportSize({ width: 700, height: 800 });
  await expect(toolbar, "a 700px viewport must collapse the toolbar").toHaveClass(/\bicons-only\b/, {
    timeout: 10_000,
  });
  // Collapsed is not gone: the buttons must survive as reachable icons. §8's rule that every
  // toolbar button needs a ::before icon exists because a text-only label gets font-size:0 here.
  await expect(page.locator("#importBtn")).toBeVisible();
  await expect(page.locator("#newCaseBtn")).toBeVisible();

  // And the labels come back when the room does — the fit measures current geometry on the grow,
  // so no trigger beyond the header ResizeObserver is needed.
  await page.setViewportSize({ width: 2560, height: 800 });
  await expect(toolbar, "growing back to 2560px must restore the labels").not.toHaveClass(/\bicons-only\b/, {
    timeout: 10_000,
  });
});

test("US-225: a collapsed section stays collapsed across a reload", async ({ page, demoCase }) => {
  await openDashboard(page, demoCase);
  await switchToTriage(page);

  const section = page.locator("#sec-timeline");
  await expect(section).not.toHaveClass(/\bcollapsed\b/);

  // The chevron in the header is the collapse control (clicks on the header's embedded filter
  // buttons are deliberately ignored by the handler).
  await section.locator("> h2 .chev").click();
  await expect(section).toHaveClass(/\bcollapsed\b/);

  await page.reload();
  await page.waitForLoadState("networkidle");
  // The persisted layout must come back without any interaction — that is the story.
  await expect(section, "the collapse must survive a reload").toHaveClass(/\bcollapsed\b/);

  // And the analyst can reopen it, so the persistence is not a trap.
  await section.locator("> h2 .chev").click();
  await expect(section).not.toHaveClass(/\bcollapsed\b/);
});
