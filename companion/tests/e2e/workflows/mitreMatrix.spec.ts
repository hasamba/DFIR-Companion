import { test, expect } from "../fixtures/test.js";

// Covers: US-067
//
// The MITRE panel's Matrix view (#1764), driven the way an analyst drives it: the panel opens on
// Matrix, a click on a hit cell opens its popover, and an event link in the popover lands on that
// row in the Forensic Timeline — in the Executive view, which HIDES the timeline. That view is the
// point: a link into a display:none section "does nothing" unless it reveals the section first,
// and the Analyst view, which shows everything, would hide that bug.

interface StateEvent {
  id: string;
  severity: string;
  mitreTechniques?: string[];
}

test("Matrix is the default; a hit cell's event link lands in the Forensic Timeline (Executive view)", async ({
  page,
  demoCase,
  request,
}) => {
  // The Executive view floors the timeline at High, so the link under test must be a High+ event.
  const res = await request.get(`/cases/${encodeURIComponent(demoCase)}/state`);
  expect(res.ok()).toBe(true);
  const state = (await res.json()) as { forensicTimeline: StateEvent[] };
  const target = state.forensicTimeline.find(
    (e) => (e.mitreTechniques ?? []).includes("T1059.001") && ["Critical", "High"].includes(e.severity),
  );
  expect(target, "the demo case has no High+ event carrying T1059.001").toBeDefined();

  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);
  await page.waitForLoadState("networkidle");

  // Executive, through the real menu.
  await page.locator("#dashViewBtn").click();
  await page.locator('#dashViewMenu .dv-item[data-view="executive"]').click();
  await expect(page.locator("#sec-timeline")).toBeHidden();

  // Executive hides the MITRE panel too; show it the way the product's own jumps do.
  await page.evaluate(() =>
    (window as unknown as { revealSection(id: string): void }).revealSection("sec-mitre"),
  );
  await expect(page.locator("#sec-mitre")).toBeVisible();

  // A fresh browser has no stored choice, so the panel opens on Matrix.
  await expect(page.locator("#mitreViewMatrix")).toHaveAttribute("aria-pressed", "true");
  const cell = page.locator('#mitre .mm-cell.mm-hit[data-tid="T1059.001"]').first();
  await expect(cell).toBeVisible({ timeout: 30_000 });
  await expect(cell).toHaveAttribute(
    "aria-label",
    /^T1059\.001 PowerShell, (Critical|High), \d+ findings?, \d+ events?$/,
  );

  await cell.click();
  const popover = page.locator("#mitrePopover");
  await expect(popover).toBeVisible();
  await expect(popover).toContainText("T1059.001 PowerShell");
  await expect(popover.locator('a[href="https://attack.mitre.org/techniques/T1059/001/"]')).toHaveCount(1);

  await popover.locator(`[data-jump-event="${target!.id}"]`).click();
  await expect(page.locator("#sec-timeline")).toBeVisible();
  await expect(page.locator(`#forensicTimeline .ev-row[data-evid="${target!.id}"]`)).toBeVisible();

  // Esc closes the popover.
  await page.locator("#mitreViewMatrix").focus();
  await cell.click();
  await expect(popover).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(popover).toBeHidden();
});
