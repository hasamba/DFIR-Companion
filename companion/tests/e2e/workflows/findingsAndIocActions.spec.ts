import { test, expect } from "../fixtures/test.js";
import type { Page } from "@playwright/test";
import { revealSections } from "../fixtures/sections.js";

// Covers: US-222, US-223, US-228, US-231
// (feature-user-stories.csv) — the in-panel actions an analyst fires dozens of times per case:
// multi-selecting findings for a bulk change, generating hunt queries from a finding, narrowing
// the IOC panel with its facet menus, and the quick-action tray on a detected value.
//
// revealSections() is used ONLY to make the findings/IOC panels visible (they are hidden by the
// default Now view); every interaction inside them is a real click. The view-menu navigation
// itself is covered by analystJourney.spec.ts and dashboardControls.spec.ts — re-proving it in
// every file would couple all panel tests to one menu.

async function openCase(page: Page, caseId: string, ...sections: string[]): Promise<void> {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(caseId)}`);
  await page.waitForLoadState("networkidle");
  await revealSections(page, ...sections);
}

test("US-222: selecting two findings raises the bulk bar, and a bulk tag lands on both", async ({
  page,
  demoCase,
}) => {
  await openCase(page, demoCase, "sec-findings");
  await expect(page.locator("#findings .finding").first()).toBeVisible({ timeout: 30_000 });

  const bar = page.locator("#findingBulkBar");
  await expect(bar, "no selection, no bar").not.toHaveClass(/\bactive\b/);

  const boxes = page.locator(".finding-row-cb");
  expect(await boxes.count(), "the seeded case must render several findings").toBeGreaterThan(1);
  await boxes.nth(0).check();
  await boxes.nth(1).check();

  await expect(bar).toHaveClass(/\bactive\b/);
  await expect(page.locator("#findingBulkCount")).toHaveText("2 findings selected");

  // The bulk action: Modify Tags → the shared tag modal → one tag applied to the whole selection.
  await page.locator("#findingBulkTagBtn").click();
  const tagOverlay = page.locator("#tagOverlay");
  await expect(tagOverlay).toHaveClass(/\bopen\b/);
  await page.locator("#tagInput").fill("e2e-bulk-review");
  await page.locator("#tagAddBtn").click();

  // The claim is persistence, not modal choreography: both selected findings now carry the tag.
  const state = async (): Promise<string[]> => {
    const res = await page.request.get(`/cases/${demoCase}/tags`);
    expect(res.status(), await res.text()).toBe(200);
    const tags = (await res.json()) as Array<{ label?: string; targetType?: string }>;
    return tags.filter((t) => t.label === "e2e-bulk-review" && t.targetType === "finding").map(() => "x");
  };
  await expect.poll(state, { timeout: 15_000 }).toHaveLength(2);

  // Clear empties the selection so the next bulk action cannot silently include these rows.
  await page.locator("#tagClose").click();
  await page.locator("#findingBulkClearBtn").click();
  await expect(bar).not.toHaveClass(/\bactive\b/);
  await expect(boxes.nth(0)).not.toBeChecked();
});

test("US-223: Hunt on a detected value opens the builder with runnable queries per platform", async ({
  page,
  demoCase,
}) => {
  // The hunt builder's analyst entries are the quick-action tray on a detected value and the hunt
  // chips on super-timeline rows — NOT a control on the finding card (the first version of this
  // test clicked "#findings .hunt-add", which does not exist). The tray path is the one an analyst
  // reaches from the evidence itself.
  await openCase(page, demoCase, "sec-timeline");
  await expect(page.locator("#sec-timeline .ev-row").first()).toBeVisible({ timeout: 30_000 });

  const value = page.locator("#forensicTimeline .qa-val").first();
  const clicked = ((await value.getAttribute("data-val")) ?? "").trim();
  expect(clicked).not.toBe("");
  await value.click();
  const tray = page.locator(".qa-tray");
  await expect(tray).toBeVisible();
  await tray.locator('[data-qa="hunt"]').click();

  const overlay = page.locator("#huntOverlay");
  await expect(overlay).toHaveClass(/\bopen\b/);

  const body = page.locator("#huntBody");
  // Which platforms render is served by /health (DFIR_HUNT_PLATFORMS); this harness allows
  // Velociraptor only, so that is what may be asserted — a KQL/Sigma expectation here failed
  // against a correctly narrowed builder. What must hold for the offered platform: real query
  // text, with the CLICKED VALUE baked into it. A template that ignores the value the analyst
  // picked would hunt for nothing.
  await expect(body).toContainText(/Velociraptor/i);
  const text = (await body.textContent()) ?? "";
  expect(text.length, "the builder must generate real query text").toBeGreaterThan(200);
  expect(text, "the VQL must be a runnable query").toMatch(/SELECT[\s\S]*FROM/);
  expect(text, "the clicked value must be baked into the hunt").toContain(clicked);

  await page.locator("#huntClose").click();
  await expect(overlay).not.toHaveClass(/\bopen\b/);
});

test("US-228: the IOC type facet narrows the table to the checked type only", async ({ page, demoCase }) => {
  await openCase(page, demoCase, "sec-iocs");
  await expect(page.locator("#iocs .ioc-row").first()).toBeVisible({ timeout: 30_000 });

  // Widen the default noise lenses first, exactly as panelBrowsing.spec.ts does, so the counts
  // below describe every IOC rather than a triage subset.
  await page.locator("#iocSignalBtn").click();
  await page.locator("#iocHideNoiseChk").uncheck();
  await page.locator("#iocHideSysPathsChk").uncheck();

  const rows = page.locator("#iocs .ioc-row");
  const before = await rows.count();
  expect(before, "the seeded case must show IOCs").toBeGreaterThan(2);

  // The seeded case spans several IOC types (hashes, ips, domains); keep only "ip".
  await page.locator("#iocTypeFilterBtn").click();
  const menu = page.locator("#iocTypeFilterMenu");
  await expect(menu).toBeVisible();
  const typeBoxes = menu.locator(".ioc-type-cb");
  const types = await typeBoxes.count();
  expect(types, "the facet must list more than one type for filtering to mean anything").toBeGreaterThan(1);
  for (let i = 0; i < types; i++) {
    const box = typeBoxes.nth(i);
    if ((await box.getAttribute("value")) !== "ip") await box.uncheck();
  }

  await expect.poll(async () => rows.count(), { timeout: 15_000 }).toBeLessThan(before);
  const after = await rows.count();
  expect(after, "unchecking every other type must leave the ip rows").toBeGreaterThan(0);
  // Every surviving row is an ip row — the subset claim, not just "fewer". No leading \b: the
  // row text runs the type label straight into the value ("ip10.10.20.15"), and \b between two
  // word characters never matches.
  for (let i = 0; i < after; i++) {
    await expect(rows.nth(i)).toContainText(/\d{1,3}(\.\d{1,3}){3}/);
  }
});

test("US-231: clicking a detected value opens the tray; Malicious pins a red verdict on its IOC", async ({
  page,
  demoCase,
}) => {
  await openCase(page, demoCase, "sec-timeline", "sec-iocs");
  await expect(page.locator("#sec-timeline .ev-row").first()).toBeVisible({ timeout: 30_000 });

  // Any detected value inside an event description is wrapped as .qa-val by the renderer.
  const value = page.locator("#forensicTimeline .qa-val").first();
  await expect(value, "the seeded timeline must render clickable detected values").toBeVisible();
  const clicked = ((await value.getAttribute("data-val")) ?? "").trim();
  expect(clicked).not.toBe("");

  await value.click();
  const tray = page.locator(".qa-tray");
  await expect(tray, "the quick-action tray opens on click").toBeVisible();
  // The four actions the story names.
  await expect(tray.locator('[data-qa="copy"]')).toBeVisible();
  await expect(tray.locator('[data-qa="benign"]')).toBeVisible();
  await expect(tray.locator('[data-qa="malicious"]')).toBeVisible();
  await expect(tray.locator('[data-qa="hunt"]')).toBeVisible();

  await tray.locator('[data-qa="malicious"]').click();

  // The verdict is persisted as a "confirmed-malicious" TAG on the case (keyed by the tracked IOC
  // id when the value is one, else by the raw value) — the red pill the tray promises is rendered
  // from exactly that tag, so the tag's existence IS the durable claim.
  await expect
    .poll(
      async () => {
        const res = await page.request.get(`/cases/${demoCase}/tags`);
        const tags = (await res.json()) as Array<{ label?: string; targetType?: string }>;
        return tags.some((t) => t.targetType === "ioc" && t.label === "confirmed-malicious");
      },
      { timeout: 15_000 },
    )
    .toBe(true);

  // Escape closes the tray — it must not linger over the timeline.
  await page.keyboard.press("Escape");
  await expect(tray).toBeHidden();
});
