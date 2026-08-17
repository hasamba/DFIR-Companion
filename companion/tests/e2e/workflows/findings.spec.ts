import { test, expect } from "../fixtures/test.js";
import type { Page } from "@playwright/test";
import { revealSections } from "../fixtures/sections.js";

// Covers: US-075
// (feature-user-stories.csv) — the Findings panel listing real findings and responding to the filter.
//

// seedDemoCase writes findings f001-f010 plus the f004b/f007b near-duplicates (12 from AI
// synthesis) and f-auto-e044/f-gap-e043-e019 (the two deterministic backfill findings, 14 in
// total), so these assert on known ids. "more than zero findings" would still pass if every row
// rendered empty.

async function openCase(page: Page, caseId: string): Promise<void> {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(caseId)}`);
  await expect(page.locator("#sec-findings .finding").first()).toBeAttached({ timeout: 30_000 });
  // #sec-findings is display:none under the default view; without this these specs assert against
  // DOM the user cannot see.
  await revealSections(page, "sec-findings");
  await expect(page.locator("#sec-findings .finding").first()).toBeVisible();
}

test("lists the seeded findings by id", async ({ page, demoCase }) => {
  await openCase(page, demoCase);

  const findings = page.locator("#sec-findings .finding");
  expect(await findings.count()).toBeGreaterThan(0);

  // f001 is the initial-access finding in the seeded scenario.
  await expect(page.locator("#sec-findings .finding[data-fid='f001']")).toHaveCount(1);

  // Every finding must carry its id — it is what the ticket-export and jump-to-evidence actions
  // key off, so a finding without one renders fine and is inert.
  expect(await page.locator("#sec-findings .finding:not([data-fid])").count()).toBe(0);
});

test("findings carry readable text, not empty placeholders", async ({ page, demoCase }) => {
  await openCase(page, demoCase);
  const first = page.locator("#sec-findings .finding[data-fid='f001']");
  const text = (await first.innerText()).trim();
  // A row that renders but says nothing is the failure a row count cannot see.
  expect(text.length).toBeGreaterThan(20);
});

test("filtering applies to findings as well as events", async ({ page, demoCase }) => {
  await openCase(page, demoCase);
  const findings = page.locator("#sec-findings .finding");
  const before = await findings.count();
  expect(before).toBeGreaterThan(1);

  await page.locator("#main").click({ position: { x: 5, y: 5 } });
  await page.keyboard.press("/");
  await page.locator("#globalSearch").fill("zzz-no-such-finding-zzz");

  // The filter bar says "Filter events, findings, IOCs…" — so findings must actually respond to it.
  await expect.poll(async () => findings.count(), { timeout: 15_000 }).toBe(0);
});

// seedDemoCase seeds exactly one backfill finding of each kind — f-auto-e044 and
// f-gap-e043-e019 — specifically so the test below can watch a row disappear instead of only
// proving the controls exist. Each lens is checked INDEPENDENTLY (not just both together): both
// boxes checked at once would still pass if they were wired to each other's predicate (i.e. if
// "hide auto" accidentally hid the gap row too), so step 2 and step 3 each isolate one checkbox
// and assert the OTHER backfill row is unaffected. That is what actually catches an argument
// swap at the findingPassesOriginLens(f, hideAuto, hideGap) call site in dashboard-render.js.
test("the origin lenses hide exactly the row they name, independently", async ({ page, demoCase }) => {
  await openCase(page, demoCase);

  const hideAuto = page.locator("#hideAutoFindings");
  const hideGap = page.locator("#hideGapFindings");
  const autoRow = page.locator("#sec-findings .finding[data-fid='f-auto-e044']");
  const gapRow = page.locator("#sec-findings .finding[data-fid='f-gap-e043-e019']");
  const aiRow = page.locator("#sec-findings .finding[data-fid='f001']");

  // Step 1: unfiltered, both backfill rows and an ordinary AI-synthesis row are all present.
  await expect(autoRow).toHaveCount(1);
  await expect(gapRow).toHaveCount(1);
  await expect(aiRow).toHaveCount(1);

  // Step 2: "Hide auto-flagged" alone drops ONLY the f-auto- row.
  await hideAuto.check();
  await expect(autoRow).toHaveCount(0);
  await expect(gapRow).toHaveCount(1);
  await expect(aiRow).toHaveCount(1);

  // Step 3 — the one that matters most: uncheck it and check "Hide coverage-gap" alone. Collapsing
  // this into step 2 (checking both together) would still pass even if the two checkboxes were
  // wired to each other's predicate; only testing each in isolation catches that.
  await hideAuto.uncheck();
  await hideGap.check();
  await expect(gapRow).toHaveCount(0);
  await expect(autoRow).toHaveCount(1);
  await expect(aiRow).toHaveCount(1);

  // Step 4: both checked — only AI-synthesis findings remain.
  await hideAuto.check();
  await expect(autoRow).toHaveCount(0);
  await expect(gapRow).toHaveCount(0);
  await expect(aiRow).toHaveCount(1);
});

// The row-disappears proof lives in the test above. This one covers a different property: the
// checkbox states survive a reload instead of evaporating back to unchecked.
test("the finding-origin lenses persist across a reload", async ({ page, demoCase }) => {
  await openCase(page, demoCase);

  const hideAuto = page.locator("#hideAutoFindings");
  const hideGap = page.locator("#hideGapFindings");
  await expect(hideAuto).toBeVisible();
  await expect(hideGap).toBeVisible();
  await expect(hideAuto).not.toBeChecked();
  await expect(hideGap).not.toBeChecked();

  // Unfiltered, the header states a plain total.
  await expect(page.locator("#findingsCount")).toHaveText(/^\(\d+ findings?\)$/);

  await hideAuto.check();

  // Checked, the header switches to the "N of M" form. This case's seeded f-auto- finding means
  // something real is now hidden, but the format must switch regardless of whether a lens actually
  // hides anything — otherwise a suppressed finding would be indistinguishable from one that was
  // never there.
  await expect(page.locator("#findingsCount")).toHaveText(/^\(\d+ of \d+ findings\)$/);

  await page.reload();
  await expect(page.locator("#sec-findings .finding").first()).toBeAttached({ timeout: 30_000 });
  await expect(page.locator("#hideAutoFindings")).toBeChecked();
  await expect(page.locator("#hideGapFindings")).not.toBeChecked();
});

// Ticking a lens re-renders the whole dashboard, and the re-render used to re-append EVERY <section>
// to <main> whether or not the order had changed. appendChild() on a node that is already a child is
// a remove followed by an insert, so the section holding the analyst's viewport — and the checkbox
// they had just clicked — left the document for an instant. Chrome answers that by blurring the
// control and dropping window.scrollY to 0: one click on a filter and the analyst was back at the
// top of a 50-section page, hunting for the findings list again.
//
// The scroll assertion needs a page long enough to scroll, hence the extra revealed sections, and it
// is deliberately NOT `toBe(before)`. Panels above the findings list finish loading on their own
// schedule, so the exact offset can legitimately drift a few pixels; what must never happen is the
// jump to the top. Focus is asserted too because it is the same defect seen from the other side and
// it is exact — the checkbox either survived the re-render still focused or it did not.
test("ticking an origin lens leaves the analyst where they were", async ({ page, demoCase }) => {
  await openCase(page, demoCase);
  await revealSections(page, "sec-timeline", "sec-iocs");

  const hideAuto = page.locator("#hideAutoFindings");
  await hideAuto.scrollIntoViewIfNeeded();
  const before = await page.evaluate(() => window.scrollY);
  expect(before).toBeGreaterThan(0);

  await hideAuto.click();

  // The re-render really happened — otherwise this passes by doing nothing at all.
  await expect(page.locator("#sec-findings .finding[data-fid='f-auto-e044']")).toHaveCount(0);

  expect(await page.evaluate(() => window.scrollY)).toBeGreaterThan(before * 0.9);
  await expect(hideAuto).toBeFocused();
});
