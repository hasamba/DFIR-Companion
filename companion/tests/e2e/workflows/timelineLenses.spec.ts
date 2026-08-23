import { test, expect } from "../fixtures/test.js";
import type { Page } from "@playwright/test";
import { revealSections } from "../fixtures/sections.js";

// Covers: US-229, US-236, US-279
// (feature-user-stories.csv) — the three lenses that turn a 60-event timeline into something an
// analyst can hold: the event-density heatmap (and its click-to-zoom), the attacker-sessions
// story view, and the time-scope window that re-projects the case without an AI run.

async function openTimeline(page: Page, caseId: string, ...extra: string[]): Promise<void> {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(caseId)}`);
  await page.waitForLoadState("networkidle");
  await revealSections(page, "sec-timeline", ...extra);
  await expect(page.locator("#sec-timeline .ev-row").first()).toBeVisible({ timeout: 30_000 });
}

/** `#timelineCount` renders "(N events)" unfiltered and "(N of M events)" once anything filters. */
async function shownCount(page: Page): Promise<number> {
  const raw = (await page.locator("#timelineCount").textContent()) ?? "";
  const m = raw.match(/(\d+)(?:\s+of\s+\d+)?\s+events?/);
  return Number(m?.[1] ?? -1);
}

test("US-229: the heatmap draws density bars, and clicking one zooms the timeline to its window", async ({
  page,
  demoCase,
}) => {
  await openTimeline(page, demoCase);

  const bars = page.locator("#timelineHeatmap .tl-heatmap-bar");
  // The seeded case spans nine days of events, so the bucketing must produce several bars —
  // a single bar would mean the whole case collapsed into one bucket and the lens shows nothing.
  expect(await bars.count(), "the seeded case must bucket into several bars").toBeGreaterThan(1);
  await expect(page.locator("#timelineHeatmapCaption")).toBeVisible();

  const before = await shownCount(page);
  expect(before).toBeGreaterThan(0);

  // A populated bar carries the zoom action and a data window; an empty bucket is inert.
  const populated = page.locator('#timelineHeatmap .tl-heatmap-bar[data-act="zoomToTimeWindow"]').first();
  await expect(populated).toBeVisible();
  await populated.click();

  // The zoom narrows the visible set to the bar's bucket. "N of M" appearing in the count is the
  // analyst-visible proof that a filter — not a data loss — happened.
  await expect
    .poll(async () => ((await page.locator("#timelineCount").textContent()) ?? "").includes(" of "), {
      timeout: 15_000,
    })
    .toBe(true);
  const after = await shownCount(page);
  expect(after, "zooming to one bucket must show fewer events than the whole case").toBeLessThan(before);
  expect(after, "a populated bucket cannot zoom to nothing").toBeGreaterThan(0);
});

test("US-236: the sessions view segments the seeded timeline into attacker sessions", async ({
  page,
  demoCase,
}) => {
  await openTimeline(page, demoCase, "sec-sessions");

  const rows = page.locator("#sessions .ses-head");
  // Derived deterministically from the timeline (no AI): contiguous activity per host/account.
  // The seeded case holds multi-host activity, so at least one session must appear.
  await expect(rows.first(), "the seeded case must segment into sessions").toBeVisible({
    timeout: 30_000,
  });
  await expect(page.locator("#sessionsCount")).not.toHaveText("");

  // Each session head names its host and when — the narrative frame the story promises.
  const head = rows.first();
  await expect(head.locator(".ses-host")).not.toHaveText("");
  await expect(head.locator(".ses-when")).not.toHaveText("");

  // "Collapsible" is section-wide: the Collapse-all button folds every card to its header line
  // (per-card heads are not toggles — clicking a CARD filters the timeline instead, below).
  const body = page.locator("#sessions .ses-body").first();
  await expect(body).toBeVisible();
  await page.locator("#sessionsCollapseAllBtn").click();
  await expect(page.locator("#sec-sessions")).toHaveClass(/\bses-collapsed\b/);
  await page.locator("#sessionsCollapseAllBtn").click();
  await expect(page.locator("#sec-sessions")).not.toHaveClass(/\bses-collapsed\b/);

  // The narrative's working move: clicking a session card filters the forensic timeline to that
  // session's events — the count switches to the "N of M" subset form.
  const before = await shownCount(page);
  await page.locator("#sessions .ses-card").first().click();
  await expect
    .poll(async () => ((await page.locator("#timelineCount").textContent()) ?? "").includes(" of "), {
      timeout: 15_000,
    })
    .toBe(true);
  const after = await shownCount(page);
  expect(after, "one session cannot be the whole case").toBeLessThanOrEqual(before);
  expect(after, "a session's filter must keep its own events").toBeGreaterThan(0);
});

test("US-279: applying a time scope re-projects the case immediately, and Clear restores it", async ({
  page,
  demoCase,
}) => {
  await openTimeline(page, demoCase);
  const fullCount = await shownCount(page);
  expect(fullCount).toBeGreaterThan(0);

  // The seeded case runs 2026-05-14 → 2026-05-23; this window keeps only the 2026-05-22 tail.
  await page.locator("#scopeStart").fill("2026-05-22T00:00");
  await page.locator("#scopeEnd").fill("2026-05-23T00:00");
  await page.locator("#applyScope").click();

  // "Instant" is the story: the deterministic re-projection updates the view without waiting on
  // the (stubbed) synthesis the scope change also queues. scopeInfo is the analyst's evidence a
  // scope is active at all — without it a narrowed case reads as missing evidence.
  await expect(page.locator("#scopeInfo")).not.toHaveText("", { timeout: 20_000 });
  await expect.poll(async () => shownCount(page), { timeout: 20_000 }).toBeLessThan(fullCount);

  const scoped = await shownCount(page);
  expect(scoped, "the 05-22 window must keep the tail of the case").toBeGreaterThan(0);

  // The server holds the scope, not just this tab — a reload must come back scoped.
  const stored = await page.request.get(`/cases/${demoCase}/scope`);
  expect(stored.status(), await stored.text()).toBe(200);
  const scope = (await stored.json()) as { start: string | null; end: string | null };
  expect(scope.start, "the scope must persist server-side").not.toBeNull();

  // Clear is the escape hatch: one click back to the whole case.
  await page.locator("#clearScope").click();
  await expect.poll(async () => shownCount(page), { timeout: 20_000 }).toBe(fullCount);
  const cleared = await page.request.get(`/cases/${demoCase}/scope`);
  const clearedScope = (await cleared.json()) as { start: string | null; end: string | null };
  expect(clearedScope.start).toBeNull();
  expect(clearedScope.end).toBeNull();
});
