import { test, expect } from "../fixtures/test.js";
import type { Page } from "@playwright/test";
import { revealSections } from "../fixtures/sections.js";

// Covers: US-053, US-055, US-183
// (feature-user-stories.csv) — the three panel behaviours an analyst uses to get through a case too
// large to read: filter the timeline by the tool that produced each event, expand a kill-chain
// tactic to the events under it, and page through a long IOC list.
//
// These were nearly written off as "styling", which was wrong. A filter that filters, a disclosure
// that discloses and a pager that pages are behaviour, and all three fail in the same quiet way: the
// control still looks right while showing the analyst the wrong subset of the evidence. That is
// worse than a visibly broken panel, because nothing prompts them to doubt what they are reading.
//
// What is deliberately NOT asserted is appearance — no CSS class or border is pinned here. US-221
// (card layout) stays uncovered for that reason; see COVERAGE.md.

/** The seeded case's timeline, straight from the API — the source of truth these specs derive from. */
async function timelineOf(page: Page, caseId: string): Promise<Array<{ sources?: string[] }>> {
  const res = await page.request.get(`/cases/${caseId}/state`);
  expect(res.status(), await res.text()).toBe(200);
  const state = (await res.json()) as { forensicTimeline?: Array<{ sources?: string[] }> };
  return state.forensicTimeline ?? [];
}

const NO_SOURCE = "(no source)";

/** The facet list the menu should show: distinct real tools, sorted, plus "(no source)" if earned. */
function sourceFacets(events: Array<{ sources?: string[] }>): string[] {
  const set = new Set<string>();
  let hasNone = false;
  for (const e of events) {
    const real = (e.sources ?? []).filter((s) => s && s !== "unknown source");
    if (real.length) for (const s of real) set.add(s);
    else hasNone = true;
  }
  const list = [...set].sort((a, b) => a.localeCompare(b));
  if (hasNone) list.push(NO_SOURCE);
  return list;
}

/**
 * How many events survive when `hidden` sources are unchecked.
 *
 * An event goes only when EVERY tool that saw it is unchecked. That rule is the whole point: an
 * event corroborated by Suricata and CrowdStrike must not vanish because the analyst set Suricata
 * aside — hiding one tool would then silently drop evidence two tools agreed on.
 */
function survivorCount(events: Array<{ sources?: string[] }>, hidden: Set<string>): number {
  return events.filter((e) => {
    const real = (e.sources ?? []).filter((s) => s && s !== "unknown source");
    if (!real.length) return !hidden.has(NO_SOURCE);
    return real.some((s) => !hidden.has(s));
  }).length;
}

/** `#timelineCount` renders "(N events)" unfiltered and "(N of M events)" once anything filters. */
async function timelineTotals(page: Page): Promise<{ shown: number; total: number }> {
  const raw = (await page.locator("#timelineCount").textContent()) ?? "";
  const filtered = raw.match(/(\d+)\s+of\s+(\d+)\s+events/);
  if (filtered) return { shown: Number(filtered[1]), total: Number(filtered[2]) };
  const plain = raw.match(/(\d+)\s+events?/);
  const n = Number(plain?.[1] ?? -1);
  return { shown: n, total: n };
}

test("US-053: the Sources menu lists the real tools, and unchecking one hides its events", async ({
  page,
  demoCase,
}) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);
  await expect(page.locator("#sec-timeline .ev-row").first()).toBeAttached({ timeout: 30_000 });
  await revealSections(page, "sec-timeline");

  const events = await timelineOf(page, demoCase);
  const facets = sourceFacets(events);
  expect(facets.length, "the seeded case must span several tools for this to mean anything").toBeGreaterThan(
    1,
  );

  await page.locator("#srcFilterBtn").click();
  const menu = page.locator("#srcFilterMenu");
  await expect(menu).toBeVisible();

  // "Sources menu lists distinct sources" — asserted as an exact set. A near-miss (a tool missing,
  // or one listed twice because a case-difference slipped through) is precisely the bug that makes
  // an analyst believe they have filtered on everything when one tool is unreachable.
  const labels = await menu.locator(".src-item span").allTextContents();
  expect(labels.map((s) => s.trim())).toEqual(facets);

  const before = await timelineTotals(page);
  expect(before.shown, "the unfiltered count comes from the case, not a placeholder").toBe(events.length);

  // Pick a tool whose removal actually changes the view — for a tool that only ever co-signs other
  // tools' events the correct answer is "nothing disappears", which would prove nothing here.
  const target = facets.find((s) => survivorCount(events, new Set([s])) < events.length);
  expect(target, "no single source removes any event; the filter cannot be demonstrated").toBeTruthy();
  const expected = survivorCount(events, new Set([target as string]));

  await menu.locator(`.src-filter[value="${target}"]`).uncheck();
  await expect.poll(async () => (await timelineTotals(page)).shown, { timeout: 15_000 }).toBe(expected);
  // The denominator must stay the full case: "12 of 58" tells the analyst they are looking at a
  // subset, where a bare "12" reads as the whole investigation.
  expect((await timelineTotals(page)).total).toBe(events.length);

  // "None" then "All" is the escape hatch — an analyst who has unchecked their way into an empty
  // timeline needs one click back, not to remember what they turned off.
  await menu.locator("[data-src-none]").click();
  await expect(page.locator("#forensicTimeline")).toContainText("No events match the current filters.");

  await menu.locator("[data-src-all]").click();
  await expect.poll(async () => (await timelineTotals(page)).shown, { timeout: 15_000 }).toBe(events.length);
});

test("US-055: a kill-chain tactic expands to exactly the events counted on it", async ({
  page,
  demoCase,
}) => {
  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);
  await expect(page.locator("#killChain .kc-phase").first()).toBeAttached({ timeout: 30_000 });
  await revealSections(page, "sec-kill-chain");

  const phases = page.locator("#killChain .kc-phase");
  expect(await phases.count(), "the strip renders one card per tactic").toBeGreaterThan(1);

  const detail = page.locator("#kcDetail");
  await expect(detail, "nothing is expanded before the analyst asks").toBeHidden();

  const populated = page.locator("#killChain .kc-phase:not(.kc-empty)").first();
  const tactic = ((await populated.locator(".kc-tac").textContent()) ?? "").trim();
  const counted = Number(((await populated.locator(".kc-count").textContent()) ?? "").trim());
  expect(counted, `${tactic} claims no events but is not marked empty`).toBeGreaterThan(0);

  await populated.click();
  await expect(detail).toBeVisible();
  await expect(detail.locator(".kc-detail-head")).toContainText(tactic);

  // THE CLAIM. The number on the card is how an analyst decides which phase to look at; if the
  // expansion shows a different set, that number was a lie and the phase they skipped may be the
  // one that mattered.
  await expect(detail.locator(".kc-event-row")).toHaveCount(counted);

  // Clicking the open tactic closes it — the strip is a toggle, so there is a way back to the
  // overview without reloading the case.
  await populated.click();
  await expect(detail).toBeHidden();

  // A tactic with no events is inert rather than expanding to an empty box that reads as a
  // rendering failure.
  const empty = page.locator("#killChain .kc-phase.kc-empty").first();
  if (await empty.count()) {
    await empty.click();
    await expect(detail).toBeHidden();
  }
});

test("US-183: the IOC panel pages a long list while keeping totals and the case", async ({
  page,
  demoCase,
}) => {
  // The seeded case has too few IOCs to page, so add enough to cross the smallest page size. How
  // many is DERIVED from the case rather than assumed: a hardcoded 40 passed its own setup
  // assertion while leaving the list one short of a second page, and the spec then failed against a
  // perfectly working pager.
  //
  // Values come from 192.0.2.0/24 (RFC 5737 TEST-NET-1), reserved for documentation and not
  // routable — nothing here can resolve to a real host even if something later tried to look one
  // up. Creation is also the one IOC route that calls autoEnrichIfEnabled, and no enrichment
  // provider is configured in this harness (enrichment.spec.ts pins that), so nothing is sent out.
  const pageSize = 50;
  const target = pageSize + 7; // a short second page, so a slice-off-by-one shows up as a count
  const state = (await (await page.request.get(`/cases/${demoCase}/state`)).json()) as {
    iocs?: unknown[];
  };
  const seeded = (state.iocs ?? []).length;
  const filler = target - seeded;
  expect(filler, "the seeded case already fills a page; pick a larger target").toBeGreaterThan(0);
  for (let i = 1; i <= filler; i++) {
    const res = await page.request.post(`/cases/${demoCase}/iocs`, {
      data: { type: "ip", value: `192.0.2.${i}`, note: "e2e pagination filler" },
    });
    expect(res.status(), await res.text()).toBe(201);
  }

  await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);
  await expect(page.locator("#iocs .ioc-row").first()).toBeAttached({ timeout: 30_000 });
  await revealSections(page, "sec-iocs");

  // The panel opens with three noise lenses on ("Signal only", "Hide FP/no-intel", "Hide OS system
  // paths"), so what it shows by default is a triage subset, not the case's IOCs. Widening to
  // everything is the first thing an analyst browsing the full set does — and it is what makes the
  // counts below mean "every IOC" rather than "every IOC that survived three filters".
  await page.locator("#iocSignalBtn").click();
  await expect(page.locator("#iocSignalBtn")).not.toHaveClass(/\bactive\b/);
  await page.locator("#iocHideNoiseChk").uncheck();
  await page.locator("#iocHideSysPathsChk").uncheck();

  const header = page.locator("#iocs .ioc-header-row");
  const total = Number((((await header.textContent()) ?? "").match(/(\d+)\s+IOCs?/) ?? [])[1]);
  expect(total, "the panel must show every IOC the case holds").toBe(target);

  // The default page size holds the whole list, so there is no pager to speak of yet — asserting
  // that first is what makes the pager's later appearance meaningful rather than incidental.
  await expect(page.locator("#iocs .tl-page-bar")).toHaveCount(0);

  await page.locator("#iocs .tl-pagesize-sel").selectOption(String(pageSize));

  const bar = page.locator("#iocs .tl-page-bar");
  await expect(bar).toBeVisible();
  await expect(bar.locator(".tl-page-info")).toHaveText(`1–${pageSize} of ${total}`);
  await expect(page.locator("#iocs .ioc-row")).toHaveCount(pageSize);

  await bar.locator('[data-act="iocPageNext"]').click();
  const remainder = total - pageSize;
  await expect(bar.locator(".tl-page-info")).toHaveText(`${pageSize + 1}–${total} of ${total}`);
  await expect(page.locator("#iocs .ioc-row")).toHaveCount(remainder);
  // Last page: there is nothing after it, and the control has to say so rather than paging into
  // an empty list.
  await expect(bar.locator('[data-act="iocPageNext"]')).toBeDisabled();

  // "without losing the selected case state" — the pager is client-side, so the case must still be
  // the one under investigation, not reset by a navigation.
  expect(new URL(page.url()).searchParams.get("caseId")).toBe(demoCase);
  await expect(page.locator("#sec-timeline .ev-row").first()).toBeAttached();

  // "keeps filters and totals coherent": filtering to the added block leaves fewer than one page,
  // so the pager must retire itself and the header must show the subset against the true total. A
  // pager left behind on a one-page result is how an analyst concludes there are more IOCs to see.
  // The filter bar is revealed by "/", the shortcut the app documents (see timeline.spec.ts).
  await page.locator("#main").click({ position: { x: 5, y: 5 } });
  await page.keyboard.press("/");
  await expect(page.locator("#globalSearch")).toBeFocused();
  await page.locator("#globalSearch").fill("192.0.2.");
  await expect(page.locator("#iocs .ioc-row")).toHaveCount(filler);
  await expect(header).toContainText(`${filler} of ${total} IOCs shown`);
  await expect(page.locator("#iocs .tl-page-bar")).toHaveCount(0);

  await page.locator("#globalSearch").fill("");
  await expect(page.locator("#iocs .tl-page-bar")).toBeVisible();
});
