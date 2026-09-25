import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import type { TimelineViewApi } from "./dashboardApi.js";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// #1652. The forensic timeline sent the analyst back to page 1 whenever anything re-drew it: a
// websocket state push (an import sends one after every artifact), a promote from the
// super-timeline, a star. renderTimelineEvents reset the page on EVERY call unless the caller set
// _tlKeepPage, which only the pager buttons and a jump did.
//
// The rule now is the one #1649 gave the IOC pager: the page resets only when what the analyst
// filters or orders the timeline on changes (or the case changes). A refresh keeps the page,
// clamped into range if the list shrank.

/** Everything the forensic timeline filters or orders on — its identity, not today's data. */
interface TimelineFilterInputs {
  caseId: string;
  scope: { start: string | null; end: string | null } | null;
  severities: string[];
  eventIds: string[] | null;
  starredOnly: boolean;
  search: string;
  excludeTerms: readonly string[];
  from: string | null;
  to: string | null;
  hiddenSources: string[];
  hiddenOrigins: string[];
  hiddenHosts: string[];
  corroboration: number;
  minSeverity?: string | null;
  sortKey: string;
  sortDir: string;
  pageSize: number;
}

interface PageInputs {
  page: number;
  pageSize: number;
  total: number;
  key: string;
  lastKey: string | null;
  keep?: boolean;
}

interface TimelinePageApi {
  timelineFilterKey(f: TimelineFilterInputs): string;
  resolveTimelinePage(p: PageInputs): { page: number; totalPages: number; start: number; end: number };
}

const tl = loadDashboardModule<TimelinePageApi>("dashboard-timeline-display.js", ["dashboard-escape.js"], {
  document: { getElementById: () => null, querySelectorAll: () => [] },
  localStorage: { getItem: () => null, setItem: () => {} },
  DfirState: { lastState: () => null, lastFt: () => [] },
});

const base: TimelineFilterInputs = {
  caseId: "case-a",
  scope: { start: null, end: null },
  severities: ["Critical", "High", "Info", "Low", "Medium"],
  eventIds: null,
  starredOnly: false,
  search: "",
  excludeTerms: [],
  from: null,
  to: null,
  hiddenSources: [],
  hiddenOrigins: [],
  hiddenHosts: [],
  corroboration: 0,
  minSeverity: null,
  sortKey: "date",
  sortDir: "asc",
  pageSize: 50,
};

describe("resolveTimelinePage — which page a render lands on (#1652)", () => {
  const key = tl.timelineFilterKey(base);

  it("keeps page 3 across a refresh that leaves the filters alone", () => {
    expect(tl.resolveTimelinePage({ page: 2, pageSize: 50, total: 180, key, lastKey: key })).toEqual({
      page: 2,
      totalPages: 4,
      start: 100,
      end: 150,
    });
  });

  it("keeps the page when a refresh ADDS events — an import landing while the analyst pages", () => {
    expect(tl.resolveTimelinePage({ page: 1, pageSize: 50, total: 400, key, lastKey: key }).page).toBe(1);
  });

  it("goes back to page 1 when a filter changed", () => {
    const next = tl.timelineFilterKey({ ...base, search: "mimikatz" });
    expect(tl.resolveTimelinePage({ page: 2, pageSize: 50, total: 180, key: next, lastKey: key })).toEqual({
      page: 0,
      totalPages: 4,
      start: 0,
      end: 50,
    });
  });

  it("starts on page 1 on the first render, when there is no previous key", () => {
    expect(tl.resolveTimelinePage({ page: 2, pageSize: 50, total: 180, key, lastKey: null }).page).toBe(0);
  });

  it("clamps to the last page when a refresh shrinks the list", () => {
    expect(tl.resolveTimelinePage({ page: 3, pageSize: 50, total: 57, key, lastKey: key })).toEqual({
      page: 1,
      totalPages: 2,
      start: 50,
      end: 57,
    });
  });

  it("shows one empty page, not a negative one, when nothing is left", () => {
    expect(tl.resolveTimelinePage({ page: 1, pageSize: 50, total: 0, key, lastKey: key })).toEqual({
      page: 0,
      totalPages: 1,
      start: 0,
      end: 0,
    });
  });

  it("treats page size 0 as All — one page holding everything", () => {
    expect(tl.resolveTimelinePage({ page: 2, pageSize: 0, total: 57, key, lastKey: key })).toEqual({
      page: 0,
      totalPages: 1,
      start: 0,
      end: 57,
    });
  });

  it("reads a garbage page as page 1 rather than a negative slice", () => {
    expect(tl.resolveTimelinePage({ page: -4, pageSize: 50, total: 57, key, lastKey: key }).page).toBe(0);
    expect(
      tl.resolveTimelinePage({ page: Number.NaN, pageSize: 50, total: 57, key, lastKey: key }).page,
    ).toBe(0);
  });

  it("keeps a page a caller chose even though the filters changed, when it says keep (a jump)", () => {
    // jumpToEvent clears the filters that hid the event, then picks the page it lands on.
    const next = tl.timelineFilterKey({ ...base, search: "", starredOnly: true });
    expect(
      tl.resolveTimelinePage({ page: 2, pageSize: 50, total: 180, key: next, lastKey: key, keep: true }).page,
    ).toBe(2);
  });

  it("still clamps a kept page into range", () => {
    const r = tl.resolveTimelinePage({ page: 9, pageSize: 50, total: 57, key, lastKey: null, keep: true });
    expect(r.page).toBe(1);
  });
});

describe("timelineFilterKey — what counts as a filter change (#1652)", () => {
  const key = tl.timelineFilterKey(base);

  it.each<[string, Partial<TimelineFilterInputs>]>([
    ["the case", { caseId: "case-b" }],
    ["the scope window", { scope: { start: "2026-01-01T00:00:00Z", end: null } }],
    ["the severity boxes", { severities: ["Critical", "High"] }],
    ["the event-id filter", { eventIds: ["e1", "e2"] }],
    ["an empty event-id filter vs none", { eventIds: [] }],
    ["starred-only", { starredOnly: true }],
    ["the search text", { search: "evil" }],
    ["the exclude terms", { excludeTerms: ["noise"] }],
    ["the from time", { from: "2026-01-01T00:00:00Z" }],
    ["the to time", { to: "2026-01-02T00:00:00Z" }],
    ["the hidden sources", { hiddenSources: ["EvtxECmd"] }],
    ["the hidden origins", { hiddenOrigins: ["screenshot"] }],
    ["the hidden hosts", { hiddenHosts: ["ws01"] }],
    ["the corroboration lens", { corroboration: 2 }],
    ["the view's severity floor", { minSeverity: "High" }],
    ["the sort column", { sortKey: "severity" }],
    ["the sort direction", { sortDir: "desc" }],
    ["the page size", { pageSize: 100 }],
  ])("changes with %s", (_label, change) => {
    expect(tl.timelineFilterKey({ ...base, ...change })).not.toBe(key);
  });

  it("changes when the id filter swaps to a different set of the same size", () => {
    expect(tl.timelineFilterKey({ ...base, eventIds: ["a", "b"] })).not.toBe(
      tl.timelineFilterKey({ ...base, eventIds: ["a", "c"] }),
    );
  });

  it("does not depend on the order the analyst chose things in", () => {
    expect(
      tl.timelineFilterKey({
        ...base,
        severities: ["High", "Critical"],
        eventIds: ["2", "1"],
        excludeTerms: ["b", "a"],
        hiddenSources: ["y", "x"],
        hiddenOrigins: ["q", "p"],
        hiddenHosts: ["h2", "h1"],
      }),
    ).toBe(
      tl.timelineFilterKey({
        ...base,
        severities: ["Critical", "High"],
        eventIds: ["1", "2"],
        excludeTerms: ["a", "b"],
        hiddenSources: ["x", "y"],
        hiddenOrigins: ["p", "q"],
        hiddenHosts: ["h1", "h2"],
      }),
    );
  });

  it("cannot be forged by separator characters inside a value", () => {
    expect(tl.timelineFilterKey({ ...base, excludeTerms: ["a,b"] })).not.toBe(
      tl.timelineFilterKey({ ...base, excludeTerms: ["a", "b"] }),
    );
    expect(tl.timelineFilterKey({ ...base, search: 'x","case-b' })).not.toBe(
      tl.timelineFilterKey({ ...base, search: "x", caseId: "case-b" }),
    );
  });

  it("reads a missing scope or view floor as its no-filter default", () => {
    const partial = { ...base, scope: null } as Partial<TimelineFilterInputs>;
    delete partial.minSeverity;
    expect(tl.timelineFilterKey(partial as TimelineFilterInputs)).toBe(key);
  });
});

describe("the id filter a key reads is its full membership (#1652)", () => {
  const load = () =>
    loadDashboardModule<TimelineViewApi>("dashboard-timeline-view.js", ["dashboard-state.js"])
      .DfirTimelineView;

  it("is null with no id filter, and a sorted copy with one", () => {
    const view = load();
    view.wire({});
    expect(view.eventIdNames()).toBeNull();
    view.filterToEventIds(["e2", "e1"], "bucket");
    expect(view.eventIdNames()).toEqual(["e1", "e2"]);
  });

  it("hands out a copy, so a caller cannot edit the filter through it", () => {
    const view = load();
    view.wire({});
    view.filterToEventIds(["e1"], "bucket");
    view.eventIdNames()!.push("e9");
    expect(view.hasEventId("e9")).toBe(false);
  });
});

describe("renderTimelineEvents no longer resets the page on every call (#1652)", () => {
  const DASHBOARD = new URL("../../../public/dashboard.html", import.meta.url);
  const body = async () => {
    const html = await readFile(DASHBOARD, "utf8");
    const start = html.indexOf("    function renderTimelineEvents(");
    expect(start, "renderTimelineEvents must still be declared inline").toBeGreaterThan(0);
    return html.slice(start, html.indexOf("\n    }\n", start));
  };

  it("routes the page through resolveTimelinePage with a filter key", async () => {
    const src = await body();
    expect(src).toContain("resolveTimelinePage(");
    expect(src).toContain("timelineFilterKey(");
  });

  it("feeds the key every filter the render applies", async () => {
    const src = await body();
    const call = src.slice(src.indexOf("timelineFilterKey("), src.indexOf("resolveTimelinePage("));
    for (const read of [
      'getElementById("caseId")',
      "DfirScope.get()",
      "activeSevs",
      "eventIdNames()",
      "starredOnly()",
      "search()",
      "excludeTerms()",
      "from()",
      "to()",
      "DfirFacets.sources.hiddenNames()",
      "DfirFacets.origins.hiddenNames()",
      "DfirFacets.hosts.hiddenNames()",
      "corrobTimeline()",
      "minSeverity",
      "timelineSort",
      "tlPageSize",
    ]) {
      expect(call, `the key must read ${read}`).toContain(read);
    }
  });

  it("has no unconditional reset to page 1 left in it", async () => {
    // The pre-#1652 line was `if (!_tlKeepPage) tlPage = 0;` — true for every caller but the pager.
    expect(await body()).not.toMatch(/\btlPage\s*=\s*0\b/);
  });
});
