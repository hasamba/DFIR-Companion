import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// #1916: a 70,000-event case read "(10000 events — page 1 of 200)". The state reply carried the real
// total and a cursor; the label printed the loaded batch as if it were the whole case, and nothing
// on screen said more existed. An analyst could take the first batch for the record.

interface DisplayApi {
  timelineCountLabel(o: {
    total: number;
    totalFiltered: number;
    pageSize: number;
    page: number;
    totalPages: number;
    filtering: boolean;
  }): { text: string; title: string };
  timelineMoreMatchesBar(): string;
}

function display(state: unknown, extra: Record<string, unknown> = {}): DisplayApi {
  return loadDashboardModule<DisplayApi>("dashboard-timeline-display.js", ["dashboard-escape.js"], {
    document: { getElementById: () => null, querySelectorAll: () => [] },
    localStorage: { getItem: () => null, setItem: () => {} },
    DfirState: { lastState: () => state, lastFt: () => [] },
    ...extra,
  });
}

const rows = (n: number) => Array.from({ length: n }, (_, i) => ({ id: `e${i}` }));
const BIG = {
  caseId: "big",
  forensicTimeline: rows(100),
  forensicTimelineTotal: 700,
  forensicTimelineNextCursor: 99,
};
const label = (api: DisplayApi, o: Partial<Parameters<DisplayApi["timelineCountLabel"]>[0]> = {}) =>
  api.timelineCountLabel({
    total: 100,
    totalFiltered: 100,
    pageSize: 50,
    page: 0,
    totalPages: 2,
    filtering: false,
    ...o,
  });

describe("the timeline count on a case larger than one batch (#1916)", () => {
  it("states the case's real size and how much of it is loaded", () => {
    const lbl = label(display(BIG));
    expect(lbl.text).toBe("(700 events, first 100 loaded — page 1 of 2)");
    expect(lbl.title).toContain("This case holds 700 forensic-timeline events");
    expect(lbl.title).toContain("Load more events");
  });

  it("says a filtered count is over the loaded events, and names the case total", () => {
    const lbl = label(display(BIG), { totalFiltered: 40, filtering: true, pageSize: 0, totalPages: 1 });
    expect(lbl.text).toBe("(40 of 100 loaded events, 60 hidden by filters; 700 in case)");
    expect(lbl.title).toContain("hiding 60 of the 100 loaded events");
  });

  it("reads exactly as before when the whole case is loaded", () => {
    const whole = { ...BIG, forensicTimelineTotal: 100, forensicTimelineNextCursor: null };
    expect(label(display(whole)).text).toBe("(100 events — page 1 of 2)");
    expect(label(display(null)).text).toBe("(100 events — page 1 of 2)");
  });

  it("leaves a search floor to its own wording", () => {
    const floor = { ...BIG, forensicTimelineTotalIsLowerBound: true };
    expect(label(display(floor)).text).toBe("(100+ events — page 1 of 2)");
  });
});

describe("the Load more events bar (#1916)", () => {
  it("offers the next batch while the case holds more", () => {
    const bar = display(BIG, {
      hasMoreEvents: () => true,
      loadingMoreEvents: () => false,
    }).timelineMoreMatchesBar();
    expect(bar).toContain('data-act="tlLoadMoreEvents"');
    expect(bar).toContain("Showing the first 100 of 700 events.");
    expect(bar).not.toContain("disabled");
  });

  it("shows a press in flight as busy", () => {
    const bar = display(BIG, {
      hasMoreEvents: () => true,
      loadingMoreEvents: () => true,
    }).timelineMoreMatchesBar();
    expect(bar).toContain("disabled");
    expect(bar).toContain("Loading…");
  });

  it("is absent when everything is loaded", () => {
    expect(display(BIG, { hasMoreEvents: () => false }).timelineMoreMatchesBar()).toBe("");
  });

  it("keeps the search bar first: a truncated search pages through its own control", () => {
    const bar = display(BIG, {
      hasMoreMatches: () => true,
      hasMoreEvents: () => true,
    }).timelineMoreMatchesBar();
    expect(bar).toContain('data-act="tlLoadMoreMatches"');
    expect(bar).not.toContain("tlLoadMoreEvents");
  });

  it("is wired to a click handler and drawn under an empty filter result too", async () => {
    const act = await readFile(new URL("../../../public/js/dashboard-data-act.js", import.meta.url), "utf8");
    expect(act).toContain("tlLoadMoreEvents: () => {");
    const html = await readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
    expect(html).toContain(
      `No events match the current filters.</div>" + (typeof timelineMoreMatchesBar === "function" ? timelineMoreMatchesBar() : "")`,
    );
  });
});
