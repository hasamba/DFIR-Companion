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
    promotedKept?: number;
    viewHidden?: number;
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
    expect(lbl.text).toBe("(40 of the first 100 loaded events, 60 hidden by filters; case holds 700)");
    expect(lbl.title).toContain("hiding 60 of the 100 loaded events");
  });

  // #1928: the batch and the case total read as two bare totals one clause apart.
  it("keeps the clause order with paging and a promoted row on a partial case", () => {
    const lbl = label(display(BIG), { totalFiltered: 60, filtering: true, promotedKept: 5 });
    expect(lbl.text).toBe(
      "(60 of the first 100 loaded events, 40 hidden by filters, 5 promoted kept; case holds 700 — page 1 of 2)",
    );
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

// #2468: a cockpit link switches to the view that shows its panel (Lead, Executive …), and those
// views carry a High floor. The timeline then said "13 hidden by filters" and no control on screen
// showed that floor. The label now names the view and its floor, and the tooltip says how to clear it.
describe("the timeline count names a dashboard view's severity floor (#2468)", () => {
  const SMALL = { caseId: "c", forensicTimeline: rows(23), forensicTimelineTotal: 23 };
  const withView = (view: unknown) =>
    display(SMALL, { DfirState: { lastState: () => SMALL, lastFt: () => [], activeView: () => view } });
  const lead = { id: "lead", name: "Lead", filters: { minSeverity: "High" } };
  const filtered = {
    total: 23,
    totalFiltered: 10,
    viewHidden: 13,
    filtering: true,
    pageSize: 0,
    totalPages: 1,
  };

  it("does not name the floor when a search or facet hid the rows and the floor hid none", () => {
    const lbl = label(withView(lead), { ...filtered, viewHidden: 0 });
    expect(lbl.text).toBe("(10 of 23 events, 13 hidden by filters)");
    expect(lbl.title).not.toContain("Lead view");
  });

  it("is passed the floor's own count by the timeline render", async () => {
    const page = await readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
    expect(page).toContain("const viewHidden = preViewFloor - visible.length;");
    expect(page).toContain("totalFiltered, viewHidden, pageSize: tlPageSize");
  });

  it("names the view and its floor when rows are hidden", () => {
    const lbl = label(withView(lead), filtered);
    expect(lbl.text).toBe("(10 of 23 events, 13 hidden by filters (Lead view: High+))");
    expect(lbl.title).toContain("The Lead view shows only High and above");
    expect(lbl.title).toContain("Analyst");
  });

  it("says nothing about a view floor when nothing is hidden", () => {
    const lbl = label(withView(lead), { ...filtered, totalFiltered: 23 });
    expect(lbl.text).not.toContain("Lead view");
    expect(lbl.title).not.toContain("Lead view");
  });

  it("says nothing for a view without a floor, or with no active view", () => {
    for (const view of [{ id: "analyst", name: "Analyst", filters: {} }, null]) {
      const lbl = label(withView(view), filtered);
      expect(lbl.text).toBe("(10 of 23 events, 13 hidden by filters)");
      expect(lbl.title).not.toContain(" view shows only");
    }
  });

  it("works with a state store that has no active-view accessor", () => {
    expect(label(display(SMALL), filtered).text).toBe("(10 of 23 events, 13 hidden by filters)");
  });
});
