import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// #1658. jumpToEvent picked the page from the event's place in the WHOLE timeline, but the
// renderer also drops rows below the dashboard view's severity floor and rows that fail the
// corroboration lens — and the jump's filter reset clears neither. Under either lens the event's
// rendered place is earlier than its raw place, so the jump opened a later page than the one that
// holds it. When a lens hid the event outright, the jump cleared the analyst's filters and landed
// on an unrelated page.

interface Ev {
  id: string;
  severity: string;
  sources?: string[];
  promoted?: boolean;
}

interface JumpSandbox {
  jumpToEvent(id: string): void;
  timelineJumpPage(sorted: Ev[], id: string, pageSize: number, keeps?: ((e: Ev) => boolean) | null): number;
  tlPage: number;
  _tlKeepPage: boolean;
}

const SEV = ["Critical", "High", "Medium", "Low", "Info"];

interface Setup {
  events: Ev[];
  pageSize?: number;
  minSeverity?: string | null;
  corroboration?: number;
}

function setup(o: Setup) {
  const calls = { resets: 0, renders: [] as number[], toasts: [] as string[] };
  const view = o.minSeverity ? { name: "Executive", filters: { minSeverity: o.minSeverity } } : null;
  const noop = () => {};
  const facet = { showAll: () => calls.resets++, matcher: () => ({ has: () => false }) };
  const sb = loadDashboardModule<JumpSandbox>(
    "dashboard-hunts-jumps.js",
    ["dashboard-filters.js", "dashboard-timeline-display.js"],
    {
      document: {
        getElementById: () => null,
        querySelectorAll: () => [],
        createElement: () => ({}),
      },
      localStorage: { getItem: () => null, setItem: noop },
      location: { hash: "" },
      tlPage: 0,
      tlPageSize: o.pageSize ?? 2,
      _tlKeepPage: false,
      _srcMenuSig: "",
      _originMenuSig: "",
      _hostMenuSig: "",
      DfirState: { lastFt: () => o.events, lastState: () => null, activeView: () => view },
      DfirFacets: { sources: facet, origins: facet, hosts: facet },
      DfirTimelineView: { clearFilters: noop, corrobTimeline: () => o.corroboration ?? 0 },
      sortTimelineEvents: (list: Ev[]) => list,
      viewMeetsMinSev: (sev: string, e: Ev) => {
        if (e && e.promoted) return true;
        return !view || SEV.indexOf(sev) <= SEV.indexOf(view.filters.minSeverity);
      },
      renderTimelineEvents: () => calls.renders.push(sb.tlPage),
      showToast: (text: string) => calls.toasts.push(text),
    },
  );
  return { sb, calls };
}

// Six events, two per page. Under a High floor the renderer shows only c, e, f.
const ladder: Ev[] = [
  { id: "a", severity: "Info" },
  { id: "b", severity: "Info" },
  { id: "c", severity: "High" },
  { id: "d", severity: "Info" },
  { id: "e", severity: "High" },
  { id: "f", severity: "High" },
];

describe("jumpToEvent under a dashboard view's severity floor (#1658)", () => {
  it("opens the page the event is on in the list the renderer shows", () => {
    const { sb, calls } = setup({ events: ladder, minSeverity: "High" });
    sb.jumpToEvent("f");
    // Rendered list c, e, f → f is row 3 → page index 1. The raw index 5 gave page index 2.
    expect(calls.renders).toEqual([1]);
  });

  it("keeps the old page arithmetic when no floor is set", () => {
    const { sb, calls } = setup({ events: ladder });
    sb.jumpToEvent("f");
    expect(calls.renders).toEqual([2]);
  });

  it("counts a promoted row the floor lets through", () => {
    const events = ladder.map((e) => (e.id === "a" ? { ...e, promoted: true } : e));
    const { sb, calls } = setup({ events, minSeverity: "High" });
    sb.jumpToEvent("f");
    // Rendered list a, c, e, f → f is row 4 → page index 1.
    expect(calls.renders).toEqual([1]);
  });

  it("refuses, and says why, when the floor hides the event", () => {
    const { sb, calls } = setup({ events: ladder, minSeverity: "High" });
    sb.tlPage = 1;
    sb.jumpToEvent("d");
    expect(calls.renders).toEqual([]); // no re-render onto an unrelated page
    expect(calls.resets).toBe(0); // the analyst's filters are left alone
    expect(sb.tlPage).toBe(1);
    expect(sb._tlKeepPage).toBe(false);
    expect(calls.toasts).toHaveLength(1);
    expect(calls.toasts[0]).toMatch(/Executive/);
    expect(calls.toasts[0]).toMatch(/High/);
  });
});

describe("jumpToEvent under the corroboration lens (#1658)", () => {
  const two = ["EvtxECmd", "Hayabusa"];
  const events: Ev[] = [
    { id: "a", severity: "High", sources: ["EvtxECmd"] },
    { id: "b", severity: "High", sources: ["EvtxECmd"] },
    { id: "c", severity: "High", sources: two },
    { id: "d", severity: "High", sources: ["EvtxECmd"] },
    { id: "e", severity: "High", sources: two },
    { id: "f", severity: "High", sources: two },
  ];

  it("opens the page the event is on once the lens has removed earlier rows", () => {
    const { sb, calls } = setup({ events, corroboration: 2 });
    sb.jumpToEvent("f");
    expect(calls.renders).toEqual([1]);
  });

  it("refuses, and names the lens, when the lens hides the event", () => {
    const { sb, calls } = setup({ events, corroboration: 2 });
    sb.jumpToEvent("d");
    expect(calls.renders).toEqual([]);
    expect(calls.resets).toBe(0);
    expect(calls.toasts).toHaveLength(1);
    expect(calls.toasts[0]).toMatch(/corroborat/i);
  });
});

describe("timelineJumpPage — the page arithmetic (#1658)", () => {
  const { sb } = setup({ events: [] });

  it("is -1 for an event the list does not hold", () => {
    expect(sb.timelineJumpPage(ladder, "zz", 2)).toBe(-1);
  });

  it("is -1 for an event the lens rejects", () => {
    expect(sb.timelineJumpPage(ladder, "d", 2, (e) => e.severity === "High")).toBe(-1);
  });

  it("is 0 for page size 0 (All)", () => {
    expect(sb.timelineJumpPage(ladder, "f", 0)).toBe(0);
  });

  it("matches ids as strings", () => {
    const numeric = [{ id: 7 as unknown as string, severity: "High" }];
    expect(sb.timelineJumpPage(numeric, "7", 2)).toBe(0);
  });
});

describe("the lenses the jump counts are the ones the renderer applies (#1658)", () => {
  // jumpToEvent clears every analyst filter through resetTimelineViewFilters, then counts the two
  // lenses that reset leaves on. If the renderer gains another filter, this list changes, and the
  // jump must either clear it or count it — or it opens the wrong page again.
  it("renderTimelineEvents filters on exactly the known set", async () => {
    const html = await readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
    const start = html.indexOf("    function renderTimelineEvents(");
    const body = html.slice(start, html.indexOf("\n    }\n", start));
    const guards = body
      .split("\n")
      .filter((l) => /visible = [^;]*\.filter\(|visible = filtering \?/.test(l))
      .map(
        (l) => (/^\s*(let visible = filtering|if \((.*?)\) visible)/.exec(l) || [])[2] ?? "severity boxes",
      );
    // Cleared by resetTimelineViewFilters: the severity boxes, id filter, starred, search, exclude
    // terms, time range, and the three facets. Counted by the jump: the corroboration lens and the
    // view floor.
    expect(guards).toEqual([
      "severity boxes",
      "DfirTimelineView.eventIdFilterActive()",
      "DfirTimelineView.starredOnly()",
      "DfirTimelineView.search()",
      "DfirTimelineView.excludeTerms().length",
      "DfirTimelineView.from() || DfirTimelineView.to()",
      "sourceFiltering",
      "originFiltering",
      "hostHidden > 0",
      "DfirTimelineView.corrobTimeline() > 1",
      "viewSevFiltering",
    ]);
    expect(body).toContain("viewMeetsMinSev(e.severity, e)");
    expect(body).toContain(
      "realSourceCount(e.sources, DfirFacets.sources.matcher()) >= DfirTimelineView.corrobTimeline()",
    );
  });
});
