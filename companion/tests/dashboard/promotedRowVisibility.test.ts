import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// A promoted row is visible in the forensic timeline panel, whatever its severity (#1554).
//
// THE BUG THIS PINS. companion/src/analysis/forensicGate.ts keeps a promoted row through the
// server's severity cut on purpose — "the analyst put it here on purpose, and the cut exists to
// keep unreviewed telemetry out, not to remove what an analyst asked to see" (#1432) — and the
// display then dropped it again. On one real case the forensic timeline held 465 rows, 262 of them
// promoted Info rows, and the panel drew 182. The analyst could not find the evidence they had
// asked for, and could not reconcile the count.
//
// Two filters did it, and both are asserted here: the severity legend, whose list had no Info
// entry at all, and the dashboard-view floor, which read `e.severity` and nothing else.

interface Ev {
  id?: string;
  severity: string;
  promotedAt?: string;
}

interface DisplayApi {
  isPromotedEvent(e: Ev | null | undefined): boolean;
  promotedBadge(e: Ev | null | undefined): string;
  promotedKeptCount(
    visible: Ev[] | null,
    activeSevs: Set<string> | null,
    meetsFloor: ((sev: string) => boolean) | null,
  ): number;
  timelineCountLabel(o: {
    total: number;
    totalFiltered: number;
    pageSize: number;
    page: number;
    totalPages: number;
    filtering: boolean;
    promotedKept?: number;
  }): { text: string; title: string };
}

interface PresetApi {
  viewMeetsMinSev(sev: string, ev?: Ev): boolean;
}

const HTML = new URL("../../../public/dashboard.html", import.meta.url);

function display(): DisplayApi {
  return loadDashboardModule<DisplayApi>("dashboard-timeline-display.js", ["dashboard-escape.js"], {
    document: { getElementById: () => null, querySelectorAll: () => [] },
    localStorage: { getItem: () => null, setItem: () => {} },
    DfirState: { lastState: () => null, lastFt: () => [] },
  });
}

// The view presets read SEV and DfirState.activeView(); both are page globals in the browser.
function presets(minSeverity?: string): PresetApi {
  return loadDashboardModule<PresetApi>("dashboard-view-presets.js", ["dashboard-escape.js"], {
    document: { getElementById: () => ({ value: "" }), addEventListener: () => {} },
    localStorage: { getItem: () => null, setItem: () => {} },
    SEV: ["Critical", "High", "Medium", "Low", "Info"],
    DASHBOARD_VIEWS: [],
    SECTION_DEFS: [],
    DfirState: {
      activeView: () => (minSeverity ? { id: "lead", name: "Lead", filters: { minSeverity } } : null),
      lastState: () => null,
      setActiveView: () => {},
    },
    // isPromotedEvent is a sibling module's published name. In the browser it resolves through the
    // shared global lexical environment at call time; here it has to actually be present, because
    // its absence is what the guard in viewMeetsMinSev is for and is covered separately below.
    isPromotedEvent: (e: Ev | null | undefined) => !!(e && e.promotedAt),
  });
}

const PROMOTED_INFO: Ev = { id: "e1", severity: "Info", promotedAt: "2026-09-20T11:04:05.000Z" };
const PLAIN_INFO: Ev = { id: "e2", severity: "Info" };
const HIGH: Ev = { id: "e3", severity: "High" };

describe("the promotion stamp the display had never read", () => {
  it("is what isPromotedEvent answers on, and nothing else", () => {
    const api = display();
    expect(api.isPromotedEvent(PROMOTED_INFO)).toBe(true);
    expect(api.isPromotedEvent(PLAIN_INFO)).toBe(false);
    expect(api.isPromotedEvent(null)).toBe(false);
    expect(api.isPromotedEvent(undefined)).toBe(false);
    // An empty stamp is not a stamp. The server writes an ISO timestamp or writes nothing.
    expect(api.isPromotedEvent({ severity: "Info", promotedAt: "" })).toBe(false);
  });
});

describe("the compact row's promoted cue", () => {
  it("is the super-timeline's own wording, not a second vocabulary for one idea", async () => {
    const api = display();
    const badge = api.promotedBadge(PROMOTED_INFO);
    expect(badge).toContain("✓ Promoted");
    // The same string the super-timeline panel already shows for the same fact.
    const st = await readFile(
      new URL("../../../public/js/dashboard-super-timeline.js", import.meta.url),
      "utf8",
    );
    expect(st).toContain("✓ Promoted");
  });

  it("carries the meaning in the word, never in the colour alone", () => {
    const badge = display().promotedBadge(PROMOTED_INFO);
    // Strip every tag and attribute: what is left is what a reader with no colour perception gets.
    const text = badge.replace(/<[^>]*>/g, "").trim();
    expect(text).toBe("✓ Promoted");
  });

  it("says when, in the title", () => {
    expect(display().promotedBadge(PROMOTED_INFO)).toContain("2026-09-20 11:04:05");
  });

  // The stamp is written by the server, but it lands in an ATTRIBUTE, and the one rule this repo
  // does not bend is that nothing reaches markup unescaped. A short value is the case that matters:
  // the 19-character slice happens to cut a long injection off, which is luck, not a defence.
  it("escapes the stamp into the title attribute", () => {
    const hostile = display().promotedBadge({ severity: "Info", promotedAt: '" onload="x' });
    expect(hostile).not.toContain('onload="x');
    expect(hostile).toContain("&quot;");
  });

  it("is nothing at all for a row nobody promoted", () => {
    const api = display();
    expect(api.promotedBadge(PLAIN_INFO)).toBe("");
    expect(api.promotedBadge(HIGH)).toBe("");
  });
});

describe("the severity legend in dashboard.html", () => {
  it("no longer claims the forensic timeline holds no Info rows", async () => {
    const html = await readFile(HTML, "utf8");
    expect(
      html,
      "the premise behind the missing Info entry was documented and false — a promoted row is " +
        "exempt from the server's cut, so Info rows do reach the forensic timeline",
    ).not.toContain("so the forensic timeline never actually holds any");
  });

  it("filters on a list that includes Info", async () => {
    const html = await readFile(HTML, "utf8");
    expect(html).toContain("const allSevs = ['Critical', 'High', 'Medium', 'Low', 'Info'];");
  });

  it("offers the analyst an Info control, ticked, like every other severity", async () => {
    const html = await readFile(HTML, "utf8");
    const legend = html.slice(html.indexOf('class="sev-legend"'), html.indexOf('class="src-legend"'));
    expect(legend).toContain('class="sev-filter" value="Info" checked');
    for (const sev of ["Critical", "High", "Medium", "Low", "Info"]) {
      expect(legend, `${sev} is missing from the legend`).toContain(`value="${sev}" checked`);
    }
  });

  it("lets a promoted row through even when its severity box is unticked", async () => {
    const html = await readFile(HTML, "utf8");
    expect(html).toContain(
      "let visible = filtering ? ft.filter(e => activeSevs.has(e.severity) || isPromotedEvent(e)) : ft;",
    );
  });

  it("hands the event, not only its severity, to the dashboard-view floor", async () => {
    const html = await readFile(HTML, "utf8");
    expect(html).toContain("visible.filter(e => viewMeetsMinSev(e.severity, e))");
  });

  it("puts the promoted badge in the compact row, outside the collapsed details panel", async () => {
    const html = await readFile(HTML, "utf8");
    expect(html).toContain('<div class="ev-col-content">${promotedBadge(e) || ""}');
  });
});

describe("the dashboard-view severity floor", () => {
  it("keeps a promoted Info row under a High floor, exactly as the server does", () => {
    expect(presets("High").viewMeetsMinSev("Info", PROMOTED_INFO)).toBe(true);
  });

  it("still drops an Info row nobody promoted", () => {
    expect(presets("High").viewMeetsMinSev("Info", PLAIN_INFO)).toBe(false);
  });

  it("leaves the findings list — which passes no event — exactly as it was", () => {
    expect(presets("High").viewMeetsMinSev("Info")).toBe(false);
    expect(presets("High").viewMeetsMinSev("Critical")).toBe(true);
    expect(presets().viewMeetsMinSev("Info")).toBe(true);
  });

  it("cites the server rule it mirrors, so the two stay recognisably one rule", async () => {
    const src = await readFile(
      new URL("../../../public/js/dashboard-view-presets.js", import.meta.url),
      "utf8",
    );
    expect(src).toContain("forensicGate.ts");
    const gate = await readFile(new URL("../../src/analysis/forensicGate.ts", import.meta.url), "utf8");
    expect(gate, "the server still applies the rule the display now mirrors").toContain("e.promotedAt ||");
  });
});

describe("the count label", () => {
  const api = display();

  it("says how many rows the filters are holding back, not just how many are drawn", () => {
    const lbl = api.timelineCountLabel({
      total: 465,
      totalFiltered: 203,
      pageSize: 0,
      page: 0,
      totalPages: 1,
      filtering: true,
    });
    expect(lbl.text).toBe("(203 of 465 events, 262 hidden by filters)");
    expect(lbl.title).toContain("The filters above are hiding 262 of this case's 465");
    expect(lbl.title).toContain("still in the record");
  });

  it("explains the rows a severity filter did not manage to hide", () => {
    const lbl = api.timelineCountLabel({
      total: 465,
      totalFiltered: 265,
      pageSize: 0,
      page: 0,
      totalPages: 1,
      filtering: true,
      promotedKept: 262,
    });
    expect(lbl.text).toBe("(265 of 465 events, 200 hidden by filters, 262 promoted kept)");
    expect(lbl.title).toContain("promotion stamp");
  });

  it("keeps the page suffix readable alongside the new clauses", () => {
    const lbl = api.timelineCountLabel({
      total: 465,
      totalFiltered: 265,
      pageSize: 100,
      page: 0,
      totalPages: 3,
      filtering: true,
      promotedKept: 262,
    });
    expect(lbl.text).toBe("(265 of 465 events, 200 hidden by filters, 262 promoted kept — page 1 of 3)");
  });

  it("says nothing extra when nothing is hidden", () => {
    expect(
      api.timelineCountLabel({
        total: 465,
        totalFiltered: 465,
        pageSize: 0,
        page: 0,
        totalPages: 1,
        filtering: false,
      }).text,
    ).toBe("(465 events)");
    // Filtering that happens to hide nothing must not invent a "0 hidden" clause.
    expect(
      api.timelineCountLabel({
        total: 12,
        totalFiltered: 12,
        pageSize: 0,
        page: 0,
        totalPages: 1,
        filtering: true,
      }).text,
    ).toBe("(12 of 12 events)");
  });
});

describe("promotedKeptCount", () => {
  const api = display();

  it("counts only the rows the analyst's own filters would have dropped", () => {
    const rows = [
      PROMOTED_INFO,
      PLAIN_INFO,
      HIGH,
      { id: "e4", severity: "High", promotedAt: "2026-09-20T00:00:00Z" },
    ];
    // Legend showing High only: the promoted Info row rode through, the promoted High row did not.
    expect(api.promotedKeptCount(rows, new Set(["High"]), null)).toBe(1);
  });

  it("counts a row the view floor would have dropped too", () => {
    const meetsHigh = (sev: string) => sev === "High" || sev === "Critical";
    expect(api.promotedKeptCount([PROMOTED_INFO], null, meetsHigh)).toBe(1);
    expect(api.promotedKeptCount([{ severity: "High", promotedAt: "x" }], null, meetsHigh)).toBe(0);
  });

  it("counts nothing when no filter is in force", () => {
    expect(api.promotedKeptCount([PROMOTED_INFO, PLAIN_INFO], null, null)).toBe(0);
    expect(api.promotedKeptCount(null, null, null)).toBe(0);
  });
});
