import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// #2065. A cockpit stage card (and a Timeline Anomaly bucket, and an Attacker Session card) filters
// the forensic timeline to exactly a set of event ids. The two lenses jumpToEvent respects (#1658)
// — the dashboard view's severity floor and the ⊕ corroboration lens — stay on, so the timeline can
// show "0 of 2" with nothing saying why. The chip keeps the lenses (the #1658 precedent) and names
// what holds each missing row back: the floor, the lens, or the part of the timeline not loaded.

interface Ev {
  id: string;
  severity: string;
  sources?: string[];
  promoted?: boolean;
}

interface ChipSandbox {
  renderEvIdFilterChip(shown: number, total: number): void;
  jumpToEvent(id: string): void;
}

const SEV = ["Critical", "High", "Medium", "Low", "Info"];

interface Setup {
  events: Ev[];
  ids: string[];
  label?: string;
  view?: { name: string; filters: { minSeverity?: string } } | null;
  corroboration?: number;
}

function setup(o: Setup) {
  const chip = { style: { display: "none" }, innerHTML: "" };
  const toasts: string[] = [];
  const view = o.view ?? null;
  const noop = () => {};
  const facet = { showAll: noop, matcher: () => ({ has: () => false }) };
  const idSet = new Set(o.ids);
  const sb = loadDashboardModule<ChipSandbox>(
    "dashboard-hunts-jumps.js",
    ["dashboard-escape.js", "dashboard-filters.js", "dashboard-timeline-display.js"],
    {
      document: {
        getElementById: (id: string) => (id === "evIdFilterChip" ? chip : null),
        querySelectorAll: () => [],
        createElement: () => ({}),
      },
      localStorage: { getItem: () => null, setItem: noop },
      location: { hash: "" },
      tlPage: 0,
      tlPageSize: 50,
      _tlKeepPage: false,
      _srcMenuSig: "",
      _originMenuSig: "",
      _hostMenuSig: "",
      DfirState: { lastFt: () => o.events, lastState: () => null, activeView: () => view },
      DfirFacets: { sources: facet, origins: facet, hosts: facet },
      DfirTimelineView: {
        clearFilters: noop,
        corrobTimeline: () => o.corroboration ?? 0,
        eventIdFilterActive: () => true,
        eventIdCount: () => idSet.size,
        eventIdLabel: () => o.label ?? "",
        eventIdNames: () => [...idSet].sort(),
        hasEventId: (id: string) => idSet.has(String(id)),
      },
      sortTimelineEvents: (list: Ev[]) => list,
      viewMeetsMinSev: (sev: string, e: Ev) => {
        if (e && e.promoted) return true;
        const floor = view && view.filters.minSeverity;
        return !floor || SEV.indexOf(sev) <= SEV.indexOf(floor);
      },
      renderTimelineEvents: noop,
      showToast: (text: string) => toasts.push(text),
    },
  );
  return { sb, chip, toasts };
}

const floorView = { name: "MyView", filters: { minSeverity: "High" } };

describe("the event-id filter chip names what holds rows back (#2065)", () => {
  it("counts rows hidden by the ⊕ corroboration lens", () => {
    const events: Ev[] = [
      { id: "a", severity: "High", sources: ["EvtxECmd"] },
      { id: "b", severity: "High", sources: ["EvtxECmd"] },
    ];
    const { sb, chip } = setup({ events, ids: ["a", "b"], corroboration: 2, label: "Execution stage" });
    sb.renderEvIdFilterChip(0, 2);
    expect(chip.innerHTML).toMatch(/Showing 0 of 2 events/);
    expect(chip.innerHTML).toMatch(/2 hidden by the ⊕ corroboration lens/);
    expect(chip.innerHTML).toMatch(/&quot;any&quot;/);
  });

  it("names the view and its floor for rows below the view's severity floor", () => {
    const events: Ev[] = [
      { id: "a", severity: "Medium" },
      { id: "b", severity: "Medium" },
      { id: "c", severity: "High" },
    ];
    const { sb, chip } = setup({ events, ids: ["a", "b", "c"], view: floorView });
    sb.renderEvIdFilterChip(1, 1);
    expect(chip.innerHTML).toMatch(/2 below the &quot;MyView&quot; dashboard view&#39;s High\+ floor/);
    expect(chip.innerHTML).toMatch(/Analyst/);
    expect(chip.innerHTML).not.toMatch(/corroboration/);
  });

  it("does not count a promoted row the floor lets through as hidden", () => {
    const events: Ev[] = [
      { id: "a", severity: "Medium", promoted: true },
      { id: "b", severity: "Medium" },
    ];
    const { sb, chip } = setup({ events, ids: ["a", "b"], view: floorView });
    sb.renderEvIdFilterChip(1, 1);
    expect(chip.innerHTML).toMatch(/1 below the &quot;MyView&quot; dashboard view&#39;s High\+ floor/);
  });

  it("reports an id the loaded timeline does not hold as not loaded, not lens-hidden", () => {
    const events: Ev[] = [{ id: "a", severity: "High", sources: ["EvtxECmd", "Hayabusa"] }];
    const { sb, chip } = setup({ events, ids: ["a", "zz"], corroboration: 2, view: floorView });
    sb.renderEvIdFilterChip(1, 1);
    expect(chip.innerHTML).toMatch(/1 not in the loaded part of the timeline/);
    expect(chip.innerHTML).not.toMatch(/corroboration/);
    expect(chip.innerHTML).not.toMatch(/floor/);
  });

  it("leaves the chip text as it was when every row shows", () => {
    const events: Ev[] = [
      { id: "a", severity: "High" },
      { id: "b", severity: "Low" },
    ];
    const { sb, chip } = setup({ events, ids: ["a", "b"], label: "Execution stage" });
    sb.renderEvIdFilterChip(2, 2);
    expect(chip.innerHTML).toMatch(/⧉ Showing 2 of 2 events in this group — Execution stage<\/span>/);
    expect(chip.innerHTML).not.toMatch(/floor|corroboration|loaded/);
  });

  it("escapes an adversarial view name and label", () => {
    const events: Ev[] = [{ id: "a", severity: "Low" }];
    const evil = { name: '<img src=x onerror="alert(1)">', filters: { minSeverity: "High" } };
    const { sb, chip } = setup({ events, ids: ["a"], view: evil, label: "<script>x</script>" });
    sb.renderEvIdFilterChip(0, 0);
    expect(chip.innerHTML).not.toMatch(/<img|<script/);
    expect(chip.innerHTML).toMatch(/&lt;img src=x/);
    expect(chip.innerHTML).toMatch(/&lt;script&gt;/);
  });

  it("keeps jumpToEvent's refusal wording for a single event (shared helper)", () => {
    const events: Ev[] = [{ id: "a", severity: "Medium" }];
    const { sb, toasts } = setup({ events, ids: [], view: floorView });
    sb.jumpToEvent("a");
    expect(toasts).toHaveLength(1);
    expect(toasts[0]).toMatch(/below the "MyView" dashboard view's High\+ floor/);
    expect(toasts[0]).toMatch(/Analyst/);
  });
});
