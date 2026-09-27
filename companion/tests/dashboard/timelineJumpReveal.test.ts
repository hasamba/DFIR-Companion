import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// The Executive and Report views hide the Forensic Timeline but still show panels that link to its
// events — the Narrative Timeline rail's times, the Playbook's matched steps. jumpToEvent found the
// row and flashed it inside a section the view had set to display:none, so the click looked dead.
// The jump now reveals the section the way the cockpit's stage cards do: the one section is shown,
// and the analyst's view stays as they chose it.

interface JumpSandbox {
  jumpToEvent(id: string): void;
}

function setup(withReveal: boolean) {
  const calls = { revealed: [] as string[], uncollapsed: 0 };
  const noop = () => {};
  const facet = { showAll: noop, matcher: () => ({ has: () => false }) };
  const section = { classList: { remove: () => calls.uncollapsed++ } };
  const sb = loadDashboardModule<JumpSandbox>(
    "dashboard-hunts-jumps.js",
    ["dashboard-filters.js", "dashboard-timeline-display.js"],
    {
      document: {
        getElementById: (id: string) => (id === "sec-timeline" ? section : null),
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
      DfirState: { lastFt: () => [{ id: "e1", severity: "High" }], lastState: () => null, activeView: () => null },
      DfirFacets: { sources: facet, origins: facet, hosts: facet },
      DfirTimelineView: { clearFilters: noop, corrobTimeline: () => 0 },
      sortTimelineEvents: (list: unknown[]) => list,
      viewMeetsMinSev: () => true,
      renderTimelineEvents: noop,
      showToast: noop,
      ...(withReveal ? { revealSection: (id: string) => calls.revealed.push(id) } : {}),
    },
  );
  return { sb, calls };
}

describe("jumpToEvent reveals the Forensic Timeline", () => {
  it("shows the section even when the active view hides it", () => {
    const { sb, calls } = setup(true);
    sb.jumpToEvent("e1");
    expect(calls.revealed).toEqual(["sec-timeline"]);
  });

  it("still opens a collapsed section when the reveal helper is absent", () => {
    const { sb, calls } = setup(false);
    sb.jumpToEvent("e1");
    expect(calls.uncollapsed).toBe(1);
  });
});
