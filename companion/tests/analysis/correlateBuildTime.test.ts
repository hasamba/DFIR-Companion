// #1698: correlation keeps the build-time note and the build-time record together.
//
// On INC-2026-014 a member capped by one import (note + record + Low) correlated with a fresh copy of
// the same event from the next import (no record, High). The merged row took the fresh copy's fields,
// so it lost the record, but it unioned every member's notes, so it kept the note — a note the cap pass
// could never remove, which synthesis then quoted as a live build window.
import { describe, it, expect } from "vitest";
import { correlateEvents } from "../../src/analysis/correlate.js";
import { capBuildTimeRows } from "../../src/analysis/buildTimeWindow.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";

const BASE =
  "Sigma: Disable Windows Defender Functionalities Via Registry Keys (EID 13) - DisableRealtimeMonitoring";
const NOTE = " [build-time: vagrant, 2026-09-26T12:34Z–13:59Z]";

const row = (id: string, p: Partial<ForensicEvent>): ForensicEvent => ({
  id,
  timestamp: "2026-09-26T13:03:24.107Z",
  description: BASE,
  severity: "High",
  mitreTechniques: ["T1562.001"],
  relatedFindingIds: [],
  sourceScreenshots: [],
  asset: "HOST-A",
  ...p,
});

// The member the old import capped, and the fresh copy the next import brought.
const capped = () =>
  row("23e17", {
    description: `${BASE}${NOTE}`,
    severity: "Low",
    sources: ["Chainsaw"],
    buildTime: {
      marker: "vagrant",
      window: "2026-09-26T12:34:00.000Z/2026-09-26T13:59:00.000Z",
      cappedFrom: "High",
    },
  });
const fresh = () => row("24e17", { severity: "High", sources: ["Velociraptor"] });

describe("correlation keeps the build-time note and record together (#1698)", () => {
  it("keeps the record when it keeps the note, with the worst original grade", () => {
    const merged = correlateEvents([capped(), fresh()], { windowSeconds: 2 });
    expect(merged).toHaveLength(1);
    const [m] = merged;
    expect(m.description).toContain("[build-time:");
    expect(m.buildTime).toBeDefined();
    expect(m.buildTime?.cappedFrom).toBe("High");
  });

  it("drops a build-time note when no member carries the record", () => {
    const orphan = row("23e17", { description: `${BASE}${NOTE}`, sources: ["Chainsaw"] });
    const [m] = correlateEvents([orphan, fresh()], { windowSeconds: 2 });
    expect(m.description).not.toContain("[build-time:");
    expect(m.buildTime).toBeUndefined();
  });

  it("then un-caps cleanly once the window is gone: no note, the original grade back", () => {
    const merged = correlateEvents([capped(), fresh()], { windowSeconds: 2 });
    const { state } = capBuildTimeRows({ ...emptyState("c1"), forensicTimeline: merged, hostRenames: [] });
    const [m] = state.forensicTimeline;
    expect(m.description).not.toContain("[build-time:");
    expect(m.buildTime).toBeUndefined();
    expect(m.severity).toBe("High");
  });
});
