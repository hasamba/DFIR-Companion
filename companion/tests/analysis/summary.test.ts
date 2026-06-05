import { describe, it, expect } from "vitest";
import { buildStateSummary } from "../../src/analysis/summary.js";
import { emptyState } from "../../src/analysis/stateTypes.js";

describe("buildStateSummary", () => {
  it("notes an empty state", () => {
    expect(buildStateSummary(emptyState("c1"))).toContain("No findings yet");
  });

  it("lists finding ids, open threads, and IOC values", () => {
    const state = emptyState("c1");
    state.findings.push({ id: "f1", severity: "High", title: "PS abuse", description: "d",
      relatedIocs: [], mitreTechniques: [], sourceScreenshots: [], firstSeen: "", lastUpdated: "", status: "open" });
    state.openThreads.push({ id: "t1", description: "trace parent", status: "open", openedAt: "", closedAt: null });
    state.iocs.push({ id: "i1", type: "ip", value: "10.0.0.5", firstSeen: "" });

    const summary = buildStateSummary(state);
    expect(summary).toContain("f1");
    expect(summary).toContain("PS abuse");
    expect(summary).toContain("t1");
    expect(summary).toContain("10.0.0.5");
  });

  it("bounds findings and IOCs so a big case doesn't bloat the prepended summary", () => {
    const state = emptyState("c1");
    for (let i = 0; i < 200; i++) {
      state.findings.push({ id: `f${i}`, severity: "Low", title: `t${i}`, description: "d".repeat(500),
        relatedIocs: [], mitreTechniques: [], sourceScreenshots: [], firstSeen: "", lastUpdated: "", status: "open" });
      state.iocs.push({ id: `i${i}`, type: "hash", value: `hash${i}`, firstSeen: "" });
    }
    const summary = buildStateSummary(state);
    // Only the most-recent slice is shown, with a "+N more" note — never all 200.
    expect(summary).toContain("f199");                 // newest finding kept
    expect(summary).not.toContain("f0");               // oldest dropped from the echo
    expect(summary).toContain("more not shown");       // findings overflow noted
    expect(summary).toContain("hash199");
    expect(summary).toContain("+120 more");            // 200 - 80 IOC cap
    // Bounded size: nowhere near the ~100KB an unbounded 200×500-char dump would be.
    expect(summary.length).toBeLessThan(30_000);
  });
});
