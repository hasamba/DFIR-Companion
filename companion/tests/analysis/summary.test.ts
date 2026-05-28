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
});
