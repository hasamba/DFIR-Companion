import { describe, it, expect } from "vitest";
import { mergeDelta } from "../../src/analysis/stateMerge.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import type { AnalysisDelta } from "../../src/analysis/responseSchema.js";

const baseDelta: AnalysisDelta = {
  findings: [], iocs: [], mitreTechniques: [], threadsOpened: [], threadsClosed: [],
  timelineNote: "", summary: "",
};

describe("mergeDelta", () => {
  it("adds a new finding with firstSeen and lastUpdated", () => {
    const state = emptyState("c1");
    const next = mergeDelta(state, {
      ...baseDelta,
      findings: [{ id: "f1", severity: "High", title: "PS abuse", description: "v1",
        relatedIocs: [], mitreTechniques: ["T1059"], status: "open" }],
      timelineNote: "window 1", summary: "s1",
    }, { windowSequence: 1, timestamp: "2026-05-28T10:00:00.000Z", sourceScreenshots: ["000001_t.webp"] });

    expect(next.findings).toHaveLength(1);
    expect(next.findings[0].firstSeen).toBe("2026-05-28T10:00:00.000Z");
    expect(next.findings[0].lastUpdated).toBe("2026-05-28T10:00:00.000Z");
    expect(state.findings).toHaveLength(0); // original not mutated
  });

  it("updates an existing finding by id instead of duplicating (revisit)", () => {
    let state = emptyState("c1");
    state = mergeDelta(state, {
      ...baseDelta,
      findings: [{ id: "f1", severity: "Medium", title: "PS abuse", description: "v1",
        relatedIocs: [], mitreTechniques: [], status: "open" }],
    }, { windowSequence: 1, timestamp: "2026-05-28T10:00:00.000Z", sourceScreenshots: ["a.webp"] });

    state = mergeDelta(state, {
      ...baseDelta,
      findings: [{ id: "f1", severity: "High", title: "PS abuse", description: "v2 escalated",
        relatedIocs: ["i1"], mitreTechniques: ["T1059"], status: "confirmed" }],
    }, { windowSequence: 5, timestamp: "2026-05-28T10:05:00.000Z", sourceScreenshots: ["b.webp"] });

    expect(state.findings).toHaveLength(1);
    const f = state.findings[0];
    expect(f.severity).toBe("High");
    expect(f.description).toBe("v2 escalated");
    expect(f.status).toBe("confirmed");
    expect(f.firstSeen).toBe("2026-05-28T10:00:00.000Z"); // preserved
    expect(f.lastUpdated).toBe("2026-05-28T10:05:00.000Z"); // refreshed
    expect(f.relatedIocs).toContain("i1");
    expect(f.sourceScreenshots).toEqual(["a.webp", "b.webp"]); // accumulated, deduped
  });

  it("dedupes IOCs by value and closes threads", () => {
    let state = emptyState("c1");
    state = mergeDelta(state, {
      ...baseDelta,
      iocs: [{ id: "i1", type: "ip", value: "10.0.0.5" }],
      threadsOpened: [{ id: "t1", description: "trace lateral movement" }],
    }, { windowSequence: 1, timestamp: "2026-05-28T10:00:00.000Z", sourceScreenshots: [] });

    state = mergeDelta(state, {
      ...baseDelta,
      iocs: [{ id: "i2", type: "ip", value: "10.0.0.5" }], // same value
      threadsClosed: ["t1"],
    }, { windowSequence: 2, timestamp: "2026-05-28T10:01:00.000Z", sourceScreenshots: [] });

    expect(state.iocs).toHaveLength(1);
    expect(state.openThreads[0].status).toBe("closed");
    expect(state.openThreads[0].closedAt).toBe("2026-05-28T10:01:00.000Z");
  });

  it("appends a timeline entry per window", () => {
    let state = emptyState("c1");
    state = mergeDelta(state, { ...baseDelta, timelineNote: "did X" },
      { windowSequence: 1, timestamp: "2026-05-28T10:00:00.000Z", sourceScreenshots: ["a.webp"] });
    expect(state.timeline).toHaveLength(1);
    expect(state.timeline[0].description).toBe("did X");
    expect(state.timeline[0].windowSequence).toBe(1);
  });
});
