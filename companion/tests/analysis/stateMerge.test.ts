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

  it("drops tool-usage narration from forensic events at merge time", () => {
    const state = mergeDelta(emptyState("c1"), {
      ...baseDelta,
      forensicEvents: [
        { id: "e1", timestamp: "2026-06-01T10:55:41Z", description: "Velociraptor Response and Monitoring session continued.",
          severity: "Info", mitreTechniques: [], relatedFindingIds: [] },
        { id: "e2", timestamp: "2026-06-01T10:56:13Z", description: "Suspicious Epmap Connection entry detected.",
          severity: "High", mitreTechniques: ["T1218.011"], relatedFindingIds: [] },
      ],
    }, { windowSequence: 1, timestamp: "2026-06-01T10:56:13Z", sourceScreenshots: ["s.webp"] });

    expect(state.forensicTimeline).toHaveLength(1);
    expect(state.forensicTimeline[0].description).toContain("Epmap");
  });

  it("merges forensic events, dedupes by id, and keeps them sorted by event time", () => {
    let state = emptyState("c1");
    // First window contributes a later event (15:00).
    state = mergeDelta(state, {
      ...baseDelta,
      forensicEvents: [{ id: "e2", timestamp: "2026-05-20T15:00:00Z", description: "encryptor ran",
        severity: "Critical", mitreTechniques: ["T1486"], relatedFindingIds: ["f1"] }],
      attackerPath: "phishing then ransomware",
    }, { windowSequence: 1, timestamp: "2026-05-28T10:00:00.000Z", sourceScreenshots: ["s2.webp"] });

    // Second window contributes an EARLIER event (09:00) — must sort before e2.
    state = mergeDelta(state, {
      ...baseDelta,
      forensicEvents: [{ id: "e1", timestamp: "2026-05-20T09:00:00Z", description: "phish opened",
        severity: "High", mitreTechniques: ["T1566"], relatedFindingIds: [] }],
    }, { windowSequence: 2, timestamp: "2026-05-28T10:05:00.000Z", sourceScreenshots: ["s1.webp"] });

    expect(state.forensicTimeline).toHaveLength(2);
    expect(state.forensicTimeline.map((e) => e.id)).toEqual(["e1", "e2"]); // chronological
    expect(state.attackerPath).toBe("phishing then ransomware");          // preserved when new delta omits it

    // Re-reporting e1 updates in place (no duplicate) and accumulates evidence.
    state = mergeDelta(state, {
      ...baseDelta,
      forensicEvents: [{ id: "e1", timestamp: "2026-05-20T09:00:00Z", description: "phish opened (confirmed)",
        severity: "High", mitreTechniques: ["T1566.001"], relatedFindingIds: ["f2"] }],
    }, { windowSequence: 3, timestamp: "2026-05-28T10:10:00.000Z", sourceScreenshots: ["s3.webp"] });

    expect(state.forensicTimeline).toHaveLength(2);
    const e1 = state.forensicTimeline.find((e) => e.id === "e1")!;
    expect(e1.description).toBe("phish opened (confirmed)");
    expect(e1.mitreTechniques).toContain("T1566.001");
    expect(e1.sourceScreenshots).toEqual(["s1.webp", "s3.webp"]);
  });
});
