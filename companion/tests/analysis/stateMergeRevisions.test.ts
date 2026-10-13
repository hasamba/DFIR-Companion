import { describe, it, expect } from "vitest";
import { mergeDelta } from "../../src/analysis/stateMerge.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import type { AnalysisDelta } from "../../src/analysis/responseSchema.js";

// #2141: a merge that overwrites a held row's description or severity records the change on the row.

const baseDelta: AnalysisDelta = {
  findings: [],
  iocs: [],
  mitreTechniques: [],
  threadsOpened: [],
  threadsClosed: [],
  timelineNote: "",
  summary: "",
};

const ev = (description: string, severity: "Critical" | "High" | "Medium" | "Low") => ({
  id: "e1",
  timestamp: "2026-07-01T10:00:00.000Z",
  description,
  severity,
  mitreTechniques: [],
  relatedFindingIds: [],
});
const first = { windowSequence: -1, timestamp: "2026-10-13T08:00:00.000Z", sourceScreenshots: ["fileA.csv"] };
const second = {
  windowSequence: -1,
  timestamp: "2026-10-13T09:00:00.000Z",
  sourceScreenshots: ["fileB.csv"],
};
const seeded = () =>
  mergeDelta(emptyState("c1"), { ...baseDelta, forensicEvents: [ev("text A", "High")] }, first);

describe("mergeDelta — changed after first recorded (#2141)", () => {
  it("overwrites the row and records what it said before, when and by whom", () => {
    const next = mergeDelta(seeded(), { ...baseDelta, forensicEvents: [ev("text B", "Medium")] }, second);
    const [row] = next.forensicTimeline;
    expect(row.description).toBe("text B");
    expect(row.severity).toBe("Medium");
    expect(row.revisions).toEqual([
      {
        at: second.timestamp,
        source: "fileB.csv",
        description: { from: "text A" },
        severity: { from: "High", to: "Medium" },
      },
    ]);
  });

  it("records nothing for an identical re-merge", () => {
    const next = mergeDelta(seeded(), { ...baseDelta, forensicEvents: [ev("text A", "High")] }, second);
    expect(next.forensicTimeline[0].revisions).toBeUndefined();
    expect(next.forensicTimeline[0].revisionsDropped).toBeUndefined();
  });

  it("names the merge's change source over the import label", () => {
    const next = mergeDelta(
      seeded(),
      { ...baseDelta, forensicEvents: [ev("text B", "High")] },
      { ...second, sourceScreenshots: [], changeSource: "MCP agent: vt" },
    );
    expect(next.forensicTimeline[0].revisions?.[0].source).toBe("MCP agent: vt");
  });

  it("leaves the input state untouched", () => {
    const before = mergeDelta(seeded(), { ...baseDelta, forensicEvents: [ev("text B", "High")] }, second);
    const snapshot = JSON.parse(JSON.stringify(before));
    mergeDelta(before, { ...baseDelta, forensicEvents: [ev("text C", "Medium")] }, second);
    expect(before).toEqual(snapshot);
  });

  describe("a row a correlation pass annotated (Codex review of #2141)", () => {
    const annotated = "Ran payload.exe [initial access: host contacted email-delivered domain example.com]";
    const held = () =>
      mergeDelta(emptyState("c1"), { ...baseDelta, forensicEvents: [ev(annotated, "Medium")] }, first);

    it("records an incoming text that only starts with the stored base, and still overwrites", () => {
      const incoming = ev("Ran payload.exe --dump-credentials", "Critical");
      const next = mergeDelta(held(), { ...baseDelta, forensicEvents: [incoming] }, second);
      const [row] = next.forensicTimeline;
      expect(row.description).toBe("Ran payload.exe --dump-credentials");
      expect(row.severity).toBe("Critical");
      expect(row.revisions).toEqual([
        {
          at: second.timestamp,
          source: "fileB.csv",
          description: { from: annotated },
          severity: { from: "Medium", to: "Critical" },
        },
      ]);
    });

    it("records nothing for a re-import that restates the raw text and grade", () => {
      const next = mergeDelta(
        held(),
        { ...baseDelta, forensicEvents: [ev("Ran payload.exe", "Low")] },
        second,
      );
      expect(next.forensicTimeline[0].revisions).toBeUndefined();
    });

    it("records an MCP agent's restatement of the raw text, which is an explicit edit", () => {
      const next = mergeDelta(
        held(),
        { ...baseDelta, forensicEvents: [ev("Ran payload.exe", "Low")] },
        { ...second, sourceScreenshots: [], changeSource: "MCP agent: vt" },
      );
      expect(next.forensicTimeline[0].revisions?.[0]).toMatchObject({
        source: "MCP agent: vt",
        description: { from: annotated },
        severity: { from: "Medium", to: "Low" },
      });
    });
  });
});
