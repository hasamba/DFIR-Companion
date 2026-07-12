import { describe, it, expect } from "vitest";
import {
  openCollectTargets,
  collectSatisfiedBy,
  detectSatisfiedCollections,
  buildSatisfiedCollectionsBlock,
  type OpenCollectTarget,
} from "../../src/analysis/collectSatisfaction.js";
import { emptyState, type ForensicEvent, type Severity } from "../../src/analysis/stateTypes.js";

function ev(p: Partial<ForensicEvent>): ForensicEvent {
  return { id: p.id ?? "e1", timestamp: "2026-01-01T00:00:00Z", description: p.description ?? "", severity: p.severity ?? "Info" as Severity,
    mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], ...p };
}

describe("openCollectTargets", () => {
  it("collects actionable targets from nextSteps and unknown questions, de-duped", () => {
    const s = emptyState("c1");
    s.nextSteps = [
      { id: "n1", priority: "high", action: "pull", rationale: "", pointer: "", collect: { host: "DC01", logSource: "Security.evtx 4624" } },
      { id: "n2", priority: "low", action: "sandbox", rationale: "", pointer: "" }, // no collect → skipped
    ];
    s.keyQuestions = [
      { id: "q1", question: "lateral?", status: "unknown", answer: "", pointer: "", collect: { host: "DC01", logSource: "Security.evtx 4624" } }, // dup of n1's target
      { id: "q2", question: "exfil?", status: "partial", answer: "", pointer: "", collect: { host: "WEB01", logSource: "web proxy logs" } },
      { id: "q3", question: "answered", status: "answered", answer: "x", pointer: "", collect: { host: "H", logSource: "y" } }, // answered → skipped
    ];
    const targets = openCollectTargets(s);
    const keys = targets.map((t) => t.key);
    expect(keys).toContain("dc01|security.evtx 4624");
    expect(keys).toContain("web01|web proxy logs");
    // n1 and q1 share a target key → de-duped to one
    expect(keys.filter((k) => k === "dc01|security.evtx 4624")).toHaveLength(1);
    expect(targets.length).toBe(2);
  });
});

describe("collectSatisfiedBy", () => {
  const target: OpenCollectTarget = { key: "dc01|security.evtx 4624", host: "DC01", source: "Security.evtx 4624", from: "question", refId: "q1", summary: "collect Security.evtx 4624 from DC01" };

  it("matches an event on the host whose source/description carries a source token", () => {
    const hits = collectSatisfiedBy(target, [
      ev({ id: "e1", asset: "DC01", description: "4624 logon type 3", sources: ["Windows.EventLogs.Security"] }),
      ev({ id: "e2", asset: "WEB01", description: "4624 logon" }), // wrong host
    ]);
    expect(hits).toEqual(["e1"]);
  });

  it("does not match a same-host event with an unrelated source (no token overlap)", () => {
    const hits = collectSatisfiedBy(target, [ev({ id: "e1", asset: "DC01", description: "a sysmon network connection", sources: ["Sysmon"] })]);
    expect(hits).toEqual([]);
  });

  it("matches on host alone when the source names nothing specific", () => {
    const t2: OpenCollectTarget = { ...target, source: "logs", key: "dc01|logs" };
    const hits = collectSatisfiedBy(t2, [ev({ id: "e1", asset: "DC01", description: "anything" })]);
    expect(hits).toEqual(["e1"]);
  });
});

describe("detectSatisfiedCollections + block", () => {
  it("flags a previously-recommended collection now present in the events", () => {
    const s = emptyState("c1");
    s.keyQuestions = [
      { id: "q_lateral_movement", question: "Was there lateral movement?", status: "unknown", answer: "", pointer: "",
        collect: { host: "DC01", logSource: "Security.evtx 4624" } },
    ];
    const events = [ev({ id: "e42", asset: "DC01", description: "Security 4624 type-3 logon from WS07", sources: ["Windows.EventLogs.Security"] })];
    const satisfied = detectSatisfiedCollections(s, events);
    expect(satisfied).toHaveLength(1);
    expect(satisfied[0].target.refId).toBe("q_lateral_movement");
    expect(satisfied[0].matchedEventIds).toEqual(["e42"]);

    const block = buildSatisfiedCollectionsBlock(satisfied);
    expect(block).toContain("SATISFIED COLLECTIONS");
    expect(block).toContain("do NOT re-recommend");
    expect(block).toContain("Was there lateral movement?");
    expect(block).toContain("e42");
  });

  it("returns '' block when nothing is satisfied", () => {
    expect(buildSatisfiedCollectionsBlock([])).toBe("");
  });
});
