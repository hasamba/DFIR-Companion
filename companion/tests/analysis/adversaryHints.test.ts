import { describe, it, expect } from "vitest";
import {
  normalizeTechniqueId,
  adversaryGroupUrl,
  collectCaseTechniques,
  rankAdversaryGroups,
  type AdversaryGroup,
} from "../../src/analysis/adversaryHints.js";
import { emptyState, type InvestigationState, type Finding, type ForensicEvent } from "../../src/analysis/stateTypes.js";

const group = (id: string, name: string, techniques: string[], over: Partial<AdversaryGroup> = {}): AdversaryGroup => ({
  id,
  name,
  aliases: [],
  description: "",
  techniques,
  ...over,
});

const finding = (id: string, mitreTechniques: string[]): Finding => ({
  id,
  severity: "High",
  title: id,
  description: "",
  relatedIocs: [],
  sourceScreenshots: [],
  mitreTechniques,
  firstSeen: "2026-01-01T00:00:00Z",
  lastUpdated: "2026-01-01T00:00:00Z",
  status: "open",
});

const ev = (id: string, mitreTechniques: string[]): ForensicEvent => ({
  id,
  timestamp: "2026-01-01T00:00:00Z",
  description: id,
  severity: "High",
  mitreTechniques,
  relatedFindingIds: [],
  sourceScreenshots: [],
});

describe("normalizeTechniqueId", () => {
  it("rolls sub-techniques up to their base id and uppercases", () => {
    expect(normalizeTechniqueId("t1059.001")).toBe("T1059");
    expect(normalizeTechniqueId("T1566")).toBe("T1566");
    expect(normalizeTechniqueId("  T1003.002  ")).toBe("T1003");
  });

  it("rejects non-technique strings", () => {
    expect(normalizeTechniqueId("TA0001")).toBeNull(); // tactic, not technique
    expect(normalizeTechniqueId("malware")).toBeNull();
    expect(normalizeTechniqueId("T123")).toBeNull(); // too few digits
    expect(normalizeTechniqueId("")).toBeNull();
  });
});

describe("adversaryGroupUrl", () => {
  it("builds the ATT&CK group page url", () => {
    expect(adversaryGroupUrl("G0016")).toBe("https://attack.mitre.org/groups/G0016/");
    expect(adversaryGroupUrl(" g0016 ")).toBe("https://attack.mitre.org/groups/G0016/");
  });
});

describe("collectCaseTechniques", () => {
  it("unions normalized base techniques from findings, events, and the MITRE table; deduped + sorted", () => {
    const state: InvestigationState = {
      ...emptyState("c1"),
      findings: [finding("f1", ["T1059.001", "T1566"])],
      forensicTimeline: [ev("e1", ["t1566", "T1003.002"])],
      mitreTechniques: [{ id: "T1078", name: "Valid Accounts", findingIds: [] }],
    };
    expect(collectCaseTechniques(state)).toEqual(["T1003", "T1059", "T1078", "T1566"]);
  });

  it("is empty when the case has no techniques", () => {
    expect(collectCaseTechniques(emptyState("c1"))).toEqual([]);
  });
});

describe("rankAdversaryGroups", () => {
  const caseTechs = ["T1059", "T1566", "T1003", "T1078"];

  it("returns groups meeting the minimum overlap, ranked by overlap count", () => {
    const groups = [
      group("G1", "Alpha", ["T1059", "T1566", "T1003", "T1078"]), // overlaps 4
      group("G2", "Bravo", ["T1059", "T1566", "T1003"]), // overlaps 3
      group("G3", "Charlie", ["T1059", "T1566"]), // overlaps 2 — below default min(3)
    ];
    const hints = rankAdversaryGroups(caseTechs, groups, { minOverlap: 3 });
    expect(hints.map((h) => h.id)).toEqual(["G1", "G2"]);
    expect(hints[0].overlapCount).toBe(4);
    expect(hints[0].overlapTechniques).toEqual(["T1003", "T1059", "T1078", "T1566"]);
    expect(hints[1].overlapCount).toBe(3);
  });

  it("matches across sub-techniques by rolling both sides up to base", () => {
    // case has PowerShell (T1059.001); group has cmd (T1059.003) — same base T1059, should match.
    const hints = rankAdversaryGroups(
      ["T1059.001", "T1566", "T1003"],
      [group("G1", "Alpha", ["T1059.003", "T1566", "T1003.001"])],
      { minOverlap: 3 },
    );
    expect(hints).toHaveLength(1);
    expect(hints[0].overlapTechniques).toEqual(["T1003", "T1059", "T1566"]);
  });

  it("breaks overlap ties toward the more specific (smaller) group", () => {
    const focused = group("G2", "Focused", ["T1059", "T1566", "T1003"]); // 3 of 3
    const sprawling = group("G1", "Sprawling", ["T1059", "T1566", "T1003", "T1078", "T1071", "T1105"]); // 3 of 6
    const hints = rankAdversaryGroups(["T1059", "T1566", "T1003"], [sprawling, focused], { minOverlap: 3 });
    expect(hints.map((h) => h.id)).toEqual(["G2", "G1"]); // focused first despite equal overlap
    expect(hints[0].groupTechniqueCount).toBe(3);
    expect(hints[1].groupTechniqueCount).toBe(6);
  });

  it("caps the result at topN", () => {
    const groups = Array.from({ length: 10 }, (_, i) =>
      group(`G${i}`, `Grp${i}`, ["T1059", "T1566", "T1003", "T1078"]),
    );
    expect(rankAdversaryGroups(caseTechs, groups, { topN: 3 })).toHaveLength(3);
  });

  it("returns nothing when the case has no techniques", () => {
    expect(rankAdversaryGroups([], [group("G1", "Alpha", ["T1059", "T1566", "T1003"])])).toEqual([]);
  });

  it("carries group metadata and a working ATT&CK url through to the hint", () => {
    const [hint] = rankAdversaryGroups(
      caseTechs,
      [group("G0016", "APT29", ["T1059", "T1566", "T1003"], { aliases: ["Cozy Bear"], description: "Russian SVR." })],
      { minOverlap: 3 },
    );
    expect(hint.name).toBe("APT29");
    expect(hint.aliases).toEqual(["Cozy Bear"]);
    expect(hint.description).toBe("Russian SVR.");
    expect(hint.url).toBe("https://attack.mitre.org/groups/G0016/");
    expect(hint.score).toBe(hint.overlapCount);
  });
});
