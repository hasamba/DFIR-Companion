import { describe, it, expect } from "vitest";
import {
  normalizeTechniqueId,
  baseTechniqueId,
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
  it("keeps the sub-technique and uppercases/trims", () => {
    expect(normalizeTechniqueId("t1059.001")).toBe("T1059.001");
    expect(normalizeTechniqueId("T1566")).toBe("T1566");
    expect(normalizeTechniqueId("  T1003.002  ")).toBe("T1003.002");
  });

  it("rejects non-technique strings", () => {
    expect(normalizeTechniqueId("TA0001")).toBeNull(); // tactic, not technique
    expect(normalizeTechniqueId("malware")).toBeNull();
    expect(normalizeTechniqueId("T123")).toBeNull(); // too few digits
    expect(normalizeTechniqueId("")).toBeNull();
  });
});

describe("baseTechniqueId", () => {
  it("strips the sub-technique to the base id", () => {
    expect(baseTechniqueId("t1059.001")).toBe("T1059");
    expect(baseTechniqueId("T1486")).toBe("T1486");
    expect(baseTechniqueId("  T1003.002 ")).toBe("T1003");
  });
  it("rejects invalid ids", () => {
    expect(baseTechniqueId("nope")).toBeNull();
  });
});

describe("adversaryGroupUrl", () => {
  it("builds the ATT&CK group page url", () => {
    expect(adversaryGroupUrl("G0016")).toBe("https://attack.mitre.org/groups/G0016/");
    expect(adversaryGroupUrl(" g0016 ")).toBe("https://attack.mitre.org/groups/G0016/");
  });
});

describe("collectCaseTechniques", () => {
  it("unions techniques at full granularity from findings, events, and the MITRE table; deduped + sorted", () => {
    const state: InvestigationState = {
      ...emptyState("c1"),
      findings: [finding("f1", ["T1059.001", "T1566"])],
      forensicTimeline: [ev("e1", ["t1566", "T1003.002"])],
      mitreTechniques: [{ id: "T1078", name: "Valid Accounts", findingIds: [] }],
    };
    // sub-techniques preserved; T1566 deduped across finding+event
    expect(collectCaseTechniques(state)).toEqual(["T1003.002", "T1059.001", "T1078", "T1566"]);
  });

  it("is empty when the case has no techniques", () => {
    expect(collectCaseTechniques(emptyState("c1"))).toEqual([]);
  });
});

describe("rankAdversaryGroups", () => {
  const caseTechs = ["T1059", "T1566", "T1003", "T1078"];

  it("returns groups meeting the minimum overlap, ranked by weighted score", () => {
    const groups = [
      group("G1", "Alpha", ["T1059", "T1566", "T1003", "T1078"]), // overlaps 4 (all exact)
      group("G2", "Bravo", ["T1059", "T1566", "T1003"]), // overlaps 3
      group("G3", "Charlie", ["T1059", "T1566"]), // overlaps 2 — below default min(3)
    ];
    const hints = rankAdversaryGroups(caseTechs, groups, { minOverlap: 3 });
    expect(hints.map((h) => h.id)).toEqual(["G1", "G2"]);
    expect(hints[0].overlapCount).toBe(4);
    expect(hints[0].exactCount).toBe(4); // base id == base id is an exact string match
    expect(hints[0].score).toBe(4);
    expect(hints[0].overlapTechniques).toEqual(["T1003", "T1059", "T1078", "T1566"]);
    expect(hints[1].overlapCount).toBe(3);
  });

  it("ranks an exact sub-technique match above a base-only match at equal breadth", () => {
    const caseSubs = ["T1059.001", "T1566", "T1003"]; // case used PowerShell specifically
    const exactGroup = group("GX", "Exact", ["T1059.001", "T1566", "T1003"]); // also PowerShell → 3 exact
    const baseGroup = group("GB", "Base", ["T1059.003", "T1566", "T1003"]); // cmd, not PowerShell → 2 exact + 1 base
    const hints = rankAdversaryGroups(caseSubs, [baseGroup, exactGroup], { minOverlap: 3 });
    expect(hints.map((h) => h.id)).toEqual(["GX", "GB"]); // exact agreement wins despite equal overlap (3 each)
    expect(hints[0]).toMatchObject({ overlapCount: 3, exactCount: 3, score: 3 });
    expect(hints[1]).toMatchObject({ overlapCount: 3, exactCount: 2, score: 2.5 }); // 2 + 0.5×1
  });

  it("awards base-only credit when the case is coarse or the sub-techniques differ", () => {
    // case T1059.001 vs group T1059.003 → base match; case T1566 (no sub) vs group T1566.002 → base match
    const hints = rankAdversaryGroups(
      ["T1059.001", "T1566", "T1003"],
      [group("G1", "Alpha", ["T1059.003", "T1566.002", "T1003"])],
      { minOverlap: 3 },
    );
    expect(hints).toHaveLength(1);
    expect(hints[0].overlapCount).toBe(3);
    expect(hints[0].exactCount).toBe(1); // only T1003 is an exact id match
    expect(hints[0].exactTechniques).toEqual(["T1003"]);
    expect(hints[0].overlapTechniques).toEqual(["T1003", "T1059.001", "T1566"]); // case-side ids, sorted
    expect(hints[0].score).toBe(2); // 1 exact + 0.5×2 base
  });

  it("breaks score ties by breadth then by the more specific (smaller) group", () => {
    const focused = group("G2", "Focused", ["T1059", "T1566", "T1003"]); // 3 exact of 3
    const sprawling = group("G1", "Sprawling", ["T1059", "T1566", "T1003", "T1078", "T1071", "T1105"]); // 3 exact of 6
    const hints = rankAdversaryGroups(["T1059", "T1566", "T1003"], [sprawling, focused], { minOverlap: 3 });
    expect(hints.map((h) => h.id)).toEqual(["G2", "G1"]); // equal score (3) + breadth (3) → ratio favours focused
    expect(hints[0].groupTechniqueCount).toBe(3);
    expect(hints[1].groupTechniqueCount).toBe(6);
  });

  it("counts overlap (breadth) for the threshold, not the weighted score", () => {
    // 3 base-only matches → overlapCount 3 (meets min) even though score is only 1.5
    const hints = rankAdversaryGroups(
      ["T1059.001", "T1566.001", "T1003.001"],
      [group("G1", "Alpha", ["T1059.002", "T1566.002", "T1003.002"])],
      { minOverlap: 3 },
    );
    expect(hints).toHaveLength(1);
    expect(hints[0]).toMatchObject({ overlapCount: 3, exactCount: 0, score: 1.5 });
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
    expect(hint.exactCount).toBe(hint.overlapCount); // all base↔base exact here
    expect(hint.score).toBe(hint.overlapCount);
  });
});
