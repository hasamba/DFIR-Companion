import { describe, it, expect } from "vitest";
import {
  eventMatches,
  techniqueSatisfies,
  scoreExtraction,
  checkSynthesis,
  passesExtraction,
  passesSynthesis,
  type GoldenEvent,
  type ProducedEvent,
  type ProducedFinding,
} from "./scorer.js";

function ev(partial: Partial<ProducedEvent> & { id: string }): ProducedEvent {
  return { timestamp: "2026-06-01T10:00:00Z", description: "", severity: "Info", ...partial };
}

describe("eventMatches (#64 fuzzy predicate)", () => {
  it("matches when every specified constraint holds; ignores omitted ones", () => {
    const golden: GoldenEvent = { timestamp: "2026-06-01T10:00:00Z", keywords: ["mimikatz"], severity: "Critical", mitreTechniques: ["T1003.001"], asset: "DC01" };
    const produced = ev({ id: "e1", timestamp: "2026-06-01T10:03:00Z", description: "Mimikatz sekurlsa::logonpasswords on DC01", severity: "Critical", mitreTechniques: ["T1003.001"], asset: "dc01" });
    expect(eventMatches(golden, produced)).toBe(true); // 3-min drift within tolerance, case-insensitive kw/asset/technique
  });

  it("fails when the timestamp is outside tolerance", () => {
    expect(eventMatches({ timestamp: "2026-06-01T10:00:00Z" }, ev({ id: "e1", timestamp: "2026-06-01T10:30:00Z" }))).toBe(false);
    expect(eventMatches({ timestamp: "2026-06-01T10:00:00Z" }, ev({ id: "e1", timestamp: "2026-06-01T10:04:00Z" }))).toBe(true);
  });

  it("fails (does not throw) on an unparseable required timestamp", () => {
    expect(eventMatches({ timestamp: "2026-06-01T10:00:00Z" }, ev({ id: "e1", timestamp: "not-a-date" }))).toBe(false);
  });

  it("requires ALL keywords and at least ONE technique overlap", () => {
    expect(eventMatches({ keywords: ["psexec", "smb"] }, ev({ id: "e1", description: "psexec over smb" }))).toBe(true);
    expect(eventMatches({ keywords: ["psexec", "smb"] }, ev({ id: "e1", description: "psexec only" }))).toBe(false);
    expect(eventMatches({ mitreTechniques: ["T1021.002", "T1570"] }, ev({ id: "e1", mitreTechniques: ["T1570"] }))).toBe(true);
    expect(eventMatches({ mitreTechniques: ["T1021.002"] }, ev({ id: "e1", mitreTechniques: ["T1059"] }))).toBe(false);
  });

  it("respects a custom tolerance window", () => {
    expect(eventMatches({ timestamp: "2026-06-01T10:00:00Z" }, ev({ id: "e1", timestamp: "2026-06-01T10:20:00Z" }), { toleranceMinutes: 30 })).toBe(true);
  });

  // A real run emitted one event per row of a 10-row brute-force burst instead of one aggregated event.
  // All 10 satisfy the same golden — finer granularity, not invention — so the 9 the 1:1 matching leaves
  // unconsumed must NOT be false positives. Genuine noise (matching no golden) still must be.
  it("does not count finer-grained duplicates of a golden as false positives", () => {
    const golden: GoldenEvent[] = [{ timestamp: "2026-06-01T10:00:00Z", keywords: ["jdoe"], asset: "WS01" }];
    const perRow = [1, 2, 3].map((n) =>
      ev({ id: `e${n}`, timestamp: `2026-06-01T10:00:0${n}Z`, description: "failed logon for jdoe", asset: "WS01" }),
    );
    const score = scoreExtraction(golden, perRow);
    expect(score.truePositives).toBe(1);      // one golden ⇒ at most one TP (recall can't be inflated)
    expect(score.falsePositives).toBe(0);     // the other two are the same fact, not noise
    expect(score.precision).toBe(1);
    expect(score.recall).toBe(1);

    // An event matching no golden is still a false positive.
    const withNoise = [...perRow, ev({ id: "n1", timestamp: "2026-06-01T10:14:00Z", description: "asmith logged off", asset: "WS03" })];
    const noisy = scoreExtraction(golden, withNoise);
    expect(noisy.falsePositives).toBe(1);
    expect(noisy.extraProduced).toEqual(["n1"]);
  });

  // A real gpt-4o-mini run tagged an SSH password-guessing burst T1110.001 against a golden asking for
  // T1110 and scored 0% recall — a strictly MORE precise answer counted as a total miss.
  it("accepts a produced SUB-technique for a golden parent, but not the reverse", () => {
    expect(techniqueSatisfies("T1110", "T1110.001")).toBe(true);   // password guessing IS brute force
    expect(techniqueSatisfies("T1110", "T1110")).toBe(true);
    expect(techniqueSatisfies("T1110.001", "T1110")).toBe(false);  // parent is less precise than asked
    expect(techniqueSatisfies("T1110", "T1111")).toBe(false);      // prefix-adjacent ids must not match
    expect(eventMatches({ mitreTechniques: ["T1110"] }, ev({ id: "e1", mitreTechniques: ["T1110.001"] }))).toBe(true);
    expect(eventMatches({ mitreTechniques: ["T1110.001"] }, ev({ id: "e1", mitreTechniques: ["T1110"] }))).toBe(false);
  });
});

describe("scoreExtraction (#64 precision/recall)", () => {
  it("computes perfect precision/recall when golden and produced align 1:1", () => {
    const golden: GoldenEvent[] = [{ keywords: ["logon"] }, { keywords: ["mimikatz"] }];
    const produced = [ev({ id: "e1", description: "successful logon" }), ev({ id: "e2", description: "mimikatz run" })];
    const s = scoreExtraction(golden, produced);
    expect(s).toMatchObject({ truePositives: 2, falsePositives: 0, falseNegatives: 0, precision: 1, recall: 1, f1: 1 });
  });

  it("counts an unmatched produced event as a false positive (noise)", () => {
    const s = scoreExtraction([{ keywords: ["logon"] }], [ev({ id: "e1", description: "logon" }), ev({ id: "e2", description: "screensaver started" })]);
    expect(s.truePositives).toBe(1);
    expect(s.falsePositives).toBe(1);
    expect(s.extraProduced).toEqual(["e2"]);
    expect(s.precision).toBeCloseTo(0.5);
    expect(s.recall).toBe(1);
  });

  it("counts an unmatched golden as a false negative (missed detection)", () => {
    const s = scoreExtraction([{ keywords: ["logon"] }, { keywords: ["exfil"] }], [ev({ id: "e1", description: "logon" })]);
    expect(s.falseNegatives).toBe(1);
    expect(s.missedGolden).toEqual([1]);
    expect(s.recall).toBeCloseTo(0.5);
  });

  it("does not let duplicate produced events inflate recall past the golden count", () => {
    const s = scoreExtraction([{ keywords: ["logon"] }], [ev({ id: "e1", description: "logon" }), ev({ id: "e2", description: "logon" })]);
    expect(s.truePositives).toBe(1); // one golden consumes exactly one produced — recall stays capped
    // ...and the leftover is NOT a false positive: it satisfies the golden, so it's the same fact restated,
    // not noise. (FP is "matches no golden" — see scoreExtraction. Previously this asserted 1, which made a
    // model that split one golden fact across several rows score 10% precision on a correct extraction.)
    expect(s.falsePositives).toBe(0);
    expect(s.precision).toBe(1);
  });

  it("defines empty cases conventionally (precision/recall = 1)", () => {
    expect(scoreExtraction([], [])).toMatchObject({ precision: 1, recall: 1, f1: 1 });
    expect(passesExtraction(scoreExtraction([], []))).toBe(true);
  });

  it("passesExtraction respects thresholds", () => {
    const s = scoreExtraction([{ keywords: ["a"] }, { keywords: ["b"] }], [ev({ id: "e1", description: "a" })]); // recall 0.5
    expect(passesExtraction(s)).toBe(false);
    expect(passesExtraction(s, { minPrecision: 0.5, minRecall: 0.5 })).toBe(true);
  });
});

describe("checkSynthesis (#64 coverage + hallucination + rubric)", () => {
  const events: ProducedEvent[] = [
    ev({ id: "e1", severity: "Critical", description: "ransomware note dropped" }),
    ev({ id: "e2", severity: "High", description: "lsass dump" }),
    ev({ id: "e3", severity: "Info", description: "screensaver" }),
  ];

  it("flags a high-severity event with no finding as uncovered", () => {
    const findings: ProducedFinding[] = [{ id: "f1", severity: "Critical", relatedEventIds: ["e1"] }];
    const r = checkSynthesis(events, findings);
    expect(r.highSeverity.total).toBe(2);            // e1, e2 (not the Info e3)
    expect(r.highSeverity.uncovered.map((e) => e.id)).toEqual(["e2"]);
    expect(passesSynthesis(r)).toBe(false);
  });

  it("counts an event covered via its own relatedFindingIds too", () => {
    const evs = [ev({ id: "e1", severity: "Critical", description: "x", relatedFindingIds: ["f9"] })];
    const r = checkSynthesis(evs, []);
    expect(r.highSeverity.uncovered).toEqual([]);
  });

  it("flags a finding referencing a non-existent event id as an invented (dangling) ref", () => {
    const findings: ProducedFinding[] = [{ id: "f1", severity: "Critical", relatedEventIds: ["e1", "e999"] }];
    const r = checkSynthesis(events, findings);
    expect(r.danglingEventRefs).toEqual([{ findingId: "f1", badRefs: ["e999"] }]);
    expect(passesSynthesis(r)).toBe(false);
  });

  it("flags a finding with no real event and no IOC as ungrounded", () => {
    const findings: ProducedFinding[] = [{ id: "f1", severity: "Medium", relatedEventIds: [] }];
    const r = checkSynthesis(events, findings);
    expect(r.grounding.ungrounded).toEqual(["f1"]);
  });

  it("treats an IOC-only finding as grounded", () => {
    const findings: ProducedFinding[] = [{ id: "f1", severity: "Medium", relatedEventIds: [], relatedIocs: ["i1"] }];
    const r = checkSynthesis(events, findings);
    expect(r.grounding.ungrounded).toEqual([]);
  });

  it("flags a numeric confidence with no reason (rubric, advisory)", () => {
    // Cover BOTH high-sev events so the only issue is the missing confidence reason — proving it's advisory.
    const findings: ProducedFinding[] = [
      { id: "f1", severity: "Critical", relatedEventIds: ["e1"], confidence: 90 },
      { id: "f2", severity: "High", relatedEventIds: ["e2"] },
    ];
    const r = checkSynthesis(events, findings);
    expect(r.confidenceIssues).toEqual(["f1"]);
    expect(passesSynthesis(r)).toBe(true); // advisory — doesn't fail the gate
  });

  it("passes a clean synthesis result", () => {
    const findings: ProducedFinding[] = [
      { id: "f1", severity: "Critical", relatedEventIds: ["e1"], confidence: 90, confidenceReason: "AV + note" },
      { id: "f2", severity: "High", relatedEventIds: ["e2"] },
    ];
    const r = checkSynthesis(events, findings);
    expect(passesSynthesis(r)).toBe(true);
  });
});
