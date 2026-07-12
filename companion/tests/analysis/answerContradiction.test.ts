import { describe, it, expect } from "vitest";
import {
  assertsAbsence,
  findContradictingEvents,
  flagContradictedAnswers,
  CONTRADICTION_RULES,
} from "../../src/analysis/answerContradiction.js";
import type { ForensicEvent, InvestigationQuestion } from "../../src/analysis/stateTypes.js";

function ev(partial: Partial<ForensicEvent>): ForensicEvent {
  return {
    id: partial.id ?? "e1",
    timestamp: "2026-01-01T00:00:00Z",
    description: partial.description ?? "an event",
    severity: partial.severity ?? "High",
    mitreTechniques: partial.mitreTechniques ?? [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...partial,
  };
}

function q(partial: Partial<InvestigationQuestion>): InvestigationQuestion {
  return {
    id: partial.id ?? "q1",
    question: partial.question ?? "a question",
    status: partial.status ?? "answered",
    answer: partial.answer ?? "",
    pointer: partial.pointer ?? "",
    ...partial,
  };
}

describe("assertsAbsence", () => {
  it("trips on a negative conclusion", () => {
    expect(assertsAbsence("No data exfiltration has been confirmed")).toBe(true);
    expect(assertsAbsence("No evidence of lateral movement was observed")).toBe(true);
    expect(assertsAbsence("Persistence was not detected")).toBe(true);
  });

  it("does not trip on a positive/neutral answer", () => {
    expect(assertsAbsence("Data was exfiltrated to mega.nz via rclone")).toBe(false);
    expect(assertsAbsence("Lateral movement from HOST1 to HOST2 via RDP")).toBe(false);
  });

  it("treats an empty answer as not an absence assertion (unknown != absent)", () => {
    expect(assertsAbsence("")).toBe(false);
    expect(assertsAbsence("   ")).toBe(false);
  });

  it("does not trip on a negation that isn't an absence conclusion", () => {
    expect(assertsAbsence("Not all hosts were patched")).toBe(false); // no absence-context word
  });
});

describe("findContradictingEvents (prefix match)", () => {
  const exfilRule = CONTRADICTION_RULES.find((r) => r.key === "exfiltration")!;

  it("matches a sub-technique by prefix (T1052.001 under T1052)", () => {
    const events = [ev({ id: "e5", mitreTechniques: ["T1052.001"] }), ev({ id: "e6", mitreTechniques: ["T1005"] })];
    const res = findContradictingEvents(events, exfilRule);
    expect(res.techniques).toContain("T1052.001");
    expect(res.eventIds).toContain("e5");
    expect(res.eventIds).not.toContain("e6");
  });

  it("returns empty when no event carries the family", () => {
    const res = findContradictingEvents([ev({ mitreTechniques: ["T1059"] })], exfilRule);
    expect(res.techniques).toEqual([]);
    expect(res.eventIds).toEqual([]);
  });
});

describe("flagContradictedAnswers", () => {
  it("flags the halcyon case: 'no exfiltration' vs staged/copied data in the timeline", () => {
    const questions = [q({ id: "q_exfiltration", question: "Was data exfiltrated?", status: "answered", answer: "No data exfiltration has been confirmed." })];
    const events = [
      ev({ id: "e10", description: "xcopy sensitive to E:", mitreTechniques: ["T1074.001"] }),
      ev({ id: "e11", description: "7z archive of finance", mitreTechniques: ["T1560.001"] }),
    ];
    const out = flagContradictedAnswers(questions, events);
    expect(out[0].status).toBe("partial");
    expect(out[0].contradicted?.techniques).toEqual(["T1074.001", "T1560.001"]);
    expect(out[0].contradicted?.eventIds).toEqual(["e10", "e11"]);
    expect(out[0].pointer).toMatch(/contradict this negative answer/i);
  });

  it("matches by question TEXT when the id is non-standard", () => {
    const questions = [q({ id: "custom1", question: "Did the attacker perform lateral movement?", answer: "No lateral movement was observed." })];
    const events = [ev({ id: "e2", mitreTechniques: ["T1021.001"] })];
    const out = flagContradictedAnswers(questions, events);
    expect(out[0].status).toBe("partial");
    expect(out[0].contradicted?.techniques).toEqual(["T1021.001"]);
  });

  it("leaves a positive answer untouched", () => {
    const questions = [q({ id: "q_exfiltration", question: "exfiltration?", status: "answered", answer: "Data exfiltrated via rclone to S3." })];
    const events = [ev({ mitreTechniques: ["T1567.002"] })];
    const out = flagContradictedAnswers(questions, events);
    expect(out[0].status).toBe("answered");
    expect(out[0].contradicted).toBeUndefined();
  });

  it("leaves a negative answer untouched when NO matching evidence exists", () => {
    const questions = [q({ id: "q_exfiltration", question: "exfiltration?", answer: "No exfiltration was observed." })];
    const events = [ev({ mitreTechniques: ["T1059"] })];
    const out = flagContradictedAnswers(questions, events);
    expect(out[0].status).toBe("answered");
    expect(out[0].contradicted).toBeUndefined();
  });

  it("does not flag an 'unknown'/empty answer", () => {
    const questions = [q({ id: "q_exfiltration", question: "exfiltration?", status: "unknown", answer: "" })];
    const events = [ev({ mitreTechniques: ["T1041"] })];
    const out = flagContradictedAnswers(questions, events);
    expect(out[0].contradicted).toBeUndefined();
    expect(out[0].status).toBe("unknown");
  });

  it("is idempotent and clears a stale flag when the answer no longer contradicts", () => {
    const stale = q({ id: "q_exfiltration", question: "exfiltration?", status: "partial", answer: "Confirmed: data exfiltrated.", contradicted: { techniques: ["T1041"], eventIds: ["x"] } });
    const out = flagContradictedAnswers([stale], [ev({ mitreTechniques: ["T1041"] })]);
    expect(out[0].contradicted).toBeUndefined(); // positive answer → flag cleared
  });
});
