import { describe, it, expect } from "vitest";
import type { InvestigationState, Finding, IOC, ForensicEvent, TimelineEntry, InvestigationQuestion } from "../../src/analysis/stateTypes.js";
import { recommendNextActions } from "../../src/analysis/coach.js";

function makeState(partial: Partial<InvestigationState> = {}): InvestigationState {
  return {
    caseId: "case-x",
    findings: [],
    iocs: [],
    openThreads: [],
    timeline: [],
    forensicTimeline: [],
    mitreTechniques: [],
    keyQuestions: [],
    nextSteps: [],
    uncertainties: [],
    lastSummary: "",
    attackerPath: "",
    narrativeTimeline: "",
    iocExcludeRules: [],
    updatedAt: new Date().toISOString(),
    ...partial,
  } as InvestigationState;
}

function finding(over: Partial<Finding> = {}): Finding {
  return {
    id: "f1",
    title: "F",
    description: "D",
    severity: "high",
    status: "open",
    relatedIocs: [],
    relatedEventIds: [],
    sourceScreenshots: [],
    mitreTechniques: [],
    firstSeen: new Date().toISOString(),
    ...over,
  } as Finding;
}

function ioc(over: Partial<IOC> = {}): IOC {
  return {
    id: "i1",
    type: "ip",
    value: "10.0.0.1",
    firstSeen: new Date().toISOString(),
    ...over,
  } as IOC;
}

function event(over: Partial<ForensicEvent> = {}): ForensicEvent {
  return {
    id: "e1",
    timestamp: new Date().toISOString(),
    description: "E",
    severity: "medium",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...over,
  } as ForensicEvent;
}

describe("recommendNextActions", () => {
  it("recommends import when the case is empty", () => {
    const recs = recommendNextActions(makeState());
    expect(recs[0]?.id).toBe("import-evidence");
  });

  it("recommends enrichment first when unenriched IOCs exist", () => {
    const state = makeState({
      forensicTimeline: [event()],
      iocs: [ioc()],
    });
    const recs = recommendNextActions(state);
    expect(recs[0]?.id).toBe("enrich-iocs");
  });

  it("does not flag unenriched IOCs if they already have enrichments", () => {
    const state = makeState({
      forensicTimeline: [event()],
      iocs: [ioc({ enrichments: [{ source: "VT", verdict: "malicious", fetchedAt: new Date().toISOString() }] } as IOC)],
    });
    const recs = recommendNextActions(state);
    expect(recs.some((r) => r.id === "enrich-iocs")).toBe(false);
  });

  it("recommends triage for open findings", () => {
    const state = makeState({
      forensicTimeline: [event()],
      findings: [finding()],
    });
    const recs = recommendNextActions(state);
    expect(recs.some((r) => r.id === "triage-findings")).toBe(true);
  });

  it("does not recommend triage for confirmed findings", () => {
    const state = makeState({
      forensicTimeline: [event()],
      findings: [finding({ status: "confirmed" })],
    });
    const recs = recommendNextActions(state);
    expect(recs.some((r) => r.id === "triage-findings")).toBe(false);
  });

  it("recommends answering unanswered key questions", () => {
    const q: InvestigationQuestion = {
      id: "q1",
      question: "Initial access?",
      status: "unknown",
      answer: "",
      pointer: "",
    } as InvestigationQuestion;
    const state = makeState({
      forensicTimeline: [event()],
      keyQuestions: [q],
    });
    const recs = recommendNextActions(state);
    expect(recs.some((r) => r.id === "answer-questions")).toBe(true);
  });

  it("recommends re-synthesis when new evidence arrived after last update", () => {
    const futureEvent = event({ timestamp: new Date(Date.now() + 120_000).toISOString() });
    const state = makeState({
      forensicTimeline: [futureEvent],
      findings: [finding()],
      updatedAt: new Date().toISOString(),
    });
    const recs = recommendNextActions(state);
    expect(recs.some((r) => r.id === "re-synthesize")).toBe(true);
  });

  it("recommends report generation for a clean, triaged case", () => {
    const state = makeState({
      forensicTimeline: [event()],
      findings: [finding({ status: "confirmed" })],
      iocs: [ioc({ enrichedBy: ["VT"] })],
      keyQuestions: [{ id: "q1", question: "Q", status: "answered", answer: "A", pointer: "" } as InvestigationQuestion],
    });
    const recs = recommendNextActions(state);
    expect(recs.some((r) => r.id === "generate-report")).toBe(true);
  });
});
