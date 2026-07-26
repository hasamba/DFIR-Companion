import { describe, it, expect } from "vitest";
import type { InvestigationState, Finding, IOC, ForensicEvent, InvestigationQuestion, NextStep } from "../../src/analysis/stateTypes.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import type { PlaybookTask } from "../../src/analysis/playbook.js";
import type { EnrichmentProvider } from "../../src/enrichment/provider.js";
import { countEnrichableWork } from "../../src/enrichment/enrichService.js";
import { recommendNextActions } from "../../src/analysis/coach.js";

// Fixtures are built off the real emptyState / typed without casts on purpose: a cast would let the
// scorer's field reads drift away from the types it claims to read (the whole class of bug the
// status-based question and playbook-based next-step counts below exist to prevent).
function makeState(partial: Partial<InvestigationState> = {}): InvestigationState {
  return { ...emptyState("case-x"), updatedAt: new Date().toISOString(), ...partial };
}

function finding(over: Partial<Finding> = {}): Finding {
  return {
    id: "f1",
    title: "F",
    description: "D",
    severity: "High",
    status: "open",
    relatedIocs: [],
    relatedEventIds: [],
    sourceScreenshots: [],
    mitreTechniques: [],
    firstSeen: new Date().toISOString(),
    lastUpdated: new Date().toISOString(),
    ...over,
  };
}

// Routable by default: enrichment holds back internal targets (isInternalTarget's SSRF guard), so an
// RFC1918 fixture would sit on that path and quietly test the wrong branch.
function ioc(over: Partial<IOC> = {}): IOC {
  return { id: "i1", type: "ip", value: "185.220.101.47", firstSeen: new Date().toISOString(), ...over };
}

function event(over: Partial<ForensicEvent> = {}): ForensicEvent {
  return {
    id: "e1",
    timestamp: new Date().toISOString(),
    description: "E",
    severity: "Medium",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...over,
  };
}

function question(over: Partial<InvestigationQuestion> = {}): InvestigationQuestion {
  return { id: "q1", question: "Initial access?", status: "unknown", answer: "", pointer: "", ...over };
}

function nextStep(over: Partial<NextStep> = {}): NextStep {
  return { id: "s1", priority: "high", action: "Pull Security.evtx", rationale: "R", pointer: "P", ...over };
}

// A playbook task as PlaybookStore.sync would return it (auto-task ids ARE their derive key).
function task(over: Partial<PlaybookTask> = {}): PlaybookTask {
  return {
    id: "next_step:s1",
    title: "Pull Security.evtx",
    description: "",
    status: "todo",
    priority: "high",
    source: "next_step",
    sourceKey: "next_step:s1",
    order: 0,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    ...over,
  };
}

function provider(name: string, kinds: string[]): EnrichmentProvider {
  return { name, scope: "external", supports: (k) => kinds.includes(k), lookup: async () => null };
}

describe("recommendNextActions", () => {
  it("recommends import when the case is empty", () => {
    const recs = recommendNextActions(makeState());
    expect(recs[0]?.id).toBe("import-evidence");
  });

  it("recommends enrichment first when a run has IOCs left to query", () => {
    const state = makeState({ forensicTimeline: [event()], iocs: [ioc()] });
    const recs = recommendNextActions(state, { pendingEnrichmentIocs: 1 });
    expect(recs[0]?.id).toBe("enrich-iocs");
    expect(recs[0]?.action).toBe("Enrich 1 IOC");
  });

  it("does not flag enrichment when a run would query nothing", () => {
    const state = makeState({ forensicTimeline: [event()], iocs: [ioc({ enrichedBy: ["VT"] })] });
    const recs = recommendNextActions(state, { pendingEnrichmentIocs: 0 });
    expect(recs.some((r) => r.id === "enrich-iocs")).toBe(false);
  });

  it("recommends triage for open findings", () => {
    const state = makeState({ forensicTimeline: [event()], findings: [finding()] });
    const recs = recommendNextActions(state);
    expect(recs.some((r) => r.id === "triage-findings")).toBe(true);
  });

  it("does not recommend triage for confirmed findings", () => {
    const state = makeState({ forensicTimeline: [event()], findings: [finding({ status: "confirmed" })] });
    const recs = recommendNextActions(state);
    expect(recs.some((r) => r.id === "triage-findings")).toBe(false);
  });

  it("recommends answering unanswered key questions", () => {
    const state = makeState({ forensicTimeline: [event()], keyQuestions: [question()] });
    const recs = recommendNextActions(state);
    expect(recs.some((r) => r.id === "answer-questions")).toBe(true);
  });

  // A "partial" answer carries text but is NOT settled — the playbook, collect-satisfaction and
  // second-look passes all key off status for exactly that reason. Counting it as answered both
  // undercounts the card (the demo case has 3 partial of 6 outstanding) and, via rule 8, declares a
  // case ready to report while a key question is half-answered.
  it("counts a partial answer as still outstanding", () => {
    const state = makeState({
      forensicTimeline: [event()],
      keyQuestions: [
        question({ id: "q1", status: "partial", answer: "Maybe phishing, unconfirmed" }),
        question({ id: "q2", status: "answered", answer: "Yes — 4624 from 10.0.0.9" }),
      ],
    });
    const recs = recommendNextActions(state);
    expect(recs.find((r) => r.id === "answer-questions")?.action).toBe("Answer 1 key question");
  });

  it("does not call a case report-ready while a key question is only partial", () => {
    const state = makeState({
      forensicTimeline: [event()],
      findings: [finding({ status: "confirmed" })],
      keyQuestions: [question({ status: "partial", answer: "Maybe phishing, unconfirmed" })],
    });
    const recs = recommendNextActions(state, { pendingEnrichmentIocs: 0 });
    expect(recs.some((r) => r.id === "generate-report")).toBe(false);
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
      keyQuestions: [question({ status: "answered", answer: "A" })],
    });
    const recs = recommendNextActions(state, { pendingEnrichmentIocs: 0 });
    expect(recs.some((r) => r.id === "generate-report")).toBe(true);
  });
});

// Next-step PROGRESS lives in the playbook, not in InvestigationState — a NextStep has no "done"
// field, so without the playbook the card can only ever count what synthesis proposed and never what
// the analyst has finished.
describe("recommendNextActions — next-step progress", () => {
  it("counts only the playbook tasks that are still open", () => {
    const state = makeState({
      forensicTimeline: [event()],
      nextSteps: [nextStep({ id: "s1" }), nextStep({ id: "s2" }), nextStep({ id: "s3" })],
    });
    const recs = recommendNextActions(state, {
      playbookTasks: [
        task({ id: "next_step:s1", status: "done" }),
        task({ id: "next_step:s2", status: "in_progress" }),
        task({ id: "next_step:s3", status: "todo" }),
      ],
    });
    expect(recs.find((r) => r.id === "run-next-steps")?.action).toBe("Run 2 recommended next steps");
  });

  it("drops the card once every next-step task is done or skipped", () => {
    const state = makeState({ forensicTimeline: [event()], nextSteps: [nextStep({ id: "s1" }), nextStep({ id: "s2" })] });
    const recs = recommendNextActions(state, {
      playbookTasks: [
        task({ id: "next_step:s1", status: "done" }),
        task({ id: "next_step:s2", status: "skipped" }),
      ],
    });
    expect(recs.some((r) => r.id === "run-next-steps")).toBe(false);
  });

  it("ignores playbook tasks that did not come from a next step", () => {
    const state = makeState({ forensicTimeline: [event()], nextSteps: [nextStep()] });
    const recs = recommendNextActions(state, {
      playbookTasks: [
        task({ id: "next_step:s1", status: "done" }),
        task({ id: "finding:f1", source: "finding", status: "todo" }),
        task({ id: "custom:1", source: "custom", status: "todo" }),
      ],
    });
    expect(recs.some((r) => r.id === "run-next-steps")).toBe(false);
  });

  it("falls back to the raw next-step list when no playbook is available", () => {
    // staleReSynth badges "stale, re-synthesis queued" after an FP cascade — it is not a completion
    // marker, so a stale-badged step is still pending work.
    const state = makeState({
      forensicTimeline: [event()],
      nextSteps: [nextStep({ id: "s1" }), nextStep({ id: "s2", staleReSynth: true })],
    });
    expect(recommendNextActions(state).find((r) => r.id === "run-next-steps")?.action)
      .toBe("Run 2 recommended next steps");
    expect(recommendNextActions(state, { playbookTasks: [] }).find((r) => r.id === "run-next-steps")?.action)
      .toBe("Run 2 recommended next steps");
  });
});

// The card's IOC count has to be the enrichment engine's own candidate filter. These pair the coach
// with countEnrichableWork the way the route does, because the failure mode is a count that can
// never reach zero: it pins a no-op "Run enrichment" at the top of the list AND, through rule 8,
// makes "ready to report" unreachable for the rest of the case's life.
describe("recommendNextActions — enrichment work comes from the engine", () => {
  const providers = [provider("virustotal", ["ip", "hash", "domain", "url"]), provider("abuseipdb", ["ip"])];

  it("does not chase IOC types no provider can look up", () => {
    const state = makeState({
      forensicTimeline: [event()],
      findings: [finding({ status: "confirmed" })],
      iocs: [
        ioc({ id: "i1", type: "ip", value: "185.220.101.47", enrichedBy: ["virustotal", "abuseipdb"] }),
        ioc({ id: "i2", type: "hash", value: "abc", enrichedBy: ["virustotal"] }),
        ioc({ id: "i3", type: "file", value: "C:\\Users\\j\\invoice.xlsm" }),
        ioc({ id: "i4", type: "sid", value: "S-1-5-21-1" }),
        ioc({ id: "i5", type: "other", value: "GLOBALTECH\\admin-deploy" }),
      ],
    });
    const pendingEnrichmentIocs = countEnrichableWork(state.iocs, providers);
    expect(pendingEnrichmentIocs).toBe(0);

    const recs = recommendNextActions(state, { pendingEnrichmentIocs });
    expect(recs.some((r) => r.id === "enrich-iocs")).toBe(false);
    expect(recs.some((r) => r.id === "generate-report")).toBe(true);
  });

  it("counts an IOC a newly-enabled provider has not checked yet", () => {
    const state = makeState({
      forensicTimeline: [event()],
      iocs: [ioc({ type: "ip", enrichedBy: ["virustotal"] })],
    });
    const pendingEnrichmentIocs = countEnrichableWork(state.iocs, providers);
    expect(pendingEnrichmentIocs).toBe(1);
    expect(recommendNextActions(state, { pendingEnrichmentIocs })[0]?.id).toBe("enrich-iocs");
  });

  it("does not chase an internal target the SSRF guard holds back", () => {
    const state = makeState({
      forensicTimeline: [event()],
      iocs: [ioc({ id: "i1", type: "ip", value: "10.10.20.15" }), ioc({ id: "i2", type: "url", value: "http://169.254.169.254/latest/meta-data/" })],
    });
    const pendingEnrichmentIocs = countEnrichableWork(state.iocs, providers);
    expect(pendingEnrichmentIocs).toBe(0);
    expect(recommendNextActions(state, { pendingEnrichmentIocs }).some((r) => r.id === "enrich-iocs")).toBe(false);
  });

  it("says nothing about enrichment when no providers are enabled", () => {
    const state = makeState({ forensicTimeline: [event()], iocs: [ioc(), ioc({ id: "i2", type: "hash", value: "abc" })] });
    const pendingEnrichmentIocs = countEnrichableWork(state.iocs, []);
    expect(pendingEnrichmentIocs).toBe(0);
    expect(recommendNextActions(state, { pendingEnrichmentIocs }).some((r) => r.id === "enrich-iocs")).toBe(false);
  });
});
