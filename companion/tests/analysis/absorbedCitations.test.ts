// #1714: correlation folds a group of events into one. Every citation of a folded-away id must follow
// it to the event that survived, and an event the case already stored must never be the one renamed.
import { describe, it, expect } from "vitest";
import { correlateEvents, correlateEventsTracked } from "../../src/analysis/correlate.js";
import { remapAbsorbedEventIds } from "../../src/analysis/absorbedCitations.js";
import { mergeDelta } from "../../src/analysis/stateMerge.js";
import { emptyState, type ForensicEvent, type InvestigationState } from "../../src/analysis/stateTypes.js";
import type { AnalysisDelta } from "../../src/analysis/responseSchema.js";

const HASH = "4813e753f6f9bfa5c5de0edbb8dd3cc7f1fa51714097d3144d44e5e89dbd33ef";
const ctx = { windowSequence: 1, timestamp: "2026-05-28T10:00:00.000Z", sourceScreenshots: [] };
const baseDelta: AnalysisDelta = {
  findings: [],
  iocs: [],
  mitreTechniques: [],
  threadsOpened: [],
  threadsClosed: [],
  timelineNote: "",
  summary: "",
};

function ev(over: Partial<ForensicEvent> & { id: string }): ForensicEvent {
  return {
    timestamp: "2026-05-26T08:35:23Z",
    description: "event",
    severity: "High",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...over,
  };
}
const velo = (id = "m1e1") => ev({ id, description: `Downloaded file evil.exe flagged, sha256 ${HASH}` });
const thor = (id = "t2e5") =>
  ev({
    id,
    severity: "Critical",
    sha256: HASH,
    description: "THOR Alert: Malware file found C:\\Tools\\evil.exe",
  });
const finding = (id: string, relatedEventIds: string[]) => ({
  id,
  severity: "High" as const,
  title: id,
  description: id,
  status: "open" as const,
  relatedIocs: [],
  mitreTechniques: [],
  relatedEventIds,
});
type DeltaEvent = NonNullable<AnalysisDelta["forensicEvents"]>[number];
/** A ForensicEvent fixture as a delta row (the delta narrows `origin`; these fixtures set none). */
const row = (e: ForensicEvent) => e as DeltaEvent;
const liveIds = (s: InvestigationState) => new Set(s.forensicTimeline.map((e) => e.id));

describe("correlateEventsTracked (#1714)", () => {
  it("keeps the primary's id and reports every other member as absorbed into it", () => {
    const { events, absorbedInto } = correlateEventsTracked([velo(), thor()]);
    expect(events).toHaveLength(1);
    expect(events[0].id).toBe("t2e5");
    expect(events[0].severity).toBe("Critical");
    expect([...absorbedInto]).toEqual([["m1e1", "t2e5"]]);
  });

  it("reports nothing absorbed for singletons and for a lone event", () => {
    expect(correlateEventsTracked([velo()]).absorbedInto.size).toBe(0);
    expect(correlateEventsTracked([velo(), ev({ id: "x", description: "other" })]).absorbedInto.size).toBe(0);
  });

  it("correlateEvents returns exactly the tracked events", () => {
    expect(correlateEvents([velo(), thor()])).toEqual(correlateEventsTracked([velo(), thor()]).events);
  });
});

describe("remapAbsorbedEventIds (#1714)", () => {
  const absorbed = new Map([["b", "a"]]);
  const state: InvestigationState = {
    ...emptyState("c"),
    findings: [
      { ...finding("f1", ["a", "b", "z"]), firstSeen: "", lastUpdated: "", sourceScreenshots: [] },
      { ...finding("f2", ["z"]), firstSeen: "", lastUpdated: "", sourceScreenshots: [] },
    ],
  };

  it("rewrites an absorbed citation to its survivor, de-duplicated in first-seen order", () => {
    const out = remapAbsorbedEventIds(state, absorbed);
    expect(out.findings[0].relatedEventIds).toEqual(["a", "z"]);
  });

  it("returns an untouched finding as the same object, and the input unchanged", () => {
    const out = remapAbsorbedEventIds(state, absorbed);
    expect(out.findings[1]).toBe(state.findings[1]);
    expect(state.findings[0].relatedEventIds).toEqual(["a", "b", "z"]);
  });

  it("returns the state itself when nothing was absorbed", () => {
    expect(remapAbsorbedEventIds(state, new Map())).toBe(state);
  });

  it("rewrites IOC provenance, session-command notes and contradiction pointers too", () => {
    const out = remapAbsorbedEventIds(
      {
        ...state,
        iocs: [{ id: "i001", type: "hash", value: HASH, firstSeen: "", extractedFrom: ["b", "a"] }],
        findings: [
          {
            ...state.findings[1],
            sessionCommands: [{ eventId: "b", timestamp: "", host: "h", kind: "process", text: "x" }],
          },
        ],
        keyQuestions: [
          {
            id: "q1",
            question: "q",
            status: "answered",
            answer: "",
            pointer: "",
            contradicted: { techniques: ["T1"], eventIds: ["b"] },
          },
        ],
      },
      absorbed,
    );
    expect(out.iocs[0].extractedFrom).toEqual(["a"]);
    expect(out.findings[0].sessionCommands?.[0].eventId).toBe("a");
    expect(out.keyQuestions[0].contradicted?.eventIds).toEqual(["a"]);
  });
});

describe("mergeDelta keeps a finding's evidence through correlation (#1714)", () => {
  it("a new finding citing a new event that folds into a stored one follows it", () => {
    const s = mergeDelta(emptyState("c"), { ...baseDelta, forensicEvents: [row(thor())] }, ctx);
    const n = mergeDelta(
      s,
      { ...baseDelta, forensicEvents: [row(velo())], findings: [finding("f1", ["m1e1"])] },
      ctx,
    );
    expect([...liveIds(n)]).toEqual(["t2e5"]);
    expect(n.findings[0].relatedEventIds).toEqual(["t2e5"]);
  });

  it("a stored finding follows its event when a more severe import folds it away", () => {
    const s = mergeDelta(
      emptyState("c"),
      { ...baseDelta, forensicEvents: [row(velo())], findings: [finding("f1", ["m1e1"])] },
      ctx,
    );
    const n = mergeDelta(s, { ...baseDelta, forensicEvents: [row(thor())] }, ctx);
    expect([...liveIds(n)]).toEqual(["t2e5"]);
    expect(n.findings[0].relatedEventIds).toEqual(["t2e5"]);
  });

  it("re-importing the folded-away row keeps the survivor's content", () => {
    const s = mergeDelta(emptyState("c"), { ...baseDelta, forensicEvents: [row(velo())] }, ctx);
    const folded = mergeDelta(s, { ...baseDelta, forensicEvents: [row(thor())] }, ctx);
    const n = mergeDelta(folded, { ...baseDelta, forensicEvents: [row(velo())] }, ctx);
    expect(n.forensicTimeline.map((e) => [e.id, e.severity])).toEqual([["t2e5", "Critical"]]);
  });

  it("a finding citing both members ends with one citation", () => {
    const n = mergeDelta(
      emptyState("c"),
      {
        ...baseDelta,
        forensicEvents: [row(velo()), row(thor())],
        findings: [finding("f1", ["m1e1", "t2e5"])],
      },
      ctx,
    );
    expect(n.findings[0].relatedEventIds).toEqual(["t2e5"]);
  });

  it("a decorated citation (#1693) of a folded-away event reaches the survivor", () => {
    const s = mergeDelta(emptyState("c"), { ...baseDelta, forensicEvents: [row(velo())] }, ctx);
    const n = mergeDelta(
      s,
      { ...baseDelta, forensicEvents: [row(thor())], findings: [finding("f1", ["~[M1E1]"])] },
      ctx,
    );
    expect(n.findings[0].relatedEventIds).toEqual(["t2e5"]);
  });

  it("an IOC extracted from a folded-away event keeps its provenance", () => {
    const s = mergeDelta(emptyState("c"), { ...baseDelta, forensicEvents: [row(velo())] }, ctx);
    const n = mergeDelta(
      s,
      {
        ...baseDelta,
        forensicEvents: [row(thor())],
        iocs: [{ id: "i1", type: "hash", value: HASH, extractedFrom: ["m1e1"] }],
      },
      ctx,
    );
    expect(n.iocs[0].extractedFrom).toEqual(["t2e5"]);
  });
});
