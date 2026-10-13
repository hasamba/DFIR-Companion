import { describe, it, expect } from "vitest";
import { mergeDelta } from "../../src/analysis/stateMerge.js";
import { emptyState, type ForensicEvent, type Severity } from "../../src/analysis/stateTypes.js";
import { applyToForensicEvent } from "../../src/analysis/tagger.js";
import type { AnalysisDelta } from "../../src/analysis/responseSchema.js";

// #2182: a re-import restates a row's raw import grade. When the tagger raised that row, the merge
// keeps the higher of the restated grade and the tagger's grade, so the demote gate cannot drop it.

const baseDelta: AnalysisDelta = {
  findings: [],
  iocs: [],
  mitreTechniques: [],
  threadsOpened: [],
  threadsClosed: [],
  timelineNote: "",
  summary: "",
};

const restated = (severity: Severity) => ({
  id: "e1",
  timestamp: "2026-07-01T10:00:00.000Z",
  description: "The Print Spooler service entered the running state.",
  severity,
  mitreTechniques: [],
  relatedFindingIds: [],
});
const row = (severity: Severity, extra: Partial<ForensicEvent> = {}): ForensicEvent => ({
  ...restated(severity),
  sourceScreenshots: [],
  ...extra,
});
const reimport = {
  windowSequence: -1,
  timestamp: "2026-10-13T09:00:00.000Z",
  sourceScreenshots: ["a-again.json"],
};
const held = (e: ForensicEvent) => ({ ...emptyState("c1"), forensicTimeline: [e] });
const merge = (existing: ForensicEvent, incoming: Severity, ctx: object = {}) =>
  mergeDelta(held(existing), { ...baseDelta, forensicEvents: [restated(incoming)] }, { ...reimport, ...ctx })
    .forensicTimeline[0];

describe("merge keeps a tagger-raised grade (#2182)", () => {
  it("a re-import restating the raw Info grade keeps High and records no revision", () => {
    const out = merge(row("High", { taggerRaisedFrom: "Info" }), "Info");
    expect(out.severity).toBe("High");
    expect(out.taggerRaisedFrom).toBe("Info");
    expect(out.revisions).toBeUndefined();
  });

  it("a raw grade above the tagger's grade lands, clears the marker and is recorded", () => {
    const out = merge(row("High", { taggerRaisedFrom: "Info" }), "Critical");
    expect(out.severity).toBe("Critical");
    expect(out.taggerRaisedFrom).toBeUndefined();
    expect(out.revisions?.[0].severity).toEqual({ from: "High", to: "Critical" });
  });

  it("a lower raw grade still under the tagger's grade keeps High and moves the marker", () => {
    const out = merge(row("High", { taggerRaisedFrom: "Info" }), "Low");
    expect(out.severity).toBe("High");
    expect(out.taggerRaisedFrom).toBe("Low");
    expect(out.revisions).toBeUndefined();
  });

  it("a row the tagger never raised still takes the lower grade and records it (#2141)", () => {
    const out = merge(row("High"), "Info");
    expect(out.severity).toBe("Info");
    expect(out.revisions?.[0].severity).toEqual({ from: "High", to: "Info" });
  });

  it("a lab-setup row keeps its capped tagger grade on re-import", () => {
    const lab = { labSetup: { tag: "lab-setup", folder: "\\vmwarednd\\" } } as Partial<ForensicEvent>;
    const out = merge(row("Medium", { taggerRaisedFrom: "Info", ...lab }), "Info");
    expect(out.severity).toBe("Medium");
    expect(out.revisions).toBeUndefined();
  });

  it("an MCP agent may still lower a tagger-raised grade, and the change is recorded", () => {
    const out = merge(row("High", { taggerRaisedFrom: "Info" }), "Low", { changeSource: "MCP agent: vt" });
    expect(out.severity).toBe("Low");
    expect(out.taggerRaisedFrom).toBeUndefined();
    expect(out.revisions?.[0]).toMatchObject({
      source: "MCP agent: vt",
      severity: { from: "High", to: "Low" },
    });
  });
});

describe("applyToForensicEvent stamps the grade it raised from (#2182)", () => {
  const result = (severity: Severity) => ({ eventId: "e1", tags: [], mitre: [], severity, ruleIds: ["r"] });

  it("stamps the pre-raise grade", () => {
    expect(applyToForensicEvent(row("Info"), result("High")).taggerRaisedFrom).toBe("Info");
  });

  it("keeps the first marker on a second raise", () => {
    const once = applyToForensicEvent(row("Info"), result("Medium"));
    expect(applyToForensicEvent(once, result("High")).taggerRaisedFrom).toBe("Info");
  });

  it("does not stamp a row it does not raise", () => {
    expect(applyToForensicEvent(row("High"), result("Medium")).taggerRaisedFrom).toBeUndefined();
    const collector = row("Info", { origin: "collector" });
    expect(applyToForensicEvent(collector, result("High")).taggerRaisedFrom).toBeUndefined();
  });
});
