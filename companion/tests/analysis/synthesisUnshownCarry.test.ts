import { describe, expect, it } from "vitest";
import { carryUnshownFindings } from "../../src/analysis/ai/synthesisUnshownCarry.js";
import type { Finding, ForensicEvent, InvestigationState } from "../../src/analysis/stateTypes.js";

const finding = (id: string, title: string): Finding =>
  ({
    id,
    title,
    severity: "Low",
    confidence: 50,
    description: "d",
    mitreTechniques: [],
    relatedEventIds: [],
  }) as unknown as Finding;
const event = (id: string, related: string[]): ForensicEvent =>
  ({ id, relatedFindingIds: related }) as unknown as ForensicEvent;
const state = (findings: Finding[], events: ForensicEvent[] = []): InvestigationState =>
  ({ findings, forensicTimeline: events }) as unknown as InvestigationState;

describe("carryUnshownFindings (#2006)", () => {
  it("keeps an unshown finding the model did not re-emit, with its id and event link", () => {
    const prior = state([finding("f-1", "Alpha"), finding("f-9", "Zulu rare thing")], [event("e1", ["f-9"])]);
    const next = state([finding("f-1", "Alpha")], [event("e1", [])]);
    const r = carryUnshownFindings(next, { prior, echoedIds: new Set(["f-1"]), markers: [] });
    expect(r.carriedCount).toBe(1);
    expect(r.state.findings.map((f) => f.id)).toEqual(["f-1", "f-9"]);
    expect(r.state.findings[1]).toEqual(prior.findings[1]);
    expect(r.state.forensicTimeline[0].relatedFindingIds).toEqual(["f-9"]);
  });

  it("drops the old unshown copy when the model emitted a finding with the same title", () => {
    const prior = state([finding("f-9", "Zulu rare thing")]);
    const next = state([finding("f-new", "zulu  Rare Thing")]);
    const r = carryUnshownFindings(next, { prior, echoedIds: new Set(), markers: [] });
    expect(r.carriedCount).toBe(0);
    expect(r.state.findings.map((f) => f.id)).toEqual(["f-new"]);
  });

  it("drops the old unshown copy when the semantic key matches", () => {
    const a = { ...finding("f-9", "Different words"), semanticKey: "T1059:shell" } as Finding;
    const b = { ...finding("f-new", "Other title"), semanticKey: "T1059:shell" } as Finding;
    const r = carryUnshownFindings(state([b]), { prior: state([a]), echoedIds: new Set(), markers: [] });
    expect(r.state.findings.map((f) => f.id)).toEqual(["f-new"]);
  });

  it("does not duplicate a shown finding, and a shown finding the model dropped stays dropped", () => {
    const prior = state([finding("f-1", "Alpha"), finding("f-2", "Beta")]);
    const next = state([finding("f-1", "Alpha")]);
    const r = carryUnshownFindings(next, { prior, echoedIds: new Set(["f-1", "f-2"]), markers: [] });
    expect(r.carriedCount).toBe(0);
    expect(r.state.findings.map((f) => f.id)).toEqual(["f-1"]);
  });

  it("leaves a finding with the same id as one in this run alone", () => {
    const prior = state([finding("f-9", "Old title")]);
    const next = state([finding("f-9", "New title")]);
    const r = carryUnshownFindings(next, { prior, echoedIds: new Set(), markers: [] });
    expect(r.state.findings).toHaveLength(1);
    expect(r.state.findings[0].title).toBe("New title");
  });
});
