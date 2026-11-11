import { describe, expect, it } from "vitest";
import { foldSynthesisDelta, type DeltaFoldContext } from "../../src/analysis/ai/synthesisMerge.js";
import { refineFindingTechniques } from "../../src/analysis/findingTechniqueRefine.js";
import { deltaSchema } from "../../src/analysis/responseSchema.js";
import { mergeDelta } from "../../src/analysis/stateMerge.js";
import { emptyState, type ForensicEvent, type InvestigationState } from "../../src/analysis/stateTypes.js";

/**
 * #2556 — a model finding kept the parent technique (T1114, T1564) although the rows it cites carry
 * the sub-techniques (T1114.003, T1564.008), and kept a technique none of its rows supports. The
 * refine pass reconciles a model finding's tags with the tags on the events it cites.
 */

const event = (id: string, techniques: string[]): ForensicEvent => ({
  id,
  timestamp: "2026-06-01T10:00:00.000Z",
  description: `row ${id}`,
  severity: "Medium",
  mitreTechniques: techniques,
  relatedFindingIds: [],
  sourceScreenshots: [],
});

const finding = (id: string, techniques: string[], relatedEventIds?: string[], status = "open") => ({
  id,
  severity: "High",
  title: `Finding ${id}`,
  description: "d",
  relatedIocs: [],
  mitreTechniques: techniques,
  status,
  ...(relatedEventIds ? { relatedEventIds } : {}),
});

const delta = (findings: unknown[], table: Array<{ id: string; name: string }> = []) =>
  deltaSchema.parse({
    findings,
    iocs: [],
    mitreTechniques: table,
    threadsOpened: [],
    threadsClosed: [],
    timelineNote: "",
    summary: "s",
  });

const byId = (events: ForensicEvent[]) => new Map(events.map((e) => [e.id, e] as const));

const BEC_EVENTS = [event("e1", ["T1564.008"]), event("e2", ["T1114.003"]), event("e3", [])];

const refine = (findings: unknown[], events: ForensicEvent[], membersOf?: Map<string, string[]>) =>
  refineFindingTechniques(delta(findings), byId(events), membersOf);

const tags = (d: ReturnType<typeof delta>, id = "f4") => d.findings.find((f) => f.id === id)?.mitreTechniques;

describe("refineFindingTechniques (#2556)", () => {
  it("replaces a parent with the sub-technique its cited rows carry, in place", () => {
    const out = refine([finding("f4", ["T1114", "T1564"], ["e1", "e2"])], BEC_EVENTS);
    expect(tags(out)).toEqual(["T1114.003", "T1564.008"]);
  });

  it("drops a technique no cited row supports (the issue's acceptance shape)", () => {
    const out = refine([finding("f4", ["T1114", "T1564", "T1562.008"], ["e1", "e2"])], BEC_EVENTS);
    expect(tags(out)).toEqual(["T1114.003", "T1564.008"]);
  });

  it("keeps a technique a cited row does carry", () => {
    const events = [...BEC_EVENTS, event("e4", ["T1562.008"])];
    const out = refine([finding("f4", ["T1114", "T1564", "T1562.008"], ["e1", "e2", "e4"])], events);
    expect(tags(out)).toEqual(["T1114.003", "T1564.008", "T1562.008"]);
  });

  it("leaves a finding that cites only untagged rows, or nothing, exactly as written", () => {
    const out = refine(
      [finding("f1", ["T1114"], ["e3"]), finding("f2", ["T1059"]), finding("f3", ["T1021"], [])],
      BEC_EVENTS,
    );
    expect(tags(out, "f1")).toEqual(["T1114"]);
    expect(tags(out, "f2")).toEqual(["T1059"]);
    expect(tags(out, "f3")).toEqual(["T1021"]);
  });

  it("never leaves a finding empty: falls back to the cited rows' tags (T1213.002 -> T1530)", () => {
    const events = [event("d1", ["T1530"]), event("d2", ["T1530"])];
    const out = refine([finding("f7", ["T1213.002"], ["d1", "d2"])], events);
    expect(tags(out, "f7")).toEqual(["T1530"]);
  });

  it("keeps a sub-technique on the finding whose base the row carries", () => {
    const out = refine([finding("f1", ["T1059.001"], ["e1"])], [event("e1", ["T1059"])]);
    expect(tags(out, "f1")).toEqual(["T1059.001"]);
  });

  it("replaces a parent with every carried sub-technique, deduped", () => {
    const events = [event("e1", ["T1114.002"]), event("e2", ["T1114.003", "T1114.002"])];
    const out = refine([finding("f1", ["T1114", "T1114.003"], ["e1", "e2"])], events);
    expect(tags(out, "f1")).toEqual(["T1114.002", "T1114.003"]);
  });

  it("leaves f-auto-* findings alone (rederiveAutoFindingTechniques owns them)", () => {
    const out = refine([finding("f-auto-e1", ["T1105"], ["e1"])], [event("e1", ["T1021.002"])]);
    expect(tags(out, "f-auto-e1")).toEqual(["T1105"]);
  });

  it("counts the members of a cited grouped row", () => {
    const events = [event("g1", []), event("m1", ["T1114.003"]), event("m2", ["T1114.003"])];
    const out = refine([finding("f1", ["T1114"], ["g1"])], events, new Map([["g1", ["m1", "m2"]]]));
    expect(tags(out, "f1")).toEqual(["T1114.003"]);
  });

  it("adds a named table row for each technique the pass introduced", () => {
    const d = delta(
      [finding("f4", ["T1114", "T1564"], ["e1", "e2"])],
      [
        { id: "T1114", name: "Email Collection" },
        { id: "T1564", name: "Hide Artifacts" },
      ],
    );
    const out = refineFindingTechniques(d, byId(BEC_EVENTS));
    const added = out.mitreTechniques.filter((t) => t.id.includes("."));
    expect(added.map((t) => t.id).sort()).toEqual(["T1114.003", "T1564.008"]);
    for (const t of added) expect(t.name).toBeTruthy();
  });

  it("does not mutate its input, and returns the same delta when nothing changes", () => {
    const d = delta([finding("f4", ["T1114", "T1564"], ["e1", "e2"])], [{ id: "T1114", name: "Email" }]);
    const snapshot = JSON.parse(JSON.stringify(d));
    const out = refineFindingTechniques(d, byId(BEC_EVENTS));
    expect(d).toEqual(snapshot);
    expect(out).not.toBe(d);
    const untouched = delta([finding("f1", ["T1114.003"], ["e2"])]);
    expect(refineFindingTechniques(untouched, byId(BEC_EVENTS))).toBe(untouched);
  });
});

describe("synthesis fold links the refined sub-technique, not the parent (#2556)", () => {
  function context(state: InvestigationState): DeltaFoldContext {
    return {
      opts: { stateStore: { load: async () => state } } as unknown as DeltaFoldContext["opts"],
      mergeWithAliases: async (base, d, ctx) => mergeDelta(base, d, ctx),
    };
  }

  it("persists the sub-technique on the finding and in the MITRE table", async () => {
    const state: InvestigationState = { ...emptyState("c1"), forensicTimeline: BEC_EVENTS };
    const d = delta(
      [finding("f4", ["T1114", "T1564", "T1562.008"], ["e1", "e2"])],
      [
        { id: "T1114", name: "Email Collection" },
        { id: "T1564", name: "Hide Artifacts" },
        { id: "T1562.008", name: "Disable or Modify Cloud Logs" },
      ],
    );
    const { next } = await foldSynthesisDelta(context(state), {
      caseId: "c1",
      state,
      delta: d,
      markers: [],
      scopedEvents: state.forensicTimeline,
      playbookTasks: [],
    });
    expect(next.findings.find((f) => f.id === "f4")?.mitreTechniques).toEqual(["T1114.003", "T1564.008"]);
    const row = (id: string) => next.mitreTechniques.find((t) => t.id === id);
    expect(row("T1114.003")?.findingIds).toEqual(["f4"]);
    expect(row("T1564.008")?.findingIds).toEqual(["f4"]);
    expect(row("T1114")?.findingIds ?? []).not.toContain("f4");
  });
});
