import { describe, expect, it } from "vitest";
import { foldSynthesisDelta, type DeltaFoldContext } from "../../../src/analysis/ai/synthesisMerge.js";
import type { FalsePositiveMarker } from "../../../src/analysis/falsePositive.js";
import { deltaSchema } from "../../../src/analysis/responseSchema.js";
import { mergeDelta } from "../../../src/analysis/stateMerge.js";
import { emptyState, type ForensicEvent, type InvestigationState } from "../../../src/analysis/stateTypes.js";

/**
 * #2047 — a re-issued finding keeps its prior citations.
 *
 * Run 1 cited event X. Run 2 re-issued the finding by id, cited nothing, and the selection no
 * longer carried X in the prompt. The finding then read as ungrounded to grading and the referee.
 */

const event = (id: string, relatedFindingIds: string[] = []): ForensicEvent => ({
  id,
  timestamp: "2026-08-30T10:00:00.000Z",
  description: `ADSLDP module load (${id})`,
  severity: "High",
  mitreTechniques: ["T1087"],
  relatedFindingIds,
  sourceScreenshots: [],
  asset: "ws01",
});

const priorState = (): InvestigationState => ({
  ...emptyState("c1"),
  forensicTimeline: [event("X", ["f7"]), event("Y")],
  findings: [
    {
      id: "f7",
      severity: "High",
      title: "Likely Active Directory LDAP discovery",
      description: "adsldp.dll loaded by PowerShell.",
      relatedIocs: [],
      mitreTechniques: ["T1087"],
      status: "open",
      relatedEventIds: ["X"],
      sourceScreenshots: [],
      firstSeen: "2026-08-30T10:00:00.000Z",
      lastUpdated: "2026-08-30T10:00:00.000Z",
    },
  ],
});

const delta = (id: string, relatedEventIds: string[] = []) =>
  deltaSchema.parse({
    findings: [
      {
        id,
        severity: "High",
        title: "Likely Active Directory LDAP discovery",
        description: "Earlier analysis found LDAP discovery.",
        relatedIocs: [],
        mitreTechniques: ["T1087"],
        status: "open",
        relatedEventIds,
      },
    ],
    iocs: [],
    mitreTechniques: [],
    threadsOpened: [],
    threadsClosed: [],
    timelineNote: "",
    summary: "s",
  });

function context(state: InvestigationState): DeltaFoldContext {
  return {
    opts: { stateStore: { load: async () => state } } as unknown as DeltaFoldContext["opts"],
    mergeWithAliases: async (base, d, ctx) => mergeDelta(base, d, ctx),
  };
}

async function fold(
  d: ReturnType<typeof delta>,
  o: { echoed?: string[]; markers?: FalsePositiveMarker[]; scoped?: string[] } = {},
) {
  const state = priorState();
  const scoped = state.forensicTimeline.filter((e) => (o.scoped ?? ["X", "Y"]).includes(e.id));
  return foldSynthesisDelta(context(state), {
    caseId: "c1",
    state,
    delta: d,
    markers: o.markers ?? [],
    scopedEvents: scoped,
    playbookTasks: [],
    ...(o.echoed ? { echoedFindingIds: new Set(o.echoed) } : {}),
  });
}

const cited = (s: InvestigationState, id: string) => s.findings.find((f) => f.id === id)?.relatedEventIds;

describe("a re-issued finding keeps its prior citations (#2047)", () => {
  it("takes back the prior citation when the re-issue cites nothing", async () => {
    const { next, inheritedCitations } = await fold(delta("f7"), { echoed: ["f7"] });
    expect(cited(next, "f7")).toEqual(["X"]);
    expect(next.forensicTimeline.find((e) => e.id === "X")?.relatedFindingIds).toContain("f7");
    expect(inheritedCitations).toEqual([{ findingId: "f7", eventIds: ["X"] }]);
  });

  it("leaves the model's own citations alone", async () => {
    const { next, inheritedCitations } = await fold(delta("f7", ["Y"]), { echoed: ["f7"] });
    expect(cited(next, "f7")).toEqual(["Y"]);
    expect(inheritedCitations).toEqual([]);
  });

  it("does not inherit an event the analyst marked false-positive", async () => {
    const marker = { id: "event:X", kind: "event", ref: "X" } as FalsePositiveMarker;
    const { next } = await fold(delta("f7"), { echoed: ["f7"], markers: [marker] });
    expect(cited(next, "f7") ?? []).toEqual([]);
  });

  it("does not inherit an event outside this run's scope", async () => {
    const { next } = await fold(delta("f7"), { echoed: ["f7"], scoped: ["Y"] });
    expect(cited(next, "f7") ?? []).toEqual([]);
  });

  it("does not inherit on a dry run (no echoed ids passed)", async () => {
    const { next } = await fold(delta("f7"));
    expect(cited(next, "f7") ?? []).toEqual([]);
  });

  it("does not inherit for a finding the model was not shown", async () => {
    const { next } = await fold(delta("f7"), { echoed: ["f1"] });
    expect(cited(next, "f7") ?? []).toEqual([]);
  });

  it("does not inherit for a genuinely new id", async () => {
    const { next } = await fold(delta("f99"), { echoed: ["f7", "f99"] });
    expect(cited(next, "f99") ?? []).toEqual([]);
  });
});
