import { describe, expect, it } from "vitest";
import { foldSynthesisDelta, type DeltaFoldContext } from "../../../src/analysis/ai/synthesisMerge.js";
import { deltaSchema } from "../../../src/analysis/responseSchema.js";
import { mergeDelta } from "../../../src/analysis/stateMerge.js";
import { emptyState, type ForensicEvent, type InvestigationState } from "../../../src/analysis/stateTypes.js";

/**
 * The synthesis fold was the last place that wrote event-carried ATT&CK techniques into PERSISTED
 * state. It made the MITRE panel correct at the moment it ran and permanently wrong afterwards:
 * scope and the false-positive filter drop events at projection rather than from state, and nothing
 * downstream removes an aggregate row — so dismissing the only event carrying a technique left the
 * row behind for good.
 *
 * They are derived at projection now (analysis/eventTechniques.ts). What the fold persists is what
 * the model ASSERTED. #893.
 */

const event = (id: string, techniques: string[]): ForensicEvent => ({
  id,
  timestamp: "2026-06-01T10:00:00.000Z",
  description: `event ${id}`,
  severity: "Medium",
  mitreTechniques: techniques,
  relatedFindingIds: [],
  sourceScreenshots: [],
});

function context(state: InvestigationState): DeltaFoldContext {
  return {
    opts: { stateStore: { load: async () => state } } as unknown as DeltaFoldContext["opts"],
    mergeWithAliases: async (base, delta, ctx) => mergeDelta(base, delta, ctx),
  };
}

const delta = (over: Record<string, unknown> = {}) =>
  deltaSchema.parse({
    findings: [],
    iocs: [],
    mitreTechniques: [],
    threadsOpened: [],
    threadsClosed: [],
    timelineNote: "n",
    summary: "s",
    ...over,
  });

async function fold(state: InvestigationState, d = delta()): Promise<InvestigationState> {
  const result = await foldSynthesisDelta(context(state), {
    caseId: "c1",
    state,
    delta: d,
    markers: [],
    scopedEvents: state.forensicTimeline,
    playbookTasks: [],
  });
  return result.next;
}

describe("synthesis does not persist event-carried techniques (#893)", () => {
  it("leaves a technique only the timeline carries out of the stored table", async () => {
    const state = { ...emptyState("c1"), forensicTimeline: [event("e1", ["T1003.003"])] };

    const next = await fold(state);

    expect(next.mitreTechniques).toEqual([]);
    expect(next.forensicTimeline[0].mitreTechniques).toEqual(["T1003.003"]);
  });

  it("still persists what the model asserted at the top level", async () => {
    const state = { ...emptyState("c1"), forensicTimeline: [event("e1", ["T1003.003"])] };

    const next = await fold(
      state,
      delta({ mitreTechniques: [{ id: "T1486", name: "Data Encrypted for Impact" }] }),
    );

    expect(next.mitreTechniques.map((t) => t.id)).toEqual(["T1486"]);
  });

  it("carries an analyst-accepted technique across the wholesale MITRE replace", async () => {
    // replaceConclusions empties the table so each run rebuilds the model's assessment. An accepted
    // technique is not the model's assessment and has no finding or event to be re-derived from, so
    // the replace erased it — and a later second-opinion run, diffing a case that no longer held it,
    // produced a fresh PENDING delta rather than re-applying the old acceptance.
    const state = {
      ...emptyState("c1"),
      mitreTechniques: [
        { id: "T1486", name: "Data Encrypted for Impact", findingIds: [], analystAccepted: true as const },
      ],
      forensicTimeline: [event("e1", ["T1003.003"])],
    };

    const next = await fold(state);

    expect(next.mitreTechniques.map((t) => t.id)).toEqual(["T1486"]);
    expect(next.mitreTechniques[0].analystAccepted).toBe(true);
  });

  it("keeps the acceptance on a technique the model re-derived this run", async () => {
    // The model naming it too must not quietly downgrade it back to a model-derived row, or the
    // NEXT replace drops it.
    const state = {
      ...emptyState("c1"),
      mitreTechniques: [{ id: "T1486", name: "Old", findingIds: [], analystAccepted: true as const }],
      forensicTimeline: [],
    };

    const next = await fold(
      state,
      delta({ mitreTechniques: [{ id: "T1486", name: "Data Encrypted for Impact" }] }),
    );

    expect(next.mitreTechniques).toHaveLength(1);
    expect(next.mitreTechniques[0]).toMatchObject({
      name: "Data Encrypted for Impact",
      analystAccepted: true,
    });
  });
});
