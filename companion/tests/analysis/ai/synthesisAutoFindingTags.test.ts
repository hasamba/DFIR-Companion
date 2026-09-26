import { describe, expect, it } from "vitest";
import { foldSynthesisDelta, type DeltaFoldContext } from "../../../src/analysis/ai/synthesisMerge.js";
import { deltaSchema } from "../../../src/analysis/responseSchema.js";
import { mergeDelta } from "../../../src/analysis/stateMerge.js";
import {
  emptyState,
  type Finding,
  type ForensicEvent,
  type InvestigationState,
} from "../../../src/analysis/stateTypes.js";

/**
 * #1684 — a re-synthesis rewrote the tags on f-auto-8e19 (PsExec64 write) from T1021.002 + T1570 to
 * T1105 + T1059.001 although no fact changed. An f-auto-* finding's tags are the union of its cited
 * events' tags (highSeverityFindings.ts), so the model echoing the id with other tags must not win.
 */

const AUTO = "f-auto-e1";

const event = (id: string, techniques: string[], related: string[] = []): ForensicEvent => ({
  id,
  timestamp: "2026-06-01T10:00:00.000Z",
  description: `PsExec64 written ${id}`,
  severity: "High",
  mitreTechniques: techniques,
  relatedFindingIds: related,
  sourceScreenshots: [],
});

const autoFinding = (techniques: string[]): Finding => ({
  id: AUTO,
  severity: "High",
  confidence: 100,
  title: "PsExec64 written",
  description: "PsExec64 written (auto-flagged from a High-severity artifact row that had no finding).",
  relatedIocs: [],
  mitreTechniques: techniques,
  sourceScreenshots: [],
  firstSeen: "2026-06-01T10:00:00.000Z",
  lastUpdated: "2026-06-01T10:00:00.000Z",
  status: "open",
});

function context(state: InvestigationState): DeltaFoldContext {
  return {
    opts: { stateStore: { load: async () => state } } as unknown as DeltaFoldContext["opts"],
    mergeWithAliases: async (base, delta, ctx) => mergeDelta(base, delta, ctx),
  };
}

const delta = (findings: unknown[]) =>
  deltaSchema.parse({
    findings,
    iocs: [],
    mitreTechniques: [],
    threadsOpened: [],
    threadsClosed: [],
    timelineNote: "",
    summary: "s",
  });

const echo = (techniques: string[], relatedEventIds?: string[]) => ({
  id: AUTO,
  severity: "High",
  title: "PsExec64 written",
  description: "PsExec64 written to the admin share.",
  relatedIocs: [],
  mitreTechniques: techniques,
  status: "open",
  ...(relatedEventIds ? { relatedEventIds } : {}),
});

async function fold(state: InvestigationState, d: ReturnType<typeof delta>): Promise<InvestigationState> {
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

const tagsOf = (state: InvestigationState, id: string): string[] =>
  [...(state.findings.find((f) => f.id === id)?.mitreTechniques ?? [])].sort();

function seeded(): InvestigationState {
  return {
    ...emptyState("c1"),
    forensicTimeline: [event("e1", ["T1021.002", "T1570"], [AUTO])],
    findings: [autoFinding(["T1021.002", "T1570"])],
  };
}

describe("f-auto-* tags follow the cited events across re-synthesis (#1684)", () => {
  it("keeps the event-derived tags when the model echoes the finding with other tags", async () => {
    const first = await fold(seeded(), delta([echo(["T1105", "T1059.001"], ["e1"])]));
    expect(tagsOf(first, AUTO)).toEqual(["T1021.002", "T1570"]);

    const second = await fold(first, delta([echo([], ["e1"])]));
    expect(tagsOf(second, AUTO)).toEqual(["T1021.002", "T1570"]);
  });

  it("keeps them when the model echoes the id without citing the events", async () => {
    const next = await fold(seeded(), delta([echo(["T1105"])]));
    expect(tagsOf(next, AUTO)).toEqual(["T1021.002", "T1570"]);
  });

  it("keeps them when the model leaves the finding out and the backfill re-mints it", async () => {
    const first = await fold(seeded(), delta([]));
    const second = await fold(first, delta([]));
    expect(tagsOf(first, AUTO)).toEqual(["T1021.002", "T1570"]);
    expect(tagsOf(second, AUTO)).toEqual(["T1021.002", "T1570"]);
  });

  it("leaves a model finding's tags to the model", async () => {
    const state = {
      ...emptyState("c1"),
      forensicTimeline: [event("e1", ["T1021.002"], ["f1"])],
    };
    const next = await fold(
      state,
      delta([{ ...echo(["T1105"], ["e1"]), id: "f1", title: "Lateral tool transfer" }]),
    );
    expect(tagsOf(next, "f1")).toEqual(["T1105"]);
  });
});
