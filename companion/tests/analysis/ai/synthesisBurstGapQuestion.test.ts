import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { buildProposals } from "../../../src/analysis/ai/watson/roundProposals.js";
import type { WatsonQuestionProposal } from "../../../src/analysis/ai/watson/types.js";
import { nextQuestions } from "../../../src/analysis/ai/watson/writers/questionWriter.js";
import { StateStore } from "../../../src/analysis/stateStore.js";
import { CaseStore } from "../../../src/storage/caseStore.js";
import { foldSynthesisDelta, type DeltaFoldContext } from "../../../src/analysis/ai/synthesisMerge.js";
import { BURST_GAP_ID_PREFIX } from "../../../src/analysis/burstGapQuestions.js";
import { deltaSchema } from "../../../src/analysis/responseSchema.js";
import { mergeDelta } from "../../../src/analysis/stateMerge.js";
import { emptyState, type ForensicEvent, type InvestigationState } from "../../../src/analysis/stateTypes.js";

// #2681: the synthesis fold asks a system-made Key Question for a burst row that hid distinct command
// lines, keeps it across runs (it is pinned), and marks it answered once findings cite every hidden id.

const IMAGE = "C:\\ProgramData\\svc\\winupd.exe";
const burst: ForensicEvent[] = Array.from({ length: 20 }, (_, i) => ({
  id: `5e${100 + i}`,
  timestamp: new Date(Date.UTC(2026, 10, 1, 10, 0, i)).toISOString(),
  description: `Sigma: Renamed cmd - Image=${IMAGE} - CommandLine=… /c echo step${i}`,
  severity: "High",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
  asset: "WS-07",
  path: IMAGE,
  commandLine: `"${IMAGE}" /c echo step${i}`,
}));
const membersOf = new Map([[burst[0].id, burst.map((e) => e.id)]]);
const hidden = burst.slice(13).map((e) => e.id);
const qid = `${BURST_GAP_ID_PREFIX}${burst[0].id}`;

function context(stored: InvestigationState): DeltaFoldContext {
  return {
    opts: { stateStore: { load: async () => stored } } as unknown as DeltaFoldContext["opts"],
    mergeWithAliases: async (base, delta, ctx) => mergeDelta(base, delta, ctx),
  };
}

const delta = (relatedEventIds: string[]) =>
  deltaSchema.parse({
    findings: [
      {
        id: "f1",
        severity: "High",
        title: "Renamed cmd ran post-exploitation commands",
        description: "winupd.exe is a renamed cmd.exe",
        relatedIocs: [],
        mitreTechniques: [],
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

async function fold(state: InvestigationState, d: ReturnType<typeof delta>, members = membersOf) {
  const result = await foldSynthesisDelta(context(state), {
    caseId: "c1",
    state,
    delta: d,
    markers: [],
    scopedEvents: state.forensicTimeline,
    playbookTasks: [],
    membersOf: members,
  });
  return result.next;
}

describe("synthesis fold asks about hidden burst lines (#2681)", () => {
  it("asks once, keeps the question on a re-run, and closes it when findings cite every hidden id", async () => {
    const state = { ...emptyState("c1"), forensicTimeline: burst };
    const first = await fold(state, delta([burst[0].id]));
    const q1 = first.keyQuestions.filter((q) => q.id === qid);
    expect(q1).toHaveLength(1);
    expect(q1[0].status).toBe("unknown");
    expect(q1[0].coverageGap?.hiddenEventIds).toEqual(hidden);

    const second = await fold(first, delta([burst[0].id]));
    expect(second.keyQuestions.filter((q) => q.id === qid)).toHaveLength(1);

    const third = await fold(second, delta([burst[0].id, ...hidden]));
    const closed = third.keyQuestions.find((q) => q.id === qid);
    expect(closed?.status).toBe("answered");
    expect(closed?.relatedFindingIds).toEqual(["f1"]);
  });

  it("drops the question when the run's grouping no longer hides lines", async () => {
    const state = { ...emptyState("c1"), forensicTimeline: burst };
    const first = await fold(state, delta([]));
    expect(first.keyQuestions.some((q) => q.id === qid)).toBe(true);
    const next = await fold(first, delta([]), new Map());
    expect(next.keyQuestions.some((q) => q.id === qid)).toBe(false);
  });
});

describe("the burst-gap question survives the store and a Watson answer (#2681)", () => {
  it("round-trips coverageGap through the real state store, whole-case and overview", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-burst-gap-"));
    try {
      const caseStore = new CaseStore(root);
      await caseStore.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
      const store = new StateStore(caseStore);
      const folded = await fold({ ...emptyState("c1"), forensicTimeline: burst }, delta([]));
      await store.save(folded);
      const loaded = (await store.load("c1")).keyQuestions.find((q) => q.id === qid);
      expect(loaded?.coverageGap?.hiddenEventIds).toEqual(hidden);
      const overview = await store.loadOverview("c1");
      await store.saveOverview({ ...overview, updatedAt: "2026-11-18T00:00:00.000Z" });
      const again = (await store.loadOverview("c1")).keyQuestions.find((q) => q.id === qid);
      expect(again?.coverageGap?.hiddenCount).toBe(7);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("keeps the mark and Watson's applied answer across a re-synthesis", async () => {
    const first = await fold({ ...emptyState("c1"), forensicTimeline: burst }, delta([]));
    const reply = {
      questionUpdates: [
        { questionId: qid, status: "answered", answer: "Persistence and LSASS dump", pointer: "5e113" },
      ],
      newQuestions: [],
      writes: [],
    } as unknown as Parameters<typeof buildProposals>[0];
    const [proposal] = buildProposals(reply, first.keyQuestions, "wt-1") as WatsonQuestionProposal[];
    const answered = { ...first, keyQuestions: nextQuestions(first.keyQuestions, proposal, "apply") };
    const again = await fold(answered, delta([]));
    const q = again.keyQuestions.find((x) => x.id === qid);
    expect(q?.status).toBe("answered");
    expect(q?.answer).toBe("Persistence and LSASS dump");
    expect(q?.coverageGap?.hiddenEventIds).toEqual(hidden);
    // A Watson answer is the analyst's record: it stays even when the burst no longer hides lines.
    const gone = await fold(answered, delta([]), new Map());
    expect(gone.keyQuestions.find((x) => x.id === qid)?.answer).toBe("Persistence and LSASS dump");
  });
});
