import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { foldSynthesisDelta, type DeltaFoldContext } from "../../../src/analysis/ai/synthesisMerge.js";
import { CLOUD_KEY_QUESTIONS, CLOUD_SEED_ID_PREFIX } from "../../../src/analysis/cloudKeyQuestions.js";
import { AnalysisPipeline } from "../../../src/analysis/pipeline.js";
import { StateStore } from "../../../src/analysis/stateStore.js";
import type { AIProvider, AnalyzeRequest, AnalyzeResult } from "../../../src/providers/provider.js";
import { CaseStore } from "../../../src/storage/caseStore.js";
import { deltaSchema } from "../../../src/analysis/responseSchema.js";
import { mergeDelta } from "../../../src/analysis/stateMerge.js";
import { emptyState, type ForensicEvent, type InvestigationState } from "../../../src/analysis/stateTypes.js";

/**
 * #2555: on a cloud-only case the cloud key questions are seeded as pinned questions. Synthesis
 * replaces keyQuestions wholesale and the pinned re-merge reads the STORE, which does not hold the
 * seeds before the first run — so the fold must seed them too, or they vanish after one synthesis.
 */

const ual: ForensicEvent = {
  id: "u1",
  timestamp: "2026-11-01T10:00:00.000Z",
  description: "M365 New-InboxRule by alice@example.test",
  severity: "High",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
  sources: ["Microsoft 365"],
};

function context(stored: InvestigationState): DeltaFoldContext {
  return {
    opts: { stateStore: { load: async () => stored } } as unknown as DeltaFoldContext["opts"],
    mergeWithAliases: async (base, delta, ctx) => mergeDelta(base, delta, ctx),
  };
}

const delta = (keyQuestions: unknown[] = []) =>
  deltaSchema.parse({
    findings: [],
    iocs: [],
    mitreTechniques: [],
    threadsOpened: [],
    threadsClosed: [],
    timelineNote: "n",
    summary: "s",
    keyQuestions,
  });

async function fold(state: InvestigationState, cloudOnly: boolean, d = delta()): Promise<InvestigationState> {
  const result = await foldSynthesisDelta(context(state), {
    caseId: "c1",
    state,
    delta: d,
    markers: [],
    scopedEvents: state.forensicTimeline,
    playbookTasks: [],
    cloudOnly,
  });
  return result.next;
}

const seedIds = CLOUD_KEY_QUESTIONS.map((q) => q.id);

describe("synthesis fold seeds the cloud key questions (#2555)", () => {
  it("adds every cloud question, pinned, when the model returned none", async () => {
    const state = { ...emptyState("c1"), forensicTimeline: [ual] };
    const next = await fold(state, true);
    const seeded = next.keyQuestions.filter((q) => seedIds.includes(q.id));
    expect(seeded).toHaveLength(CLOUD_KEY_QUESTIONS.length);
    expect(seeded.every((q) => q.pinned)).toBe(true);
  });

  it("keeps the model's answer to a seed and adds no duplicate on a second run", async () => {
    const state = { ...emptyState("c1"), forensicTimeline: [ual] };
    const [first] = CLOUD_KEY_QUESTIONS;
    const answered = {
      id: first.id,
      question: first.question,
      status: "answered",
      answer: "Yes.",
      pointer: "",
    };
    const once = await fold(state, true, delta([answered]));
    const twice = await fold(once, true, delta([answered]));
    const copies = twice.keyQuestions.filter((q) => q.id === first.id);
    expect(copies).toHaveLength(1);
    expect(copies[0].answer).toBe("Yes.");
    expect(copies[0].pinned).toBe(true);
    expect(twice.keyQuestions.filter((q) => seedIds.includes(q.id))).toHaveLength(CLOUD_KEY_QUESTIONS.length);
  });

  it("seeds nothing on a case that is not cloud-only", async () => {
    const state = { ...emptyState("c1"), forensicTimeline: [{ ...ual, asset: "WS01" }] };
    const next = await fold(state, false);
    expect(next.keyQuestions.some((q) => seedIds.includes(q.id))).toBe(false);
  });
});

// The fold tests pass `cloudOnly` by hand; this runs a real synthesis so the wiring in synthesis.ts
// (prompt-side seeding and the flag handed to the fold) is covered end to end.
describe("synthesize seeds the cloud key questions end to end (#2555)", () => {
  const cannedDelta = JSON.stringify({
    findings: [],
    iocs: [],
    mitreTechniques: [],
    keyQuestions: [
      { id: "q1", question: "Initial access vector?", status: "unknown", answer: "", pointer: "" },
    ],
    attackerPath: "x",
    summary: "s",
    forensicEvents: [],
    threadsOpened: [],
    threadsClosed: [],
    timelineNote: "",
  });

  class CapturingProvider implements AIProvider {
    readonly name = "mock";
    readonly model = "mock-model";
    readonly prompts: string[] = [];
    async analyze(req: AnalyzeRequest): Promise<AnalyzeResult> {
      this.prompts.push(req.userPrompt);
      return { rawText: cannedDelta };
    }
  }

  async function setup(timeline: ForensicEvent[]) {
    const root = await mkdtemp(join(tmpdir(), "dfir-cloud-seed-"));
    const caseStore = new CaseStore(root);
    await caseStore.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
    const stateStore = new StateStore(caseStore);
    await stateStore.save({ ...emptyState("c1"), forensicTimeline: timeline });
    const provider = new CapturingProvider();
    const pipeline = new AnalysisPipeline({
      provider,
      stateStore,
      imageLoader: async () => ({ base64: "A", mimeType: "image/webp" }),
    });
    return { root, stateStore, provider, pipeline };
  }

  it("shows the seeds to the model, stores them pinned, and adds none on a second run", async () => {
    const { root, stateStore, provider, pipeline } = await setup([ual]);
    try {
      await pipeline.synthesize("c1", { force: true });
      expect(provider.prompts[0]).toContain(`[${seedIds[0]}]`);
      const once = await stateStore.load("c1");
      const seeded = once.keyQuestions.filter((q) => seedIds.includes(q.id));
      expect(seeded).toHaveLength(CLOUD_KEY_QUESTIONS.length);
      expect(seeded.every((q) => q.pinned)).toBe(true);

      await pipeline.synthesize("c1", { force: true });
      const twice = await stateStore.load("c1");
      expect(twice.keyQuestions.filter((q) => seedIds.includes(q.id))).toHaveLength(
        CLOUD_KEY_QUESTIONS.length,
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("seeds nothing on a host case", async () => {
    const { root, stateStore, provider, pipeline } = await setup([{ ...ual, asset: "WS01" }]);
    try {
      await pipeline.synthesize("c1", { force: true });
      expect(provider.prompts[0]).not.toContain(CLOUD_SEED_ID_PREFIX);
      const state = await stateStore.load("c1");
      expect(state.keyQuestions.some((q) => seedIds.includes(q.id))).toBe(false);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
