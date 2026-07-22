import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { emptyState, type ForensicEvent, type InvestigationState } from "../../src/analysis/stateTypes.js";
import type { AIProvider, AnalyzeRequest, AnalyzeResult } from "../../src/providers/provider.js";

// Observation calls carry the OBSERVE system prompt ("ONE SLICE"); the final call carries the
// synthesis prompt. Splitting on that marker is the same trick tests/server/secondOpinion.test.ts
// uses to tell the synthesis and reconcile passes apart.
class ScriptedProvider implements AIProvider {
  readonly name = "scripted";
  readonly model = "mock-model";
  readonly observeRequests: AnalyzeRequest[] = [];
  readonly synthRequests: AnalyzeRequest[] = [];
  onCall?: () => void;
  constructor(private readonly observations: string, private readonly synth: string) {}
  async analyze(req: AnalyzeRequest): Promise<AnalyzeResult> {
    const isObserve = /ONE SLICE/i.test(req.systemPrompt);
    if (isObserve) this.observeRequests.push(req);
    else this.synthRequests.push(req);
    this.onCall?.();
    return { rawText: isObserve ? this.observations : this.synth };
  }
}

const SYNTH_DELTA = JSON.stringify({
  findings: [], iocs: [], mitreTechniques: [], attackerPath: "", summary: "done",
  forensicEvents: [], threadsOpened: [], threadsClosed: [], timelineNote: "deep pass",
});

const OBSERVATIONS = JSON.stringify({
  observations: [
    { summary: "archive staged", hosts: ["ws-01"], eventIds: ["e0"], whyItMatters: "precedes an upload" },
  ],
});

let caseStore: CaseStore;
let stateStore: StateStore;

// Distinct rule TITLES, not numbered ones. patternKey normalizes bare numbers to <n> (so that
// "robocopy C:\data\1" and "…\2" fingerprint alike), which means "detection number 1" and
// "detection number 2" are ONE pattern and would collapse into a single grouped row — silently
// turning a 250-event fixture into 1 batch. Letters keep every row genuinely distinct.
function ruleTitle(i: number): string {
  const a = "abcdefghijklmnopqrstuvwxyz";
  return `${a[Math.floor(i / 26) % 26]}${a[i % 26]}`;
}

function seedEvents(n: number): ForensicEvent[] {
  return Array.from({ length: n }, (_, i) => ({
    id: `e${i}`,
    timestamp: `2026-05-20T${String(Math.floor(i / 60) % 24).padStart(2, "0")}:${String(i % 60).padStart(2, "0")}:00Z`,
    description: `distinct detection ${ruleTitle(i)}`,
    severity: "High" as const,
    mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [],
  }));
}

async function seed(events: ForensicEvent[]): Promise<InvestigationState> {
  const state: InvestigationState = { ...emptyState("c1"), forensicTimeline: events };
  await stateStore.save(state);
  return state;
}

// retries/backoffMs default to 3 × 500ms exponential in production; a test that deliberately fails a
// batch would then spend seconds sleeping, so failure paths pass a trivial schedule instead.
function makePipeline(provider: AIProvider, opts: { retries?: number; backoffMs?: number } = {}): AnalysisPipeline {
  return new AnalysisPipeline({
    provider,
    stateStore,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    ...opts,
  });
}

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-deeppass-"));
  caseStore = new CaseStore(root);
  await caseStore.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
  stateStore = new StateStore(caseStore);
  process.env.DFIR_AI_SYNTH_MAX_EVENTS = "100";
});

describe("deepPass", () => {
  it("makes one observation call per batch, then exactly one synthesis call", async () => {
    await seed(seedEvents(250));
    const provider = new ScriptedProvider(OBSERVATIONS, SYNTH_DELTA);
    const result = await makePipeline(provider).deepPass("c1", { minSeverity: "High" });

    expect(provider.observeRequests).toHaveLength(3);   // ceil(250 / 100)
    expect(provider.synthRequests).toHaveLength(1);
    expect(result.batches).toBe(3);
    expect(result.aborted).toBe(false);
  });

  it("refuses before spending anything when the batch count exceeds the ceiling", async () => {
    await seed(seedEvents(250));
    const provider = new ScriptedProvider(OBSERVATIONS, SYNTH_DELTA);

    await expect(makePipeline(provider).deepPass("c1", { minSeverity: "High", maxBatches: 2 }))
      .rejects.toThrow(/3 batches/);
    expect(provider.observeRequests).toHaveLength(0);   // nothing spent
    expect(provider.synthRequests).toHaveLength(0);
  });

  it("stops between batches when the abort signal fires and never synthesizes", async () => {
    await seed(seedEvents(250));
    const controller = new AbortController();
    const provider = new ScriptedProvider(OBSERVATIONS, SYNTH_DELTA);
    provider.onCall = () => controller.abort();        // abort once the first batch has been served

    const result = await makePipeline(provider).deepPass("c1", { minSeverity: "High", signal: controller.signal });

    expect(result.aborted).toBe(true);
    expect(provider.synthRequests).toHaveLength(0);     // no final call, so nothing persisted
  });

  it("drops observations citing unknown event ids before the final synthesis", async () => {
    await seed(seedEvents(50));
    const ghost = JSON.stringify({ observations: [{ summary: "ghost claim", eventIds: ["nope-9999"], whyItMatters: "x" }] });
    const provider = new ScriptedProvider(ghost, SYNTH_DELTA);

    const result = await makePipeline(provider).deepPass("c1", { minSeverity: "High" });

    expect(result.observations).toBe(0);
    expect(provider.synthRequests[0].userPrompt).not.toContain("ghost claim");
  });

  it("passes surviving observations into the final synthesis prompt", async () => {
    await seed(seedEvents(50));
    const provider = new ScriptedProvider(OBSERVATIONS, SYNTH_DELTA);

    await makePipeline(provider).deepPass("c1", { minSeverity: "High" });

    expect(provider.synthRequests[0].userPrompt).toContain("DEEP-PASS OBSERVATIONS");
    expect(provider.synthRequests[0].userPrompt).toContain("archive staged");
  });

  it("reports progress for every batch", async () => {
    await seed(seedEvents(250));
    const seen: string[] = [];
    await makePipeline(new ScriptedProvider(OBSERVATIONS, SYNTH_DELTA))
      .deepPass("c1", { minSeverity: "High", onProgress: (_d, _t, detail) => seen.push(detail) });

    expect(seen.filter((s) => /batch/i.test(s))).toHaveLength(3);
    expect(seen.some((s) => /synthesiz/i.test(s))).toBe(true);
  });

  it("returns a run summary the route can serialise", async () => {
    await seed(seedEvents(250));
    const result = await makePipeline(new ScriptedProvider(OBSERVATIONS, SYNTH_DELTA))
      .deepPass("c1", { minSeverity: "High" });

    expect(result.floor).toBe("High");
    expect(result.events).toBe(250);
    expect(result.rows).toBe(250);      // distinct descriptions → nothing groups
    expect(result.batches).toBe(3);
    expect(result.observations).toBeGreaterThan(0);
  });
});

describe("deepPass resilience", () => {
  // A live halcyon run died on batch 1 of 5 with "Bad control character in string literal in JSON":
  // one malformed model response destroyed a 20-minute, 5-call run. Observations are ADDITIVE, so a
  // bad batch must cost that batch's coverage and nothing more.
  class FlakyProvider implements AIProvider {
    readonly name = "flaky";
    readonly model = "mock-model";
    observeCalls = 0;
    synthCalls = 0;
    // Fails the FIRST batch on every attempt it gets, then behaves. `failAttempts` must equal that
    // batch's attempt budget (retries + 1) — size it larger and the later batches get eaten too,
    // which is what made this fixture wrongly report zero observations.
    constructor(private readonly failAttempts: number) {}
    async analyze(req: AnalyzeRequest): Promise<AnalyzeResult> {
      if (/ONE SLICE/i.test(req.systemPrompt)) {
        this.observeCalls++;
        if (this.observeCalls <= this.failAttempts) {
          return { rawText: '{"observations": [{"summary": "bad\ncontrol", ' };
        }
        return { rawText: OBSERVATIONS };
      }
      this.synthCalls++;
      return { rawText: SYNTH_DELTA };
    }
  }

  it("skips a batch whose response never parses and still completes the run", async () => {
    await seed(seedEvents(250));                       // 3 batches at cap 100
    const provider = new FlakyProvider(2);             // first batch is unrecoverable

    const result = await makePipeline(provider, { retries: 1, backoffMs: 1 }).deepPass("c1", { minSeverity: "High" });

    expect(result.aborted).toBe(false);
    expect(result.batchesFailed).toBeGreaterThan(0);
    expect(provider.synthCalls).toBe(1);               // the final synthesis still ran
  });

  it("still collects observations from the batches that did parse", async () => {
    await seed(seedEvents(250));
    const result = await makePipeline(new FlakyProvider(2), { retries: 1, backoffMs: 1 }).deepPass("c1", { minSeverity: "High" });

    expect(result.observations).toBeGreaterThan(0);    // batches 2 and 3 contributed
  });

  it("reports zero failures on a clean run", async () => {
    await seed(seedEvents(250));
    const result = await makePipeline(new ScriptedProvider(OBSERVATIONS, SYNTH_DELTA))
      .deepPass("c1", { minSeverity: "High" });

    expect(result.batchesFailed).toBe(0);
  });
});
