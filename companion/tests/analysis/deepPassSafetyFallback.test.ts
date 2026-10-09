import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { AnalysisRunStore } from "../../src/analysis/analysisRunStore.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import {
  ProviderError,
  safetyStopError,
  type AIProvider,
  type AnalyzeRequest,
  type AnalyzeResult,
} from "../../src/providers/provider.js";

// #2076: a safety stop on a deep-pass batch read retries on the primary, then reads that batch on
// the configured fallback model — the same rule synthesis follows (#1734/#1740). Before this the
// stop cost the whole batch. Always a temp case root.

const SYNTH_DELTA = JSON.stringify({
  findings: [],
  iocs: [],
  mitreTechniques: [],
  attackerPath: "",
  summary: "done",
  forensicEvents: [],
  threadsOpened: [],
  threadsClosed: [],
  timelineNote: "deep pass",
});

const observations = (id: string) =>
  JSON.stringify({
    observations: [{ summary: `seen ${id}`, hosts: ["ws-01"], eventIds: [id], whyItMatters: "matters" }],
  });

const isObserve = (req: AnalyzeRequest) => /ONE SLICE/i.test(req.systemPrompt);

/** Answers observe calls through `onObserve` (call index, request); synthesis always answers. */
class Scripted implements AIProvider {
  readonly observeCalls: AnalyzeRequest[] = [];
  constructor(
    readonly name: string,
    readonly model: string,
    private readonly onObserve: (index: number, req: AnalyzeRequest) => string | Error,
  ) {}
  async analyze(req: AnalyzeRequest): Promise<AnalyzeResult> {
    if (!isObserve(req)) return { rawText: SYNTH_DELTA };
    const answer = this.onObserve(this.observeCalls.length, req);
    this.observeCalls.push(req);
    if (answer instanceof Error) throw answer;
    return { rawText: answer };
  }
}

const inBatch1 = (req: AnalyzeRequest) => req.userPrompt.includes("[e0] ");
const fallbackAnswers = () => new Scripted("codex", "gpt-6-sol", () => observations("e0"));

let caseStore: CaseStore;
let stateStore: StateStore;
let runStore: AnalysisRunStore;
let warns: string[];

const logger = {
  debug: () => undefined,
  info: () => undefined,
  warn: (msg: string) => void warns.push(msg),
  error: () => undefined,
};

function seedEvents(n: number): ForensicEvent[] {
  const a = "abcdefghijklmnopqrstuvwxyz";
  return Array.from({ length: n }, (_, i) => ({
    id: `e${i}`,
    timestamp: `2026-05-20T${String(Math.floor(i / 60) % 24).padStart(2, "0")}:${String(i % 60).padStart(2, "0")}:00Z`,
    description: `distinct detection ${a[Math.floor(i / 26) % 26]}${a[i % 26]}`,
    severity: "High" as const,
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
  }));
}

function pipeline(primary: AIProvider, fallback?: AIProvider): AnalysisPipeline {
  return new AnalysisPipeline({
    stateStore,
    analysisRunStore: runStore,
    synthesisProvider: primary,
    synthesisModelLabel: "opus",
    ...(fallback ? { synthesisFallback: { provider: fallback, label: "gpt-6-sol" } } : {}),
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    logger: logger as never,
    retries: 1,
    backoffMs: 0,
  });
}

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-deeppass-fallback-"));
  caseStore = new CaseStore(root);
  await caseStore.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
  stateStore = new StateStore(caseStore);
  runStore = new AnalysisRunStore(caseStore, { appVersion: "0.0.0-test" });
  warns = [];
  process.env.DFIR_AI_SYNTH_MAX_EVENTS = "100";
  await stateStore.save({ ...emptyState("c1"), forensicTimeline: seedEvents(150) }); // 2 batches
});

afterEach(() => {
  delete process.env.DFIR_AI_CONTEXT_TOKENS;
});

describe("deep pass falls back on a safety stop (#2076)", () => {
  it("reads a stopped batch on the fallback model instead of losing it", async () => {
    const primary = new Scripted("claude-code", "opus", (_i, req) =>
      inBatch1(req) ? safetyStopError("Claude Code (opus)") : observations("e100"),
    );
    const fallback = fallbackAnswers();
    const result = await pipeline(primary, fallback).deepPass("c1", { minSeverity: "High" });

    expect(result.batchesFailed).toBe(0);
    expect(result.batchesOnFallback).toBe(1);
    expect(result.fallbackModel).toBe("gpt-6-sol");
    expect(result.observations).toBe(2); // batch 1 via the fallback, batch 2 via the primary
    expect(primary.observeCalls.filter(inBatch1)).toHaveLength(2); // stopped, retried once, stopped
    expect(fallback.observeCalls).toHaveLength(1);
    expect(fallback.observeCalls.every(inBatch1)).toBe(true); // batch 2 stays on the primary
    expect(warns.some((w) => w.includes("safety filter") && w.includes("gpt-6-sol"))).toBe(true);
  });

  it("starts every batch on the primary again", async () => {
    // Batch 1 stopped → fallback; batch 2 answered by the primary.
    const primary = new Scripted("claude-code", "opus", (_i, req) =>
      inBatch1(req) ? safetyStopError("Claude Code (opus)") : observations("e100"),
    );
    const fallback = fallbackAnswers();
    await pipeline(primary, fallback).deepPass("c1", { minSeverity: "High" });
    expect(primary.observeCalls.filter((r) => !inBatch1(r))).toHaveLength(1);
  });

  it("without a fallback, counts the batch failed and names the setting and the deep pass", async () => {
    const primary = new Scripted("claude-code", "opus", (_i, req) =>
      inBatch1(req) ? safetyStopError("Claude Code (opus)") : observations("e100"),
    );
    const result = await pipeline(primary).deepPass("c1", { minSeverity: "High" });

    expect(result.batchesFailed).toBe(1);
    expect(result.batchesOnFallback).toBe(0);
    expect(result.fallbackModel).toBeUndefined();
    const failure = warns.find((w) => w.includes("batch 1/2"));
    expect(failure).toContain("stopped the deep-pass answer");
    expect(failure).toContain("DFIR_AI_SYNTH_FALLBACK_MODEL");
    expect(failure).not.toContain("synthesis answer");
  });

  it("never falls back for a model the analyst chose for this run", async () => {
    const chosen = new Scripted("chosen", "m", (_i, req) =>
      inBatch1(req) ? safetyStopError("chosen") : observations("e100"),
    );
    const primary = new Scripted("claude-code", "opus", () => observations("e100"));
    const fallback = fallbackAnswers();
    const result = await pipeline(primary, fallback).deepPass("c1", {
      minSeverity: "High",
      provider: chosen,
    });

    expect(result.batchesFailed).toBe(1);
    expect(fallback.observeCalls).toHaveLength(0);
    expect(chosen.observeCalls.filter(inBatch1)).toHaveLength(2); // its safety retry still runs
  });

  it("does not fall back on any other error", async () => {
    const primary = new Scripted("claude-code", "opus", (_i, req) =>
      inBatch1(req) ? new ProviderError("bad request", "context") : observations("e100"),
    );
    const fallback = fallbackAnswers();
    const result = await pipeline(primary, fallback).deepPass("c1", { minSeverity: "High" });

    expect(result.batchesFailed).toBe(1);
    expect(fallback.observeCalls).toHaveLength(0);
  });

  it("a run cancelled at the stop never calls the fallback", async () => {
    const controller = new AbortController();
    const primary = new Scripted("claude-code", "opus", () => {
      controller.abort();
      return safetyStopError("Claude Code (opus)");
    });
    const fallback = fallbackAnswers();
    const result = await pipeline(primary, fallback).deepPass("c1", {
      minSeverity: "High",
      signal: controller.signal,
    });

    expect(result.aborted).toBe(true);
    expect(primary.observeCalls).toHaveLength(1);
    expect(fallback.observeCalls).toHaveLength(0);
  });

  it("the run record says how many batches the fallback read; the configured model stays", async () => {
    const primary = new Scripted("claude-code", "opus", (_i, req) =>
      inBatch1(req) ? safetyStopError("Claude Code (opus)") : observations("e100"),
    );
    await pipeline(primary, fallbackAnswers()).deepPass("c1", { minSeverity: "High" });

    const record = (await runStore.list("c1")).find((r) => r.kind === "deep-pass");
    expect(record?.configuration?.provider).toBe("claude-code");
    expect(record?.configuration?.model).toBe("opus");
    expect(record?.execution?.warnings).toContain(
      "1 batch(es) answered by the fallback model gpt-6-sol after opus's safety filter stopped them",
    );
  });

  it("a condense group that is stopped is also read on the fallback", async () => {
    process.env.DFIR_AI_CONTEXT_TOKENS = "1"; // budget ≤ 0 → every round condenses
    await stateStore.save({ ...emptyState("c1"), forensicTimeline: seedEvents(10) }); // 1 batch
    // The batch read answers; every condense call after it is stopped.
    const primary = new Scripted("claude-code", "opus", (i) =>
      i === 0 ? observations("e0") : safetyStopError("Claude Code (opus)"),
    );
    const fallback = fallbackAnswers();
    const result = await pipeline(primary, fallback).deepPass("c1", { minSeverity: "High" });

    expect(result.batchesFailed).toBe(0);
    expect(fallback.observeCalls.length).toBeGreaterThan(0);
    expect(result.batchesOnFallback).toBe(fallback.observeCalls.length);
  });
});
