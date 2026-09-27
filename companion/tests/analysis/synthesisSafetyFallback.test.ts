import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SynthMetaStore } from "../../src/analysis/synthMeta.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { safetyRetriesFromEnv } from "../../src/analysis/ai/synthesisFallback.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import {
  ProviderError,
  safetyStopError,
  type AIProvider,
  type AnalyzeRequest,
} from "../../src/providers/provider.js";

// #1734: when the synthesis model's safety filter stops the answer, synthesis runs once on the
// fallback model and stays there for the rest of that synthesis. Always a temp case root.

const GOOD = JSON.stringify({
  summary: "fallback summary",
  findings: [
    {
      id: "f1",
      severity: "High",
      title: "Credential dumping",
      description: "LSASS read",
      relatedIocs: [],
      mitreTechniques: ["T1003.001"],
      status: "open",
    },
  ],
});

let cases: CaseStore;
let stateStore: StateStore;
let synthMetaStore: SynthMetaStore;
let warns: string[];

function ev(id: string): ForensicEvent {
  return {
    id,
    timestamp: "2026-04-22T11:41:00Z",
    description: "LSASS access",
    severity: "Critical",
    mitreTechniques: ["T1003.001"],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset: "WS01",
    sources: ["Sysmon"],
  };
}

const logger = {
  debug: () => undefined,
  info: () => undefined,
  warn: (msg: string) => void warns.push(msg),
  error: () => undefined,
};

function provider(name: string, model: string, answers: Array<string | Error | (() => Error)>) {
  let i = 0;
  const analyze = vi.fn(async (_req: AnalyzeRequest) => {
    const a = answers[Math.min(i++, answers.length - 1)];
    const v = typeof a === "function" ? a() : a;
    if (v instanceof Error) throw v;
    return { rawText: v };
  });
  return { name, model, analyze } satisfies AIProvider;
}

let metrics: Array<Record<string, unknown>>;

function pipeline(primary: AIProvider, fallback?: AIProvider): AnalysisPipeline {
  return new AnalysisPipeline({
    operationalMetrics: { record: async (m: Record<string, unknown>) => void metrics.push(m) } as never,
    stateStore,
    synthMetaStore,
    synthesisProvider: primary,
    synthesisModelLabel: "opus",
    ...(fallback ? { synthesisFallback: { provider: fallback, label: "gpt-6-sol" } } : {}),
    imageLoader: async () => ({ data: Buffer.from(""), mediaType: "image/png" }) as never,
    logger: logger as never,
    retries: 3,
    backoffMs: 0,
  });
}

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-safetyfallback-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  stateStore = new StateStore(cases);
  synthMetaStore = new SynthMetaStore(cases);
  warns = [];
  metrics = [];
  delete process.env.DFIR_AI_SYNTH_SAFETY_RETRIES;
  const s = emptyState("c1");
  s.forensicTimeline.push(ev("a"), ev("b"));
  await stateStore.save(s);
});

afterEach(() => {
  delete process.env.DFIR_AI_SYNTH_SAFETY_RETRIES;
});

describe("synthesis fallback on a safety-filter stop (#1734)", () => {
  it("falls back once and keeps later retries on the fallback model", async () => {
    const primary = provider("claude-code", "opus", [safetyStopError("Claude Code (opus)")]);
    const fallback = provider("codex", "gpt-6-sol", [JSON.stringify({ findings: [] }), GOOD]);
    const state = await pipeline(primary, fallback).synthesize("c1");

    expect(primary.analyze).toHaveBeenCalledTimes(2); // #1740: one retry on the primary first
    expect(fallback.analyze).toHaveBeenCalledTimes(2);
    expect(state.lastSummary).toBe("fallback summary");
    expect(state.findings.map((f) => f.title)).toContain("Credential dumping");

    const log = state.timeline[state.timeline.length - 1].description;
    expect(log).toContain("Synthesis:");
    expect(log).toContain("gpt-6-sol");
    expect(log).toContain("safety filter");
    expect(warns.some((w) => w.includes("safety filter") && w.includes("gpt-6-sol"))).toBe(true);

    const meta = await synthMetaStore.load("c1");
    expect(meta.synthModel).toBe("gpt-6-sol");
  });

  it("fails once with the safety_stop error when no fallback is set", async () => {
    const primary = provider("claude-code", "opus", [safetyStopError("Claude Code (opus)")]);
    await expect(pipeline(primary).synthesize("c1")).rejects.toMatchObject({ kind: "safety_stop" });
    expect(primary.analyze).toHaveBeenCalledTimes(2); // #1740: stopped, retried once, stopped again
  });

  it("does not fall back on any other provider error", async () => {
    const primary = provider("claude-code", "opus", [new ProviderError("blip", "transport"), GOOD]);
    const fallback = provider("codex", "gpt-6-sol", [GOOD]);
    await pipeline(primary, fallback).synthesize("c1");
    expect(primary.analyze).toHaveBeenCalledTimes(2);
    expect(fallback.analyze).not.toHaveBeenCalled();
    expect((await synthMetaStore.load("c1")).synthModel).toBe("opus");
  });

  it("never starts the fallback for a run cancelled while the primary was stopping", async () => {
    const controller = new AbortController();
    const primary = provider("claude-code", "opus", [
      () => {
        controller.abort();
        return safetyStopError("Claude Code (opus)");
      },
    ]);
    const fallback = provider("codex", "gpt-6-sol", [GOOD]);
    await expect(
      pipeline(primary, fallback).synthesize("c1", { signal: controller.signal }),
    ).rejects.toBeDefined();
    expect(fallback.analyze).not.toHaveBeenCalled();
  });

  it("never replaces a provider the caller chose, such as second-opinion model B", async () => {
    const primary = provider("claude-code", "opus", [GOOD]);
    const modelB = provider("openrouter", "b-model", [safetyStopError("model B")]);
    const fallback = provider("codex", "gpt-6-sol", [GOOD]);
    await expect(pipeline(primary, fallback).synthesize("c1", { provider: modelB })).rejects.toMatchObject({
      kind: "safety_stop",
    });
    expect(modelB.analyze).toHaveBeenCalledTimes(2); // #1740: model B keeps its own retry
    expect(fallback.analyze).not.toHaveBeenCalled();
  });
});

describe("one safety retry on the same model before the fallback (#1740)", () => {
  it("keeps the synthesis model when the retry passes, and says so", async () => {
    const primary = provider("claude-code", "opus", [safetyStopError("Claude Code (opus)"), GOOD]);
    const fallback = provider("codex", "gpt-6-sol", [GOOD]);
    const state = await pipeline(primary, fallback).synthesize("c1");
    expect(primary.analyze).toHaveBeenCalledTimes(2);
    expect(fallback.analyze).not.toHaveBeenCalled();
    const log = state.timeline[state.timeline.length - 1].description;
    expect(log).toContain("opus's safety filter stopped the answer 1 time; it passed on retry");
    expect((await synthMetaStore.load("c1")).synthModel).toBe("opus");
    expect(metrics.some((m) => m.type === "ai_retry" && m.errorKind === "safety_stop")).toBe(true);
  });

  it("falls back at once when the setting is 0", async () => {
    process.env.DFIR_AI_SYNTH_SAFETY_RETRIES = "0";
    const primary = provider("claude-code", "opus", [safetyStopError("Claude Code (opus)"), GOOD]);
    const fallback = provider("codex", "gpt-6-sol", [GOOD]);
    await pipeline(primary, fallback).synthesize("c1");
    expect(primary.analyze).toHaveBeenCalledTimes(1);
    expect(fallback.analyze).toHaveBeenCalledTimes(1);
  });

  it("counts the budget across the whole synthesis, not per attempt", async () => {
    const primary = provider("claude-code", "opus", [
      safetyStopError("Claude Code (opus)"),
      JSON.stringify({ findings: [] }), // passes the filter, fails the schema → a parse retry
      safetyStopError("Claude Code (opus)"),
    ]);
    const fallback = provider("codex", "gpt-6-sol", [GOOD]);
    const state = await pipeline(primary, fallback).synthesize("c1");
    expect(primary.analyze).toHaveBeenCalledTimes(3);
    expect(fallback.analyze).toHaveBeenCalledTimes(1);
    expect(state.timeline[state.timeline.length - 1].description).toContain(
      "written by the fallback model gpt-6-sol after opus's safety filter stopped the answer 2 times",
    );
  });

  it("never retries a stop from the fallback model", async () => {
    const primary = provider("claude-code", "opus", [safetyStopError("Claude Code (opus)")]);
    const fallback = provider("codex", "gpt-6-sol", [safetyStopError("Codex (gpt-6-sol)")]);
    await expect(pipeline(primary, fallback).synthesize("c1")).rejects.toMatchObject({ kind: "safety_stop" });
    expect(primary.analyze).toHaveBeenCalledTimes(2);
    expect(fallback.analyze).toHaveBeenCalledTimes(1);
  });

  it("reads the setting strictly: a whole number from 0 to 3, anything else means 1", () => {
    expect(safetyRetriesFromEnv(undefined)).toBe(1);
    expect(safetyRetriesFromEnv("")).toBe(1);
    expect(safetyRetriesFromEnv(" 2 ")).toBe(2);
    expect(safetyRetriesFromEnv("0")).toBe(0);
    expect(safetyRetriesFromEnv("9")).toBe(3);
    for (const bad of ["-1", "1.5", "2x", "x"]) expect(safetyRetriesFromEnv(bad)).toBe(1);
  });
});
