import { describe, it, expect, beforeEach, vi } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SynthMetaStore } from "../../src/analysis/synthMeta.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
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

function pipeline(primary: AIProvider, fallback?: AIProvider): AnalysisPipeline {
  return new AnalysisPipeline({
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
  const s = emptyState("c1");
  s.forensicTimeline.push(ev("a"), ev("b"));
  await stateStore.save(s);
});

describe("synthesis fallback on a safety-filter stop (#1734)", () => {
  it("falls back once and keeps later retries on the fallback model", async () => {
    const primary = provider("claude-code", "opus", [safetyStopError("Claude Code (opus)")]);
    const fallback = provider("codex", "gpt-6-sol", [JSON.stringify({ findings: [] }), GOOD]);
    const state = await pipeline(primary, fallback).synthesize("c1");

    expect(primary.analyze).toHaveBeenCalledTimes(1);
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
    expect(primary.analyze).toHaveBeenCalledTimes(1);
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
    expect(modelB.analyze).toHaveBeenCalledTimes(1);
    expect(fallback.analyze).not.toHaveBeenCalled();
  });
});
