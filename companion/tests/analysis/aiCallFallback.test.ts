import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { callAiJson, type AiCallContext } from "../../src/analysis/ai/aiContext.js";
import { withRetry } from "../../src/analysis/ai/retry.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import {
  ProviderError,
  safetyStopError,
  type AIProvider,
  type AnalyzeRequest,
  type AnalyzeResult,
} from "../../src/providers/provider.js";

// #2083: the one-click AI actions that run on the synthesis model — Explain event, the view reports
// and the default second-opinion referee — follow the synthesis safety-stop rule: retry on the
// primary per DFIR_AI_SYNTH_SAFETY_RETRIES, then answer on DFIR_AI_SYNTH_FALLBACK_MODEL. Opt-in per
// call site; a model the analyst picked for the work never falls back.

/** Stops every answer with the provider's safety_stop. */
class Stopped implements AIProvider {
  calls = 0;
  constructor(
    readonly name = "claude-code",
    readonly model = "opus",
  ) {}
  async analyze(_req: AnalyzeRequest): Promise<AnalyzeResult> {
    this.calls++;
    throw safetyStopError("Claude Code (opus)");
  }
}

/** Answers every call with the same JSON. */
class Answers implements AIProvider {
  calls = 0;
  constructor(
    private readonly body: object,
    readonly name = "codex",
    readonly model = "gpt-6-sol",
  ) {}
  async analyze(_req: AnalyzeRequest): Promise<AnalyzeResult> {
    this.calls++;
    return { rawText: JSON.stringify(this.body) };
  }
}

/** Fails every call with a non-safety error. */
class Broken implements AIProvider {
  readonly name = "claude-code";
  readonly model = "opus";
  calls = 0;
  async analyze(_req: AnalyzeRequest): Promise<AnalyzeResult> {
    this.calls++;
    throw new ProviderError("context window exceeded", "context");
  }
}

interface Fake {
  ctx: AiCallContext;
  warnings: string[];
  retried: string[];
}

function fakeCtx(primary: AIProvider, fallback?: AIProvider, safetyRetries = 1): Fake {
  const warnings: string[] = [];
  const retried: string[] = [];
  const ctx: AiCallContext = {
    opts: {
      synthesisProvider: primary,
      synthesisModelLabel: "opus",
      ...(fallback ? { synthesisFallback: { provider: fallback, label: "gpt-6-sol" } } : {}),
      synthesisSafetyRetries: safetyRetries,
      stateStore: {} as AiCallContext["opts"]["stateStore"],
      retries: 0,
      backoffMs: 0,
    },
    log: {
      debug: () => undefined,
      info: () => undefined,
      warn: (msg: string) => void warnings.push(msg),
      error: () => undefined,
    } as unknown as NonNullable<AiCallContext["log"]>,
    requireProvider: () => primary,
    getKevCatalog: async () => undefined,
    withRetry: (_c, _l, fn, retries, backoffMs) => withRetry(fn, retries, backoffMs),
    recordRetry: (_c, label) => void retried.push(label),
    analyzeRestored: async (_c, _s, provider, req) =>
      JSON.parse((await provider.analyze(req)).rawText ?? "null") as unknown,
  };
  return { ctx, warnings, retried };
}

const parseAnswer = (raw: unknown) => (raw as { answer: string }).answer;
const state = emptyState("c1");

function call(ctx: AiCallContext, provider: AIProvider, opts?: Parameters<typeof callAiJson>[8]) {
  return callAiJson(ctx, "c1", state, provider, "explain-event", "sys", "user", parseAnswer, opts);
}

describe("callAiJson safety-stop fallback (#2083)", () => {
  it("answers on the fallback once the primary's safety retries run out", async () => {
    const primary = new Stopped();
    const fallback = new Answers({ answer: "from fallback" });
    const { ctx, warnings, retried } = fakeCtx(primary, fallback, 1);
    const used: string[] = [];

    const out = await call(ctx, primary, {
      safetyFallback: { task: "explain event", onFallback: (l) => void used.push(l) },
    });

    expect(out).toBe("from fallback");
    expect(primary.calls).toBe(2); // 1 + DFIR_AI_SYNTH_SAFETY_RETRIES
    expect(fallback.calls).toBe(1);
    expect(used).toEqual(["gpt-6-sol"]);
    expect(retried).toEqual(["explain-event"]);
    expect(warnings.some((w) => /fallback model gpt-6-sol/.test(w))).toBe(true);
  });

  it("without the opt-in a safety stop is rethrown after one attempt", async () => {
    const primary = new Stopped();
    const fallback = new Answers({ answer: "x" });
    const { ctx } = fakeCtx(primary, fallback, 1);

    await expect(call(ctx, primary)).rejects.toMatchObject({ kind: "safety_stop" });
    expect(primary.calls).toBe(1);
    expect(fallback.calls).toBe(0);
  });

  it("never falls back for a provider that is not the synthesis model", async () => {
    const primary = new Answers({ answer: "unused" }, "claude-code", "opus");
    const picked = new Stopped("velociraptor", "small");
    const fallback = new Answers({ answer: "x" });
    const { ctx } = fakeCtx(primary, fallback, 1);

    await expect(call(ctx, picked, { safetyFallback: { task: "explain event" } })).rejects.toMatchObject({
      kind: "safety_stop",
    });
    expect(picked.calls).toBe(1);
    expect(fallback.calls).toBe(0);
  });

  it("with no fallback set, the exhaustion error names the task and the setting", async () => {
    const primary = new Stopped();
    const { ctx } = fakeCtx(primary, undefined, 1);

    const err = await call(ctx, primary, { safetyFallback: { task: "explain event" } }).catch((e) => e);
    expect(err).toBeInstanceOf(ProviderError);
    expect(err.kind).toBe("safety_stop");
    expect(err.message).toContain("stopped the explain event answer 2 times");
    expect(err.message).toContain("DFIR_AI_SYNTH_FALLBACK_MODEL");
    expect(err.message).not.toContain("synthesis answer");
    expect(primary.calls).toBe(2);
  });

  it("a non-safety error never touches the fallback", async () => {
    const primary = new Broken();
    const fallback = new Answers({ answer: "x" });
    const { ctx } = fakeCtx(primary, fallback, 1);

    await expect(call(ctx, primary, { safetyFallback: { task: "explain event" } })).rejects.toMatchObject({
      kind: "context",
    });
    expect(primary.calls).toBe(1);
    expect(fallback.calls).toBe(0);
  });

  it("a call aborted after the stop never reaches the fallback", async () => {
    const controller = new AbortController();
    const primary: AIProvider = {
      name: "claude-code",
      model: "opus",
      analyze: async () => {
        controller.abort();
        throw safetyStopError("Claude Code (opus)");
      },
    };
    const fallback = new Answers({ answer: "x" });
    const { ctx } = fakeCtx(primary, fallback, 0);

    await expect(
      call(ctx, primary, { safetyFallback: { task: "explain event" }, signal: controller.signal }),
    ).rejects.toThrow();
    expect(fallback.calls).toBe(0);
  });

  it("does not report a fallback when the primary answers", async () => {
    const primary = new Answers({ answer: "primary" }, "claude-code", "opus");
    const fallback = new Answers({ answer: "x" });
    const { ctx } = fakeCtx(primary, fallback, 1);
    const used: string[] = [];

    const out = await call(ctx, primary, {
      safetyFallback: { task: "explain event", onFallback: (l) => void used.push(l) },
    });
    expect(out).toBe("primary");
    expect(used).toEqual([]);
    expect(fallback.calls).toBe(0);
  });
});

// --- Through the pipeline: Explain event and the view reports opt in --------------------------

function ev(p: Partial<ForensicEvent> & { id: string }): ForensicEvent {
  return {
    timestamp: "2026-01-01T00:00:00Z",
    description: "powershell.exe spawned by WINWORD.EXE",
    severity: "High",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...p,
  };
}

const EXPLANATION = {
  summary: "fallback explanation",
  whyItMatters: "w",
  normalContext: "n",
  suspiciousIndicators: "s",
  attackMapping: "a",
  pivotQueries: [],
  evidenceFor: "f",
  evidenceAgainst: "g",
  relatedEventIds: ["e1"],
};

async function pipelineWith(primary: AIProvider, fallback: AIProvider): Promise<AnalysisPipeline> {
  const root = await mkdtemp(join(tmpdir(), "dfir-aicall-fb-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(cases);
  const s = emptyState("c1");
  s.forensicTimeline = [ev({ id: "e1" })];
  await stateStore.save(s);
  const superTimelineStore = new SuperTimelineStore(cases);
  await superTimelineStore.append("c1", [ev({ id: "e1" })]);
  return new AnalysisPipeline({
    provider: primary,
    synthesisProvider: primary,
    synthesisModelLabel: "opus",
    synthesisFallback: { provider: fallback, label: "gpt-6-sol" },
    synthesisSafetyRetries: 0,
    stateStore,
    superTimelineStore,
    imageLoader: async () => ({ base64: "", mimeType: "image/webp" }),
    retries: 0,
    backoffMs: 0,
  });
}

describe("one-click AI actions fall back on a safety stop (#2083)", () => {
  it("Explain event returns the fallback's explanation", async () => {
    const primary = new Stopped();
    const fallback = new Answers(EXPLANATION);
    const result = await (await pipelineWith(primary, fallback)).explainEvent("c1", "e1");

    expect(result.summary).toBe("fallback explanation");
    expect(primary.calls).toBe(1);
    expect(fallback.calls).toBe(1);
  });

  it("the starred report returns the fallback's markdown", async () => {
    const primary = new Stopped();
    const fallback = new Answers({ markdown: "# from fallback" });
    const result = await (await pipelineWith(primary, fallback)).starredReport("c1", ["e1"]);

    expect(result.markdown).toContain("# from fallback");
    expect(fallback.calls).toBe(1);
  });

  it("View summary returns the fallback's markdown", async () => {
    const primary = new Stopped();
    const fallback = new Answers({ markdown: "# view from fallback" });
    const result = await (await pipelineWith(primary, fallback)).viewSummary("c1", {});

    expect(result.markdown).toContain("# view from fallback");
    expect(fallback.calls).toBe(1);
  });
});
