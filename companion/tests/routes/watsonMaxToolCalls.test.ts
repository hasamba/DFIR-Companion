import { describe, expect, it } from "vitest";
import { watsonMaxToolCalls, watsonRoundDeps } from "../../src/routes/watsonDeps.js";
import type { RouteContext } from "../../src/routes/context.js";

// Watson phase 5, Task 6 (D13): the "Watson lookups per question" setting, and the round deps that
// carry it and the per-send stop check into the round.

function ctxOf(o: { status?: string; enabled?: boolean } = {}) {
  return {
    options: { watsonChatStore: {}, watsonProvider: () => ({ name: "fake" }) },
    store: { getCaseMeta: async () => ({ status: o.status ?? "open" }) },
    getControl: async () => ({ enabled: o.enabled ?? true }),
    markConclusionsOutOfDate: async () => undefined,
  } as unknown as RouteContext;
}

describe("watsonMaxToolCalls (D13)", () => {
  it.each([
    [undefined, 4],
    ["", 4],
    ["junk", 4],
    ["-1", 4],
    ["0", 0],
    ["3", 3],
    ["2.7", 2],
    ["99", 10],
  ])("%s → %s", (raw, want) => {
    expect(watsonMaxToolCalls({ DFIR_AI_WATSON_MAX_TOOL_CALLS: raw })).toBe(want);
  });
});

describe("watsonRoundDeps carries the tool cap and the stop check", () => {
  it("reads DFIR_AI_WATSON_MAX_TOOL_CALLS per call", () => {
    const old = process.env.DFIR_AI_WATSON_MAX_TOOL_CALLS;
    try {
      process.env.DFIR_AI_WATSON_MAX_TOOL_CALLS = "3";
      expect(watsonRoundDeps(ctxOf())?.maxToolCalls).toBe(3);
      delete process.env.DFIR_AI_WATSON_MAX_TOOL_CALLS;
      expect(watsonRoundDeps(ctxOf())?.maxToolCalls).toBe(4);
    } finally {
      if (old === undefined) delete process.env.DFIR_AI_WATSON_MAX_TOOL_CALLS;
      else process.env.DFIR_AI_WATSON_MAX_TOOL_CALLS = old;
    }
  });

  it("canContinue: AI off, a closed or archived case, or null — as rawSearch.writable decides", async () => {
    expect(await watsonRoundDeps(ctxOf())?.canContinue?.("c1")).toBeNull();
    expect(await watsonRoundDeps(ctxOf({ enabled: false }))?.canContinue?.("c1")).toBe("off");
    expect(await watsonRoundDeps(ctxOf({ status: "closed" }))?.canContinue?.("c1")).toBe("frozen");
    expect(await watsonRoundDeps(ctxOf({ status: "archived" }))?.canContinue?.("c1")).toBe("frozen");
  });
});

describe("through the pipeline, a configured cap runs the round in tool mode", () => {
  it("deps.maxToolCalls = 4 → the round's first send goes through converse with tools", async () => {
    const { mkdtemp } = await import("node:fs/promises");
    const { tmpdir } = await import("node:os");
    const { join } = await import("node:path");
    const { AnalysisPipeline } = await import("../../src/analysis/pipeline.js");
    const { StateStore } = await import("../../src/analysis/stateStore.js");
    const { StateLock } = await import("../../src/analysis/stateLock.js");
    const { AiCostStore } = await import("../../src/analysis/aiCost.js");
    const { CaseStore } = await import("../../src/storage/caseStore.js");
    const { WatsonChatStore } = await import("../../src/analysis/ai/watson/chatStore.js");
    const { Scripted, final } = await import("../analysis/watson/roundToolsFixtures.js");
    const root = await mkdtemp(join(tmpdir(), "dfir-watson-pipeline-tools-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: "p1", name: "n", investigator: "i", aiProvider: null });
    const provider = new Scripted([final()]);
    const pipeline = new AnalysisPipeline({
      provider,
      stateStore: new StateStore(cases),
      stateLock: new StateLock(),
      aiCostStore: new AiCostStore(cases),
      imageLoader: async () => ({ base64: "A", mimeType: "image/webp" }),
    });
    const deps = {
      chatStore: new WatsonChatStore(cases),
      cases,
      provider,
      isAiEnabled: async () => true,
      maxToolCalls: 4,
      canContinue: async () => null,
    };
    const chat = await pipeline.watsonRound("p1", { text: "hello" }, deps);
    expect(provider.sent).toHaveLength(1);
    expect(provider.sent[0].tools.length).toBeGreaterThan(0);
    expect(chat.turns.at(-1)?.role).toBe("watson");
  });
});
