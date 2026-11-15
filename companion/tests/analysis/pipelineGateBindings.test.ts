import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { CaseStore } from "../../src/storage/caseStore.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import type { AiCallContext } from "../../src/analysis/ai/aiContext.js";
import type { AIProvider, AnalyzeRequest, AnalyzeResult } from "../../src/providers/provider.js";
import type { ConverseRequest, ConverseResult } from "../../src/providers/toolCalling.js";

// Codex P1-1: the gate bindings sit inside the object literal that assigns aiCtx, so a binding that
// read the context when it was BUILT would capture undefined. Both gates must work through the
// real pipeline after construction.

class Both implements AIProvider {
  readonly name = "both";
  readonly model = "m";
  readonly supportsTools = true;
  async analyze(_req: AnalyzeRequest): Promise<AnalyzeResult> {
    return { rawText: '{"via":"analyze"}' };
  }
  async converse(_req: ConverseRequest): Promise<ConverseResult> {
    return { text: '{"via":"converse"}', calls: [] };
  }
}

describe("pipeline gate bindings (Codex P1-1)", () => {
  it("both bound gates work after real pipeline construction (no undefined context)", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-gate-bind-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: "g1", name: "n", investigator: "i", aiProvider: null });
    const provider = new Both();
    const pipeline = new AnalysisPipeline({
      provider,
      stateStore: new StateStore(cases),
      imageLoader: async () => ({ base64: "A", mimeType: "image/webp" }),
    });
    const ctx = (pipeline as unknown as { aiCtx: AiCallContext }).aiCtx;
    const st = emptyState("g1");
    await expect(
      ctx.analyzeRestored("g1", st, provider, { systemPrompt: "s", userPrompt: "u", images: [] }),
    ).resolves.toEqual({ via: "analyze" });
    const { result: out } = await ctx.converseRestored!(
      "g1",
      st,
      provider,
      { systemPrompt: "s", userPrompt: "u", transcript: [], tools: [], toolChoice: "auto" },
      { pairs: [] },
      "watson",
    );
    expect(out.answer).toEqual({ via: "converse" });
  });
});
