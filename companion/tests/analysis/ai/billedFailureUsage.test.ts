import { describe, expect, it } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../../src/storage/caseStore.js";
import { AiCostStore } from "../../../src/analysis/aiCost.js";
import { analyzeRestored, type ProviderCallContext } from "../../../src/analysis/ai/providerCall.js";
import { inUsageScope, newUsageTally } from "../../../src/analysis/ai/usageScope.js";
import { emptyState } from "../../../src/analysis/stateTypes.js";
import { createConsoleLogger } from "../../../src/logging/logger.js";
import { ProviderError, type AIProvider, type AnalyzeResult } from "../../../src/providers/provider.js";

// #2663: a one-step call that was billed and then refused or cut off still counts — in the case's cost
// file and in the round's own tally — as the tool-mode path already did.

class BilledFailure implements AIProvider {
  readonly name = "stub";
  readonly model = "stub-model";
  async analyze(): Promise<AnalyzeResult> {
    const err = new ProviderError("cut off at the output limit", "other");
    err.usage = { inputTokens: 300, outputTokens: 50, cacheReadTokens: 700 };
    throw err;
  }
}

describe("a billed failure on the one-step path (#2663)", () => {
  it("is booked in the cost file and the round tally, and still throws", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-billed-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const aiCostStore = new AiCostStore(cases);
    const ctx: ProviderCallContext = { log: createConsoleLogger("error"), opts: { aiCostStore } };
    const tally = newUsageTally();
    await expect(
      inUsageScope(tally, () =>
        analyzeRestored(
          ctx,
          "c1",
          emptyState("c1"),
          new BilledFailure(),
          { systemPrompt: "s", userPrompt: "u", images: [] },
          "watson",
        ),
      ),
    ).rejects.toThrow("cut off");
    const b = (await aiCostStore.load("c1")).watson;
    expect(b.totalCalls).toBe(1);
    expect(b.totalInputTokens).toBe(300);
    expect(b.cacheReadTokens).toBe(700);
    expect(tally).toEqual({ promptTokens: 1000, cacheReadTokens: 700, reported: true });
  });
});

describe("real one-step providers attach a billed failure's usage (#2663)", () => {
  it("OpenAI: an empty, cut-off reply throws with its usage", async () => {
    const { OpenAIProvider } = await import("../../../src/providers/openai.js");
    const { fetchMock, jsonResponse } = await import("../../helpers/fetchMock.js");
    const fetchFn = fetchMock(async () =>
      jsonResponse({
        choices: [{ message: { content: "" }, finish_reason: "length" }],
        usage: { prompt_tokens: 500, completion_tokens: 64, prompt_tokens_details: { cached_tokens: 400 } },
      }),
    );
    const err = await new OpenAIProvider({ apiKey: "k", model: "gpt-4o", fetchFn })
      .analyze({ systemPrompt: "s", userPrompt: "u", images: [] })
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ProviderError);
    expect((err as ProviderError).usage).toMatchObject({ inputTokens: 500, cacheReadTokens: 400 });
  });

  it("Gemini: a blocked reply throws with its usage", async () => {
    const { GeminiProvider } = await import("../../../src/providers/gemini.js");
    const { fetchMock, jsonResponse } = await import("../../helpers/fetchMock.js");
    const fetchFn = fetchMock(async () =>
      jsonResponse({
        candidates: [{ finishReason: "SAFETY", content: { parts: [] } }],
        usageMetadata: { promptTokenCount: 800, candidatesTokenCount: 0, cachedContentTokenCount: 600 },
      }),
    );
    const err = await new GeminiProvider({ apiKey: "k", model: "gemini-2.5-pro", fetchFn })
      .analyze({ systemPrompt: "s", userPrompt: "u", images: [] })
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ProviderError);
    expect((err as ProviderError).usage).toMatchObject({ inputTokens: 800, cacheReadTokens: 600 });
  });
});
