import { describe, expect, it } from "vitest";
import { ProviderError, type AIProvider } from "../../src/providers/provider.js";
import { MeteredProvider } from "./meter.js";

const REQUEST = { systemPrompt: "system", userPrompt: "user", images: [] };

describe("evaluation resource meter (#378)", () => {
  it("records time, token use, and monetary cost without retaining prompts or output", async () => {
    const provider: AIProvider = {
      name: "meter-test",
      model: "model-1",
      analyze: async () => ({
        rawText: "{}",
        usage: { inputTokens: 12, outputTokens: 4, costUSD: 0.03 },
      }),
    };
    const metered = new MeteredProvider(provider);
    await metered.analyze(REQUEST);
    expect(metered.snapshot()).toMatchObject({
      calls: 1,
      failedCalls: 0,
      inputTokens: 12,
      outputTokens: 4,
      costUsd: 0.03,
    });
    expect(JSON.stringify(metered.snapshot())).not.toContain("system");
    expect(JSON.stringify(metered.snapshot())).not.toContain("rawText");
  });

  it("counts a provider failure separately and rethrows it", async () => {
    const provider: AIProvider = {
      name: "meter-test",
      model: "model-1",
      analyze: async () => {
        throw new ProviderError("upstream timed out", "timeout");
      },
    };
    const metered = new MeteredProvider(provider);
    await expect(metered.analyze(REQUEST)).rejects.toThrow("upstream timed out");
    expect(metered.snapshot()).toMatchObject({ calls: 1, failedCalls: 1 });
  });
});
