import { describe, expect, it } from "vitest";
import { AnthropicProvider } from "../../src/providers/anthropic.js";
import { OpenAIProvider } from "../../src/providers/openai.js";
import { GeminiProvider } from "../../src/providers/gemini.js";
import { ProviderError } from "../../src/providers/provider.js";
import type { ConverseRequest } from "../../src/providers/toolCalling.js";

// Task 4 review I3: an error thrown after a billed response carries that response's usage, so the
// caller can count the spend against the round's limits.

const fetchOf = (json: unknown) =>
  (async () =>
    new Response(JSON.stringify(json), {
      status: 200,
      headers: { "content-type": "application/json" },
    })) as never;
const req: ConverseRequest = {
  systemPrompt: "s",
  userPrompt: "u",
  transcript: [],
  tools: [],
  toolChoice: "auto",
};
const usageOf = (p: Promise<unknown>) =>
  p.then(
    () => undefined,
    (e: unknown) => (e instanceof ProviderError ? e.usage : "not a ProviderError"),
  );

describe("billed failures carry usage (I3)", () => {
  it("Anthropic max_tokens and refusal", async () => {
    for (const stop_reason of ["max_tokens", "refusal"]) {
      const p = new AnthropicProvider({
        apiKey: "k",
        model: "m",
        fetchFn: fetchOf({ content: [], stop_reason, usage: { input_tokens: 10, output_tokens: 16000 } }),
      });
      expect(await usageOf(p.converse(req))).toMatchObject({ inputTokens: 10, outputTokens: 16000 });
    }
  });

  it("Anthropic: a billed reply with no content", async () => {
    const p = new AnthropicProvider({
      apiKey: "k",
      model: "m",
      fetchFn: fetchOf({
        content: [],
        stop_reason: "end_turn",
        usage: { input_tokens: 10, output_tokens: 3 },
      }),
    });
    expect(await usageOf(p.converse(req))).toMatchObject({ inputTokens: 10, outputTokens: 3 });
  });

  it("OpenAI-compatible finish_reason length", async () => {
    const p = new OpenAIProvider({
      apiKey: "k",
      model: "m",
      fetchFn: fetchOf({
        choices: [{ finish_reason: "length", message: { content: "" } }],
        usage: { prompt_tokens: 10, completion_tokens: 500 },
      }),
    });
    expect(await usageOf(p.converse(req))).toMatchObject({ inputTokens: 10, outputTokens: 500 });
  });

  it("Gemini MAX_TOKENS", async () => {
    const p = new GeminiProvider({
      apiKey: "k",
      model: "gemini-x",
      fetchFn: fetchOf({
        candidates: [{ finishReason: "MAX_TOKENS", content: { parts: [] } }],
        usageMetadata: { promptTokenCount: 10, candidatesTokenCount: 700 },
      }),
    });
    expect(await usageOf(p.converse(req))).toMatchObject({ inputTokens: 10, outputTokens: 700 });
  });
});
