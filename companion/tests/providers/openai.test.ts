import { describe, it, expect, vi } from "vitest";
import { fetchMock, jsonResponse } from "../helpers/fetchMock.js";
import { OpenAIProvider } from "../../src/providers/openai.js";
import { LiteLlmProvider } from "../../src/providers/litellm.js";
import { ProviderError, type AIProvider } from "../../src/providers/provider.js";

describe("OpenAIProvider — base URL validation (#246)", () => {
  // validateBaseUrl() has its own unit tests (urlValidation.test.ts); these confirm it's actually
  // WIRED into the real constructor, not just written and left uncalled.
  it("throws constructing with an http:// base URL to a non-loopback host", () => {
    expect(
      () => new OpenAIProvider({ apiKey: "k", model: "gpt-4o", baseUrl: "http://attacker.example.com/v1" }),
    ).toThrow(ProviderError);
  });

  it("allows http:// to a loopback host (local LiteLLM/Ollama)", () => {
    expect(
      () => new OpenAIProvider({ apiKey: "k", model: "gpt-4o", baseUrl: "http://127.0.0.1:4000/v1" }),
    ).not.toThrow();
  });

  it("allows https:// to any host, including the provider default", () => {
    expect(() => new OpenAIProvider({ apiKey: "k", model: "gpt-4o" })).not.toThrow();
  });
});

describe("OpenAIProvider", () => {
  it("sends images and returns assistant content", async () => {
    const fetchFn = fetchMock(async () =>
      jsonResponse({ choices: [{ message: { content: '{"summary":"done"}' } }] }),
    );
    const p = new OpenAIProvider({ apiKey: "k", model: "gpt-4o", fetchFn });
    const result = await p.analyze({
      systemPrompt: "s",
      userPrompt: "u",
      images: [{ base64: "AAAA", mimeType: "image/webp" }],
    });
    expect(result.rawText).toBe('{"summary":"done"}');
    expect(fetchFn).toHaveBeenCalledOnce();
    const body = JSON.parse((fetchFn.mock.calls[0][1] as RequestInit).body as string);
    expect(body.model).toBe("gpt-4o");
    expect(JSON.stringify(body)).toContain("data:image/webp;base64,AAAA");
    // small forensic text needs full-resolution tiling, not a downscaled image
    expect(body.messages[1].content[1].image_url.detail).toBe("high");
  });

  it("sends max_tokens when set (bounds cost / avoids OpenRouter 402), omits it otherwise", async () => {
    const fetchFn = fetchMock(async () => jsonResponse({ choices: [{ message: { content: "{}" } }] }));
    const withCap = new OpenAIProvider({ apiKey: "k", model: "gpt-4o", fetchFn, maxTokens: 8192 });
    await withCap.analyze({ systemPrompt: "s", userPrompt: "u", images: [] });
    expect(JSON.parse((fetchFn.mock.calls[0][1] as RequestInit).body as string).max_tokens).toBe(8192);

    const noCap = new OpenAIProvider({ apiKey: "k", model: "gpt-4o", fetchFn });
    await noCap.analyze({ systemPrompt: "s", userPrompt: "u", images: [] });
    expect(JSON.parse((fetchFn.mock.calls[1][1] as RequestInit).body as string).max_tokens).toBeUndefined();
  });

  it("honours an explicit imageDetail override", async () => {
    const fetchFn = fetchMock(async () => jsonResponse({ choices: [{ message: { content: "{}" } }] }));
    const p = new OpenAIProvider({ apiKey: "k", model: "gpt-4o", fetchFn, imageDetail: "low" });
    await p.analyze({
      systemPrompt: "s",
      userPrompt: "u",
      images: [{ base64: "AAAA", mimeType: "image/png" }],
    });
    const body = JSON.parse((fetchFn.mock.calls[0][1] as RequestInit).body as string);
    expect(body.messages[1].content[1].image_url.detail).toBe("low");
  });

  it("context guard: throws a clear 'context' error when the prompt alone exceeds the window (no API call)", async () => {
    const fetchFn = fetchMock(async () => jsonResponse({ choices: [{ message: { content: "{}" } }] }));
    const p = new OpenAIProvider({ apiKey: "k", model: "m", fetchFn, contextTokens: 1000, maxTokens: 200 });
    // ~5000-token user prompt (20000 chars / 4) >> 1000-token context.
    await expect(
      p.analyze({ systemPrompt: "s", userPrompt: "x".repeat(20_000), images: [] }),
    ).rejects.toMatchObject({ kind: "context" } as Partial<ProviderError>);
    expect(fetchFn).not.toHaveBeenCalled(); // failed fast — never hit the upstream API
    await p
      .analyze({ systemPrompt: "s", userPrompt: "x".repeat(20_000), images: [] })
      .catch((e: ProviderError) => {
        expect(e.message).toContain("over the model's");
        expect(e.message).toContain("DFIR_AI_SYNTH_MAX_EVENTS");
      });
  });

  it("context guard: shrinks max_tokens so a large-but-fitting prompt still sends", async () => {
    const fetchFn = fetchMock(async () => jsonResponse({ choices: [{ message: { content: "{}" } }] }));
    // ctx 10000, margin 1000. Prompt ~2000 tokens (8000 chars). room = 10000-2000-1000 = 7000.
    const p = new OpenAIProvider({
      apiKey: "k",
      model: "m",
      fetchFn,
      contextTokens: 10_000,
      maxTokens: 16_000,
    });
    await p.analyze({ systemPrompt: "", userPrompt: "x".repeat(8_000), images: [] });
    const body = JSON.parse((fetchFn.mock.calls[0][1] as RequestInit).body as string);
    expect(body.max_tokens).toBe(7_000); // reduced from 16000 to fit the window
  });

  it("context guard: leaves max_tokens untouched when the request comfortably fits", async () => {
    const fetchFn = fetchMock(async () => jsonResponse({ choices: [{ message: { content: "{}" } }] }));
    const p = new OpenAIProvider({
      apiKey: "k",
      model: "m",
      fetchFn,
      contextTokens: 128_000,
      maxTokens: 16_000,
    });
    await p.analyze({ systemPrompt: "s", userPrompt: "u", images: [] });
    expect(JSON.parse((fetchFn.mock.calls[0][1] as RequestInit).body as string).max_tokens).toBe(16_000);
  });

  it("maps an upstream 400 about context length to an actionable message", async () => {
    const fetchFn = fetchMock(async () =>
      jsonResponse(
        {
          error: {
            message: "This endpoint's maximum context length is 128000 tokens. However, you requested 251167",
          },
        },
        400,
      ),
    );
    const p = new OpenAIProvider({ apiKey: "k", model: "m", fetchFn }); // guard off (no contextTokens)
    await p.analyze({ systemPrompt: "s", userPrompt: "u", images: [] }).catch((e: ProviderError) => {
      expect(e.message).toContain("context too large");
      expect(e.message).toContain("DFIR_AI_CONTEXT_TOKENS");
    });
  });

  it("maps 429 to a rate_limit ProviderError", async () => {
    const fetchFn = fetchMock(async () => jsonResponse({ error: "slow down" }, 429));
    const p = new OpenAIProvider({ apiKey: "k", model: "gpt-4o", fetchFn });
    await expect(p.analyze({ systemPrompt: "s", userPrompt: "u", images: [] })).rejects.toMatchObject({
      kind: "rate_limit",
    } as Partial<ProviderError>);
  });

  it("maps 402 to a 'billing' ProviderError with an actionable message", async () => {
    const fetchFn = fetchMock(async () =>
      jsonResponse({ error: { message: "Insufficient credit balance" } }, 402),
    );
    const p = new OpenAIProvider({ apiKey: "k", model: "gpt-4o", fetchFn });
    await expect(p.analyze({ systemPrompt: "s", userPrompt: "u", images: [] })).rejects.toMatchObject({
      kind: "billing",
    } as Partial<ProviderError>);
    await p.analyze({ systemPrompt: "s", userPrompt: "u", images: [] }).catch((e: ProviderError) => {
      expect(e.message).toContain("payment required");
      expect(e.message).toContain("out of credits");
      expect(e.message).toContain("Insufficient credit balance"); // provider body echoed
    });
  });

  it("exposes the configured model", () => {
    const p = new OpenAIProvider({ apiKey: "k", model: "gpt-4o-mini", fetchFn: vi.fn() });
    expect(p.model).toBe("gpt-4o-mini");
  });

  it("populates token usage from the response for every OpenAI-compatible provider", async () => {
    const fetchFn = fetchMock(async () =>
      jsonResponse({
        choices: [{ message: { content: "{}" } }],
        usage: { prompt_tokens: 120, completion_tokens: 45 },
      }),
    );
    const p = new OpenAIProvider({ apiKey: "k", model: "gpt-4o", fetchFn });
    const result = await p.analyze({ systemPrompt: "s", userPrompt: "u", images: [] });
    expect(result.usage).toEqual({ inputTokens: 120, outputTokens: 45 });
  });

  it("does not populate costUSD for the plain openai provider name, even if the response has it", async () => {
    const fetchFn = fetchMock(async () =>
      jsonResponse({
        choices: [{ message: { content: "{}" } }],
        usage: { prompt_tokens: 10, completion_tokens: 5, cost: 0.001 },
      }),
    );
    const p = new OpenAIProvider({ apiKey: "k", model: "gpt-4o", fetchFn });
    const result = await p.analyze({ systemPrompt: "s", userPrompt: "u", images: [] });
    expect(result.usage?.costUSD).toBeUndefined();
  });

  it("omits usage entirely when the response has none", async () => {
    const fetchFn = fetchMock(async () => jsonResponse({ choices: [{ message: { content: "{}" } }] }));
    const p = new OpenAIProvider({ apiKey: "k", model: "gpt-4o", fetchFn });
    const result = await p.analyze({ systemPrompt: "s", userPrompt: "u", images: [] });
    expect(result.usage).toBeUndefined();
  });
});

describe("OpenAIProvider — supportsThinking (#1468)", () => {
  it("does NOT claim thinking support — reasoningBody() is a no-op on the base class", () => {
    // Read through the interface: the class does not declare the field, and that is the point.
    const p: AIProvider = new OpenAIProvider({ apiKey: "k", model: "gpt-4o" });
    expect(p.supportsThinking).toBeFalsy();
  });
});

describe('OpenAIProvider — output limit (finish_reason "length")', () => {
  const lengthResponse = (message: Record<string, unknown>, usage?: Record<string, unknown>) =>
    jsonResponse({ choices: [{ message, finish_reason: "length" }], ...(usage ? { usage } : {}) });
  const req = { systemPrompt: "s", userPrompt: "u", images: [] };

  it("throws output_limit when the limit is hit with no answer, naming the limit and the reasoning share", async () => {
    const fetchFn = fetchMock(async () => lengthResponse({ content: "", reasoning: "x".repeat(4000) }));
    const p = new OpenAIProvider({ apiKey: "k", model: "m", fetchFn, maxTokens: 16000 });
    const err = await p.analyze(req).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ProviderError);
    expect((err as ProviderError).kind).toBe("output_limit");
    expect((err as ProviderError).message).toContain("16,000");
    expect((err as ProviderError).message).toContain("About 1,000 of those tokens");
  });

  it("throws output_limit on a missing message, with no reasoning estimate", async () => {
    const fetchFn = fetchMock(async () => jsonResponse({ choices: [{ finish_reason: "length" }] }));
    const p = new OpenAIProvider({ apiKey: "k", model: "m", fetchFn, maxTokens: 16000 });
    const err = (await p.analyze(req).catch((e: unknown) => e)) as ProviderError;
    expect(err.kind).toBe("output_limit");
    expect(err.message).not.toContain("hidden reasoning");
  });

  it("names the max_tokens actually sent, after the context guard shrank it", async () => {
    const fetchFn = fetchMock(async () => lengthResponse({ content: "" }));
    const p = new OpenAIProvider({ apiKey: "k", model: "m", fetchFn, maxTokens: 16000, contextTokens: 8000 });
    const err = (await p.analyze(req).catch((e: unknown) => e)) as ProviderError;
    const sent = JSON.parse((fetchFn.mock.calls[0][1] as RequestInit).body as string).max_tokens as number;
    expect(sent).toBeLessThan(16000);
    expect(err.message).toContain(sent.toLocaleString("en-US"));
  });

  it("throws output_limit on a truncated answer when the caller sets rejectTruncated", async () => {
    const fetchFn = fetchMock(async () => lengthResponse({ content: '{"summary":"cut' }));
    const p = new OpenAIProvider({ apiKey: "k", model: "m", fetchFn, maxTokens: 16000 });
    await expect(p.analyze({ ...req, rejectTruncated: true })).rejects.toMatchObject({
      kind: "output_limit",
    } as Partial<ProviderError>);
  });

  it("returns a truncated answer unchanged when the caller does not set rejectTruncated", async () => {
    const fetchFn = fetchMock(async () => lengthResponse({ content: '{"summary":"cut' }));
    const p = new OpenAIProvider({ apiKey: "k", model: "m", fetchFn, maxTokens: 16000 });
    const result = await p.analyze(req);
    expect(result.rawText).toBe('{"summary":"cut');
  });

  it("prefers usage.completion_tokens_details.reasoning_tokens over the estimate", async () => {
    const fetchFn = fetchMock(async () =>
      lengthResponse(
        { content: "", reasoning: "x".repeat(4000) },
        {
          prompt_tokens: 10,
          completion_tokens: 16000,
          completion_tokens_details: { reasoning_tokens: 15500 },
        },
      ),
    );
    const p = new OpenAIProvider({ apiKey: "k", model: "m", fetchFn, maxTokens: 16000 });
    const err = (await p.analyze(req).catch((e: unknown) => e)) as ProviderError;
    expect(err.message).toContain("About 15,500 of those tokens");
    expect(err.message).not.toContain("About 1,000");
  });

  it("keeps the 'returned no content' error when the model stopped normally with no answer", async () => {
    const fetchFn = fetchMock(async () =>
      jsonResponse({ choices: [{ message: { content: "" }, finish_reason: "stop" }] }),
    );
    const p = new OpenAIProvider({ apiKey: "k", model: "m", fetchFn });
    await expect(p.analyze(req)).rejects.toMatchObject({ kind: "other" } as Partial<ProviderError>);
  });

  it("sends no reasoning_effort on OpenAI or LiteLLM, whatever the thinking budget", async () => {
    const fetchFn = fetchMock(async () => jsonResponse({ choices: [{ message: { content: "{}" } }] }));
    for (const p of [
      new OpenAIProvider({ apiKey: "k", model: "m", fetchFn }),
      new LiteLlmProvider({ apiKey: "k", model: "m", fetchFn }),
    ]) {
      await p.analyze({ ...req, thinkingTokens: 8000 });
    }
    for (const call of fetchFn.mock.calls) {
      expect(JSON.parse((call[1] as RequestInit).body as string).reasoning_effort).toBeUndefined();
    }
  });
});
