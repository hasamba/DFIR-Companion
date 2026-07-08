import { describe, it, expect, vi } from "vitest";
import { OpenAIProvider } from "../../src/providers/openai.js";
import { ProviderError } from "../../src/providers/provider.js";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

describe("OpenAIProvider", () => {
  it("sends images and returns assistant content", async () => {
    const fetchFn = vi.fn(async () =>
      jsonResponse({ choices: [{ message: { content: '{"summary":"done"}' } }] }),
    );
    const p = new OpenAIProvider({ apiKey: "k", model: "gpt-4o", fetchFn });
    const result = await p.analyze({
      systemPrompt: "s", userPrompt: "u",
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
    const fetchFn = vi.fn(async () => jsonResponse({ choices: [{ message: { content: "{}" } }] }));
    const withCap = new OpenAIProvider({ apiKey: "k", model: "gpt-4o", fetchFn, maxTokens: 8192 });
    await withCap.analyze({ systemPrompt: "s", userPrompt: "u", images: [] });
    expect(JSON.parse((fetchFn.mock.calls[0][1] as RequestInit).body as string).max_tokens).toBe(8192);

    const noCap = new OpenAIProvider({ apiKey: "k", model: "gpt-4o", fetchFn });
    await noCap.analyze({ systemPrompt: "s", userPrompt: "u", images: [] });
    expect(JSON.parse((fetchFn.mock.calls[1][1] as RequestInit).body as string).max_tokens).toBeUndefined();
  });

  it("honours an explicit imageDetail override", async () => {
    const fetchFn = vi.fn(async () =>
      jsonResponse({ choices: [{ message: { content: "{}" } }] }),
    );
    const p = new OpenAIProvider({ apiKey: "k", model: "gpt-4o", fetchFn, imageDetail: "low" });
    await p.analyze({ systemPrompt: "s", userPrompt: "u", images: [{ base64: "AAAA", mimeType: "image/png" }] });
    const body = JSON.parse((fetchFn.mock.calls[0][1] as RequestInit).body as string);
    expect(body.messages[1].content[1].image_url.detail).toBe("low");
  });

  it("context guard: throws a clear 'context' error when the prompt alone exceeds the window (no API call)", async () => {
    const fetchFn = vi.fn(async () => jsonResponse({ choices: [{ message: { content: "{}" } }] }));
    const p = new OpenAIProvider({ apiKey: "k", model: "m", fetchFn, contextTokens: 1000, maxTokens: 200 });
    // ~5000-token user prompt (20000 chars / 4) >> 1000-token context.
    await expect(p.analyze({ systemPrompt: "s", userPrompt: "x".repeat(20_000), images: [] }))
      .rejects.toMatchObject({ kind: "context" } as Partial<ProviderError>);
    expect(fetchFn).not.toHaveBeenCalled();   // failed fast — never hit the upstream API
    await p.analyze({ systemPrompt: "s", userPrompt: "x".repeat(20_000), images: [] }).catch((e: ProviderError) => {
      expect(e.message).toContain("over the model's");
      expect(e.message).toContain("DFIR_AI_SYNTH_MAX_EVENTS");
    });
  });

  it("context guard: shrinks max_tokens so a large-but-fitting prompt still sends", async () => {
    const fetchFn = vi.fn(async () => jsonResponse({ choices: [{ message: { content: "{}" } }] }));
    // ctx 10000, margin 1000. Prompt ~2000 tokens (8000 chars). room = 10000-2000-1000 = 7000.
    const p = new OpenAIProvider({ apiKey: "k", model: "m", fetchFn, contextTokens: 10_000, maxTokens: 16_000 });
    await p.analyze({ systemPrompt: "", userPrompt: "x".repeat(8_000), images: [] });
    const body = JSON.parse((fetchFn.mock.calls[0][1] as RequestInit).body as string);
    expect(body.max_tokens).toBe(7_000);       // reduced from 16000 to fit the window
  });

  it("context guard: leaves max_tokens untouched when the request comfortably fits", async () => {
    const fetchFn = vi.fn(async () => jsonResponse({ choices: [{ message: { content: "{}" } }] }));
    const p = new OpenAIProvider({ apiKey: "k", model: "m", fetchFn, contextTokens: 128_000, maxTokens: 16_000 });
    await p.analyze({ systemPrompt: "s", userPrompt: "u", images: [] });
    expect(JSON.parse((fetchFn.mock.calls[0][1] as RequestInit).body as string).max_tokens).toBe(16_000);
  });

  it("maps an upstream 400 about context length to an actionable message", async () => {
    const fetchFn = vi.fn(async () => jsonResponse({ error: { message: "This endpoint's maximum context length is 128000 tokens. However, you requested 251167" } }, 400));
    const p = new OpenAIProvider({ apiKey: "k", model: "m", fetchFn });   // guard off (no contextTokens)
    await p.analyze({ systemPrompt: "s", userPrompt: "u", images: [] }).catch((e: ProviderError) => {
      expect(e.message).toContain("context too large");
      expect(e.message).toContain("DFIR_AI_CONTEXT_TOKENS");
    });
  });

  it("maps 429 to a rate_limit ProviderError", async () => {
    const fetchFn = vi.fn(async () => jsonResponse({ error: "slow down" }, 429));
    const p = new OpenAIProvider({ apiKey: "k", model: "gpt-4o", fetchFn });
    await expect(p.analyze({ systemPrompt: "s", userPrompt: "u", images: [] }))
      .rejects.toMatchObject({ kind: "rate_limit" } as Partial<ProviderError>);
  });

  it("maps 402 to a 'billing' ProviderError with an actionable message", async () => {
    const fetchFn = vi.fn(async () => jsonResponse({ error: { message: "Insufficient credit balance" } }, 402));
    const p = new OpenAIProvider({ apiKey: "k", model: "gpt-4o", fetchFn });
    await expect(p.analyze({ systemPrompt: "s", userPrompt: "u", images: [] }))
      .rejects.toMatchObject({ kind: "billing" } as Partial<ProviderError>);
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
    const fetchFn = vi.fn(async () => jsonResponse({
      choices: [{ message: { content: "{}" } }],
      usage: { prompt_tokens: 120, completion_tokens: 45 },
    }));
    const p = new OpenAIProvider({ apiKey: "k", model: "gpt-4o", fetchFn });
    const result = await p.analyze({ systemPrompt: "s", userPrompt: "u", images: [] });
    expect(result.usage).toEqual({ inputTokens: 120, outputTokens: 45 });
  });

  it("does not populate costUSD for the plain openai provider name, even if the response has it", async () => {
    const fetchFn = vi.fn(async () => jsonResponse({
      choices: [{ message: { content: "{}" } }],
      usage: { prompt_tokens: 10, completion_tokens: 5, cost: 0.001 },
    }));
    const p = new OpenAIProvider({ apiKey: "k", model: "gpt-4o", fetchFn });
    const result = await p.analyze({ systemPrompt: "s", userPrompt: "u", images: [] });
    expect(result.usage?.costUSD).toBeUndefined();
  });

  it("omits usage entirely when the response has none", async () => {
    const fetchFn = vi.fn(async () => jsonResponse({ choices: [{ message: { content: "{}" } }] }));
    const p = new OpenAIProvider({ apiKey: "k", model: "gpt-4o", fetchFn });
    const result = await p.analyze({ systemPrompt: "s", userPrompt: "u", images: [] });
    expect(result.usage).toBeUndefined();
  });
});
