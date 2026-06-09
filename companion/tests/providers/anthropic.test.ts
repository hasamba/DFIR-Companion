import { describe, it, expect, vi } from "vitest";
import { AnthropicProvider } from "../../src/providers/anthropic.js";
import { ProviderError } from "../../src/providers/provider.js";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

const OK = { content: [{ type: "text", text: '{"summary":"done"}' }] };

describe("AnthropicProvider", () => {
  it("sends images and returns assistant text", async () => {
    const fetchFn = vi.fn(async () => jsonResponse(OK));
    const p = new AnthropicProvider({ apiKey: "k", model: "claude-haiku-4-5-20251001", fetchFn });
    const result = await p.analyze({
      systemPrompt: "s", userPrompt: "u",
      images: [{ base64: "AAAA", mimeType: "image/webp" }],
    });
    expect(result.rawText).toBe('{"summary":"done"}');
    const body = JSON.parse((fetchFn.mock.calls[0][1] as RequestInit).body as string);
    expect(body.model).toBe("claude-haiku-4-5-20251001");
    expect(body.messages[0].content[1]).toMatchObject({
      type: "image", source: { type: "base64", media_type: "image/webp", data: "AAAA" },
    });
  });

  it("caches ONLY the static system prompt — the breakpoint never sits on case content (OPSEC)", async () => {
    const fetchFn = vi.fn(async () => jsonResponse(OK));
    const p = new AnthropicProvider({ apiKey: "k", model: "claude-sonnet-4-6", fetchFn });
    await p.analyze({
      systemPrompt: "SYSTEM", userPrompt: "CASE EVIDENCE",
      images: [{ base64: "AAAA", mimeType: "image/png" }],
    });
    const body = JSON.parse((fetchFn.mock.calls[0][1] as RequestInit).body as string);

    // system is a content-block array with an ephemeral cache breakpoint on the static prompt
    expect(body.system).toEqual([
      { type: "text", text: "SYSTEM", cache_control: { type: "ephemeral" } },
    ]);

    // the user message (case evidence + screenshots) carries NO cache_control anywhere —
    // forensic content must never be the cached region.
    expect(JSON.stringify(body.messages)).not.toContain("cache_control");
  });

  it("parses cache usage back from the response so caching can be confirmed", async () => {
    const fetchFn = vi.fn(async () => jsonResponse({
      ...OK,
      usage: {
        input_tokens: 12,
        output_tokens: 34,
        cache_creation_input_tokens: 2048,
        cache_read_input_tokens: 0,
      },
    }));
    const p = new AnthropicProvider({ apiKey: "k", model: "claude-sonnet-4-6", fetchFn });
    const result = await p.analyze({ systemPrompt: "s", userPrompt: "u", images: [] });
    expect(result.usage).toEqual({
      inputTokens: 12, outputTokens: 34, cacheCreationTokens: 2048, cacheReadTokens: 0,
    });
  });

  it("omits usage when the provider does not report it", async () => {
    const fetchFn = vi.fn(async () => jsonResponse(OK));
    const p = new AnthropicProvider({ apiKey: "k", model: "claude-sonnet-4-6", fetchFn });
    const result = await p.analyze({ systemPrompt: "s", userPrompt: "u", images: [] });
    expect(result.usage).toBeUndefined();
  });

  it("sends max_tokens (bounds cost) and the anthropic-version header", async () => {
    const fetchFn = vi.fn(async () => jsonResponse(OK));
    const p = new AnthropicProvider({ apiKey: "k", model: "m", fetchFn, maxTokens: 8192 });
    await p.analyze({ systemPrompt: "s", userPrompt: "u", images: [] });
    const init = fetchFn.mock.calls[0][1] as RequestInit;
    expect(JSON.parse(init.body as string).max_tokens).toBe(8192);
    expect((init.headers as Record<string, string>)["anthropic-version"]).toBe("2023-06-01");
  });

  it("maps 529 (overloaded) to a rate_limit ProviderError", async () => {
    const fetchFn = vi.fn(async () => jsonResponse({ error: "overloaded" }, 529));
    const p = new AnthropicProvider({ apiKey: "k", model: "m", fetchFn });
    await expect(p.analyze({ systemPrompt: "s", userPrompt: "u", images: [] }))
      .rejects.toMatchObject({ kind: "rate_limit" } as Partial<ProviderError>);
  });
});
