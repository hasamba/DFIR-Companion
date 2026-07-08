import { describe, it, expect, vi } from "vitest";
import { OpenRouterProvider } from "../../src/providers/openrouter.js";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

const OK = { choices: [{ message: { content: '{"summary":"done"}' } }] };

describe("OpenRouterProvider — reasoning / Chain-of-Thought (#121)", () => {
  it("defaults to the OpenRouter base URL and name", async () => {
    const fetchFn = vi.fn(async () => jsonResponse(OK));
    const p = new OpenRouterProvider({ apiKey: "k", model: "anthropic/claude-sonnet-4.6", fetchFn });
    await p.analyze({ systemPrompt: "s", userPrompt: "u", images: [] });
    expect(p.name).toBe("openrouter");
    expect(fetchFn.mock.calls[0][0]).toBe("https://openrouter.ai/api/v1/chat/completions");
  });

  it("adds the unified `reasoning` field with the thinking budget when a CoT budget is set", async () => {
    const fetchFn = vi.fn(async () => jsonResponse(OK));
    const p = new OpenRouterProvider({ apiKey: "k", model: "anthropic/claude-sonnet-4.6", fetchFn });
    await p.analyze({ systemPrompt: "s", userPrompt: "u", images: [], thinkingTokens: 8000 });
    const body = JSON.parse((fetchFn.mock.calls[0][1] as RequestInit).body as string);
    expect(body.reasoning).toEqual({ max_tokens: 8000 });
  });

  it("omits `reasoning` without a budget or below the 1024-token minimum", async () => {
    const fetchFn = vi.fn(async () => jsonResponse(OK));
    const p = new OpenRouterProvider({ apiKey: "k", model: "m", fetchFn });
    await p.analyze({ systemPrompt: "s", userPrompt: "u", images: [] });
    await p.analyze({ systemPrompt: "s", userPrompt: "u", images: [], thinkingTokens: 500 });
    for (const call of fetchFn.mock.calls) {
      expect(JSON.parse((call[1] as RequestInit).body as string).reasoning).toBeUndefined();
    }
  });

  it("requests usage.include and populates costUSD from the response", async () => {
    const fetchFn = vi.fn(async () => jsonResponse({
      choices: [{ message: { content: "{}" } }],
      usage: { prompt_tokens: 200, completion_tokens: 80, cost: 0.0123 },
    }));
    const p = new OpenRouterProvider({ apiKey: "k", model: "anthropic/claude-sonnet-4.6", fetchFn });
    const result = await p.analyze({ systemPrompt: "s", userPrompt: "u", images: [] });
    const body = JSON.parse((fetchFn.mock.calls[0][1] as RequestInit).body as string);
    expect(body.usage).toEqual({ include: true });
    expect(result.usage).toEqual({ inputTokens: 200, outputTokens: 80, costUSD: 0.0123 });
  });

  it("has no costUSD when OpenRouter's response omits cost", async () => {
    const fetchFn = vi.fn(async () => jsonResponse({
      choices: [{ message: { content: "{}" } }],
      usage: { prompt_tokens: 200, completion_tokens: 80 },
    }));
    const p = new OpenRouterProvider({ apiKey: "k", model: "m", fetchFn });
    const result = await p.analyze({ systemPrompt: "s", userPrompt: "u", images: [] });
    expect(result.usage).toEqual({ inputTokens: 200, outputTokens: 80 });
  });
});
