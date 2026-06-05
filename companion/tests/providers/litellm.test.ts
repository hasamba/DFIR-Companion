import { describe, it, expect, vi } from "vitest";
import { LiteLlmProvider } from "../../src/providers/litellm.js";
import { buildProviderFrom } from "../../src/server.js";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

describe("LiteLlmProvider", () => {
  it("targets the local LiteLLM proxy by default and is OpenAI-compatible", async () => {
    const fetchFn = vi.fn(async () => jsonResponse({ choices: [{ message: { content: '{"summary":"ok"}' } }] }));
    const p = new LiteLlmProvider({ apiKey: "", model: "ollama/llama3.1", fetchFn });
    expect(p.name).toBe("litellm");
    const result = await p.analyze({ systemPrompt: "s", userPrompt: "u", images: [] });
    expect(result.rawText).toBe('{"summary":"ok"}');
    // Hits the standard local proxy port on the OpenAI chat-completions path.
    expect(fetchFn.mock.calls[0][0]).toBe("http://localhost:4000/v1/chat/completions");
    const init = fetchFn.mock.calls[0][1] as RequestInit;
    expect(JSON.parse(init.body as string).model).toBe("ollama/llama3.1");
    // An empty key still sends a (harmless) Bearer header for an auth-less local proxy.
    expect((init.headers as Record<string, string>).authorization).toBe("Bearer ");
  });

  it("honours a custom base URL (remote / non-default port)", async () => {
    const fetchFn = vi.fn(async () => jsonResponse({ choices: [{ message: { content: "{}" } }] }));
    const p = new LiteLlmProvider({ apiKey: "sk-virtual", model: "gpt-4o", baseUrl: "http://10.0.0.5:8000/v1", fetchFn });
    await p.analyze({ systemPrompt: "s", userPrompt: "u", images: [] });
    expect(fetchFn.mock.calls[0][0]).toBe("http://10.0.0.5:8000/v1/chat/completions");
    expect((fetchFn.mock.calls[0][1] as RequestInit).headers as Record<string, string>)
      .toMatchObject({ authorization: "Bearer sk-virtual" });
  });

  it("labels its errors 'LiteLLM', not 'OpenAI'", async () => {
    const fetchFn = vi.fn(async () => jsonResponse({ error: "model not found" }, 400));
    const p = new LiteLlmProvider({ apiKey: "", model: "nope", fetchFn });
    await p.analyze({ systemPrompt: "s", userPrompt: "u", images: [] }).catch((e: Error) => {
      expect(e.message).toContain("LiteLLM");
      expect(e.message).not.toContain("OpenAI");
    });
  });
});

describe("buildProviderFrom — litellm wiring", () => {
  it("resolves the litellm provider by name", () => {
    const p = buildProviderFrom({ provider: "litellm", model: "ollama/llama3.1" });
    expect(p?.name).toBe("litellm");
  });

  it("returns undefined when no provider is set", () => {
    expect(buildProviderFrom({ provider: undefined })).toBeUndefined();
  });
});
