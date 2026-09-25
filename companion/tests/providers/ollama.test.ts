import { describe, it, expect } from "vitest";
import { fetchMock, jsonResponse } from "../helpers/fetchMock.js";
import { OllamaCloudProvider } from "../../src/providers/ollama.js";
import type { AIProvider } from "../../src/providers/provider.js";
import { buildProviderFrom } from "../../src/server.js";

describe("OllamaCloudProvider", () => {
  it("targets hosted Ollama Cloud by default", async () => {
    const fetchFn = fetchMock(async () => jsonResponse({ choices: [{ message: { content: "{}" } }] }));
    const p = new OllamaCloudProvider({ apiKey: "k", model: "llama3.1", fetchFn });
    expect(p.name).toBe("ollama");
    await p.analyze({ systemPrompt: "s", userPrompt: "u", images: [] });
    expect(fetchFn.mock.calls[0][0]).toBe("https://ollama.com/v1/chat/completions");
  });

  it("honours DFIR_AI_BASE_URL to hit a LOCAL Ollama daemon, no proxy", async () => {
    const fetchFn = fetchMock(async () =>
      jsonResponse({ choices: [{ message: { content: '{"summary":"ok"}' } }] }),
    );
    // This is exactly what DFIR_AI_BASE_URL=http://localhost:11434/v1 threads into the provider.
    const p = new OllamaCloudProvider({
      apiKey: "",
      model: "llama3.2-vision",
      baseUrl: "http://localhost:11434/v1",
      fetchFn,
    });
    const result = await p.analyze({ systemPrompt: "s", userPrompt: "u", images: [] });
    expect(result.rawText).toBe('{"summary":"ok"}');
    expect(fetchFn.mock.calls[0][0]).toBe("http://localhost:11434/v1/chat/completions");
    // Local Ollama ignores auth; an empty key sends a harmless `Bearer ` it discards.
    const init = fetchFn.mock.calls[0][1] as RequestInit;
    expect((init.headers as Record<string, string>).authorization).toBe("Bearer ");
    // OpenAI-compatible shape: model + json_object response format.
    const sent = JSON.parse(init.body as string);
    expect(sent.model).toBe("llama3.2-vision");
    expect(sent.response_format).toEqual({ type: "json_object" });
  });

  it("labels its errors 'Ollama', not 'OpenAI'", async () => {
    const fetchFn = fetchMock(async () => jsonResponse({ error: "model not found" }, 404));
    const p = new OllamaCloudProvider({
      apiKey: "",
      model: "nope",
      baseUrl: "http://localhost:11434/v1",
      fetchFn,
    });
    await p.analyze({ systemPrompt: "s", userPrompt: "u", images: [] }).catch((e: Error) => {
      expect(e.message).toContain("Ollama");
      expect(e.message).not.toContain("OpenAI");
    });
  });
});

describe("buildProviderFrom — ollama base-URL wiring", () => {
  it("resolves the ollama provider by name (DFIR_AI_BASE_URL is threaded through this path)", () => {
    const p = buildProviderFrom({
      provider: "ollama",
      model: "llama3.2-vision",
      baseUrl: "http://localhost:11434/v1",
    });
    expect(p?.name).toBe("ollama");
  });
});

describe("OllamaCloudProvider — supportsThinking (#1468)", () => {
  it("declares that it acts on thinkingTokens (reasoning_effort)", () => {
    const p: AIProvider = new OllamaCloudProvider({ apiKey: "k", model: "glm-5.3-flash" });
    expect(p.supportsThinking).toBe(true);
  });
});

describe("OllamaCloudProvider — reasoning_effort", () => {
  const sentBody = async (thinkingTokens?: number) => {
    const fetchFn = fetchMock(async () => jsonResponse({ choices: [{ message: { content: "{}" } }] }));
    const p = new OllamaCloudProvider({ apiKey: "k", model: "glm-5.3-flash", fetchFn });
    await p.analyze({ systemPrompt: "s", userPrompt: "u", images: [], thinkingTokens });
    return JSON.parse((fetchFn.mock.calls[0][1] as RequestInit).body as string);
  };

  it("asks for low effort by default, so a reasoning model cannot spend the whole output limit thinking", async () => {
    expect((await sentBody()).reasoning_effort).toBe("low");
    expect((await sentBody(500)).reasoning_effort).toBe("low");
  });

  it("asks for high effort when deep reasoning is on", async () => {
    expect((await sentBody(1024)).reasoning_effort).toBe("high");
    expect((await sentBody(8000)).reasoning_effort).toBe("high");
  });

  it("never sends reasoning_effort none", async () => {
    for (const t of [undefined, 0, 1024]) expect((await sentBody(t)).reasoning_effort).not.toBe("none");
  });
});
