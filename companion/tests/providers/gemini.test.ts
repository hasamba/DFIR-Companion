import { describe, it, expect } from "vitest";
import { GeminiProvider } from "../../src/providers/gemini.js";
import { ProviderError, type AnalyzeResult } from "../../src/providers/provider.js";

describe("GeminiProvider — base URL validation (#246)", () => {
  // validateBaseUrl() has its own unit tests (urlValidation.test.ts); these confirm it's actually
  // WIRED into the real constructor, not just written and left uncalled.
  it("throws constructing with an http:// base URL to a non-loopback host", () => {
    expect(
      () =>
        new GeminiProvider({
          apiKey: "k",
          model: "gemini-1.5-pro",
          baseUrl: "http://attacker.example.com/v1",
        }),
    ).toThrow(ProviderError);
  });

  it("allows http:// to a loopback host", () => {
    expect(
      () => new GeminiProvider({ apiKey: "k", model: "gemini-1.5-pro", baseUrl: "http://127.0.0.1:4000/v1" }),
    ).not.toThrow();
  });

  it("allows https:// to any host, including the provider default", () => {
    expect(() => new GeminiProvider({ apiKey: "k", model: "gemini-1.5-pro" })).not.toThrow();
  });
});

describe("GeminiProvider — API key placement (#516)", () => {
  // A key in the query string is written into the request line, so it lands in the access log of
  // any proxy or gateway on the path — and baseUrl is user-configurable, so that path can be one
  // the operator does not control. Google accepts the key as a header; nothing needs it in the URL.
  it("sends the key in the x-goog-api-key header and keeps it out of the URL", async () => {
    let seenUrl = "";
    let seenHeaders: Record<string, string> = {};
    const provider = new GeminiProvider({
      apiKey: "super-secret-key",
      model: "gemini-2.5-pro",
      fetchFn: async (input: RequestInfo | URL, init?: RequestInit) => {
        seenUrl = String(input);
        seenHeaders = (init?.headers ?? {}) as Record<string, string>;
        return {
          ok: true,
          status: 200,
          json: async () => ({ candidates: [{ content: { parts: [{ text: '{"findings":[]}' }] } }] }),
          text: async () => "",
        } as unknown as Response;
      },
    });
    await provider.analyze({ systemPrompt: "s", userPrompt: "x", images: [] });

    expect(seenUrl).not.toContain("super-secret-key");
    expect(seenUrl).not.toContain("key=");
    expect(seenHeaders["x-goog-api-key"]).toBe("super-secret-key");
  });
});

describe("GeminiProvider — usageMetadata parsing (#3)", () => {
  it("reports input/output/cacheRead tokens from usageMetadata so the AI cost card is not always 0/0", async () => {
    const fakeResponse = {
      ok: true,
      status: 200,
      json: async () => ({
        candidates: [{ content: { parts: [{ text: '{"findings":[]}' }] } }],
        usageMetadata: { promptTokenCount: 42, candidatesTokenCount: 7, cachedContentTokenCount: 3 },
      }),
      text: async () => "",
    };
    const provider = new GeminiProvider({
      apiKey: "k",
      model: "gemini-2.5-pro",
      fetchFn: async () => fakeResponse as unknown as Response,
    });
    const result: AnalyzeResult = await provider.analyze({ systemPrompt: "s", userPrompt: "x", images: [] });
    expect(result.usage).toBeDefined();
    expect(result.usage!.inputTokens).toBe(42);
    expect(result.usage!.outputTokens).toBe(7);
    expect(result.usage!.cacheReadTokens).toBe(3);
    // Google does not report a dollar cost.
    expect(result.usage!.costUSD).toBeUndefined();
  });

  it("omits usage when usageMetadata is absent (no regression)", async () => {
    const fakeResponse = {
      ok: true,
      status: 200,
      json: async () => ({ candidates: [{ content: { parts: [{ text: '{"findings":[]}' }] } }] }),
      text: async () => "",
    };
    const provider = new GeminiProvider({
      apiKey: "k",
      model: "gemini-2.5-pro",
      fetchFn: async () => fakeResponse as unknown as Response,
    });
    const result = await provider.analyze({ systemPrompt: "s", userPrompt: "x", images: [] });
    expect(result.usage).toBeUndefined();
  });
});
