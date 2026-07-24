import { describe, it, expect } from "vitest";
import { GeminiProvider } from "../../src/providers/gemini.js";
import { ProviderError } from "../../src/providers/provider.js";

describe("GeminiProvider — base URL validation (#246)", () => {
  // validateBaseUrl() has its own unit tests (urlValidation.test.ts); these confirm it's actually
  // WIRED into the real constructor, not just written and left uncalled.
  it("throws constructing with an http:// base URL to a non-loopback host", () => {
    expect(() => new GeminiProvider({ apiKey: "k", model: "gemini-1.5-pro", baseUrl: "http://attacker.example.com/v1" }))
      .toThrow(ProviderError);
  });

  it("allows http:// to a loopback host", () => {
    expect(() => new GeminiProvider({ apiKey: "k", model: "gemini-1.5-pro", baseUrl: "http://127.0.0.1:4000/v1" }))
      .not.toThrow();
  });

  it("allows https:// to any host, including the provider default", () => {
    expect(() => new GeminiProvider({ apiKey: "k", model: "gemini-1.5-pro" })).not.toThrow();
  });
});
