import { describe, it, expect } from "vitest";
import { ProviderRegistry, MockProvider, type AnalyzeRequest } from "../../src/providers/provider.js";

describe("ProviderRegistry", () => {
  it("registers and resolves a provider by name", () => {
    const registry = new ProviderRegistry();
    registry.register(new MockProvider("mock", '{"summary":"ok"}'));
    const p = registry.get("mock");
    expect(p.name).toBe("mock");
  });

  it("throws for unknown provider", () => {
    const registry = new ProviderRegistry();
    expect(() => registry.get("nope")).toThrow();
  });

  it("MockProvider returns its canned response", async () => {
    const p = new MockProvider("mock", "RAW-JSON");
    const req: AnalyzeRequest = { systemPrompt: "s", userPrompt: "u", images: [] };
    const result = await p.analyze(req);
    expect(result.rawText).toBe("RAW-JSON");
  });
});
