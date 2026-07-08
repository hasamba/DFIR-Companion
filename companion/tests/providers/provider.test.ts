import { describe, it, expect } from "vitest";
import { ProviderRegistry, MockProvider, requestSignal, type AnalyzeRequest } from "../../src/providers/provider.js";

describe("requestSignal (#225 cancel)", () => {
  it("returns a plain timeout signal when no external signal is given", () => {
    const s = requestSignal(50_000);
    expect(s).toBeInstanceOf(AbortSignal);
    expect(s.aborted).toBe(false);
  });

  it("aborts immediately when the external signal is already aborted", () => {
    const external = AbortSignal.abort();
    const s = requestSignal(50_000, external);
    expect(s.aborted).toBe(true);
  });

  it("aborts when the external signal fires later (combined via AbortSignal.any)", () => {
    const controller = new AbortController();
    const s = requestSignal(50_000, controller.signal);
    expect(s.aborted).toBe(false);
    controller.abort();
    expect(s.aborted).toBe(true);
  });
});

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

describe("MockProvider", () => {
  it("defaults model to a placeholder when not given, but accepts an explicit one", async () => {
    const p1 = new MockProvider("mock", "{}");
    expect(p1.model).toBe("mock-model");
    const p2 = new MockProvider("mock", "{}", "gpt-4o-mini");
    expect(p2.model).toBe("gpt-4o-mini");
  });
});
