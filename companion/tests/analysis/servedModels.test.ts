// Where the concrete served model goes after each AI call (#1601).
import { describe, it, expect } from "vitest";
import {
  ServedModelRegistry,
  collectServedModel,
  validResolvedModel,
  type ServedModelEvent,
} from "../../src/analysis/servedModels.js";

describe("validResolvedModel", () => {
  it("keeps a plain id, trimmed", () => {
    expect(validResolvedModel(" claude-sonnet-5 ")).toBe("claude-sonnet-5");
  });

  it.each([undefined, null, 5, "", "   ", "a".repeat(201), "claude\nsonnet", "x\u0000y"])(
    "rejects %j",
    (value) => {
      expect(validResolvedModel(value)).toBeUndefined();
    },
  );
});

describe("ServedModelRegistry", () => {
  it("keeps the last answer per provider and alias", () => {
    const registry = new ServedModelRegistry();
    registry.record({ provider: "claude-code", alias: "sonnet", resolvedModel: "claude-sonnet-4-6" });
    registry.record({ provider: "claude-code", alias: "sonnet", resolvedModel: "claude-sonnet-5" });
    registry.record({ provider: "claude-code", alias: "opus", resolvedModel: "claude-opus-5-5" });
    expect(registry.lastFor("claude-code", "sonnet")).toBe("claude-sonnet-5");
    expect(registry.lastFor("claude-code", "opus")).toBe("claude-opus-5-5");
    expect(registry.lastFor("openrouter", "sonnet")).toBeUndefined();
  });

  it("ignores a call that reported no model — nothing is guessed", () => {
    const registry = new ServedModelRegistry();
    const seen: ServedModelEvent[] = [];
    registry.subscribe((e) => seen.push(e));
    registry.record({ provider: "openai", alias: "gpt-6-sol", resolvedModel: undefined });
    expect(registry.lastFor("openai", "gpt-6-sol")).toBeUndefined();
    expect(seen).toEqual([]);
  });

  it("tells subscribers, with the call's signal, and stops after unsubscribe", () => {
    const registry = new ServedModelRegistry();
    const seen: ServedModelEvent[] = [];
    const off = registry.subscribe((e) => seen.push(e));
    const signal = new AbortController().signal;
    registry.record({ provider: "claude-code", alias: "sonnet", resolvedModel: "claude-sonnet-5", signal });
    off();
    registry.record({ provider: "claude-code", alias: "sonnet", resolvedModel: "claude-sonnet-5" });
    expect(seen).toHaveLength(1);
    expect(seen[0].signal).toBe(signal);
    expect(seen[0].resolvedModel).toBe("claude-sonnet-5");
  });

  it("a throwing subscriber cannot fail the call", () => {
    const registry = new ServedModelRegistry();
    registry.subscribe(() => {
      throw new Error("boom");
    });
    expect(() =>
      registry.record({ provider: "claude-code", alias: "sonnet", resolvedModel: "claude-sonnet-5" }),
    ).not.toThrow();
  });
});

describe("collectServedModel", () => {
  it("reports the last model served inside its own call chain only", async () => {
    const registry = new ServedModelRegistry();
    const tick = () => new Promise((r) => setTimeout(r, 1));
    const [mine, other] = await Promise.all([
      collectServedModel(async () => {
        await tick();
        registry.record({ provider: "claude-code", alias: "sonnet", resolvedModel: "claude-sonnet-4-6" });
        await tick();
        registry.record({ provider: "claude-code", alias: "sonnet", resolvedModel: "claude-sonnet-5" });
        await tick();
        return "a";
      }),
      collectServedModel(async () => {
        await tick();
        registry.record({ provider: "claude-code", alias: "opus", resolvedModel: "claude-opus-5-5" });
        await tick();
        await tick();
        await tick();
        return "b";
      }),
    ]);
    expect(mine).toEqual({ value: "a", resolvedModel: "claude-sonnet-5" });
    expect(other).toEqual({ value: "b", resolvedModel: "claude-opus-5-5" });
  });

  it("reports nothing when no call reported a model", async () => {
    expect(await collectServedModel(async () => 1)).toEqual({ value: 1 });
  });
});
