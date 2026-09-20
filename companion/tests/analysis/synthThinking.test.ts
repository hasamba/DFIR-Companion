import { describe, it, expect } from "vitest";
import {
  resolveSynthThinking,
  resolveSynthThinkingBudget,
  DEFAULT_SYNTH_THINKING_TOKENS,
  MIN_SYNTH_THINKING_TOKENS,
} from "../../src/analysis/synthThinking.js";

describe("resolveSynthThinkingBudget (#121 per-run deep-reasoning toggle)", () => {
  it("uses the global env default when no per-run input is given", () => {
    expect(resolveSynthThinkingBudget({}, 8000)).toBe(8000);
    expect(resolveSynthThinkingBudget({}, 0)).toBe(0);
  });

  it("treats an env value below the minimum as off", () => {
    expect(resolveSynthThinkingBudget({}, 500)).toBe(0);
    expect(resolveSynthThinkingBudget({}, MIN_SYNTH_THINKING_TOKENS - 1)).toBe(0);
  });

  it("deepReasoning uses the env budget when meaningfully set", () => {
    expect(resolveSynthThinkingBudget({ deepReasoning: true }, 12000)).toBe(12000);
  });

  it("deepReasoning falls back to the default when the env is unset/too low (toggle works with no .env)", () => {
    expect(resolveSynthThinkingBudget({ deepReasoning: true }, 0)).toBe(DEFAULT_SYNTH_THINKING_TOKENS);
    expect(resolveSynthThinkingBudget({ deepReasoning: true }, 100)).toBe(DEFAULT_SYNTH_THINKING_TOKENS);
  });

  it("an explicit per-run thinkingTokens wins over deepReasoning and the env", () => {
    expect(resolveSynthThinkingBudget({ thinkingTokens: 5000, deepReasoning: true }, 8000)).toBe(5000);
    expect(resolveSynthThinkingBudget({ thinkingTokens: 5000 }, 0)).toBe(5000);
  });

  it("an explicit thinkingTokens of 0 (or below min) forces OFF for this run, even with the env set", () => {
    expect(resolveSynthThinkingBudget({ thinkingTokens: 0 }, 8000)).toBe(0);
    expect(resolveSynthThinkingBudget({ thinkingTokens: 500 }, 8000)).toBe(0);
  });

  it("floors fractional budgets", () => {
    expect(resolveSynthThinkingBudget({ thinkingTokens: 2048.9 }, 0)).toBe(2048);
  });
});

describe("resolveSynthThinking (#1468 records where the budget came from)", () => {
  it("names the env as the source when only the global default is set", () => {
    expect(resolveSynthThinking({}, 8000)).toEqual({ tokens: 8000, source: "env" });
  });

  it("is off when nothing sets a budget", () => {
    expect(resolveSynthThinking({}, 0)).toEqual({ tokens: 0, source: "off" });
    expect(resolveSynthThinking({ deepReasoning: false }, 500)).toEqual({ tokens: 0, source: "off" });
  });

  it("names the toggle when the per-run deep-reasoning checkbox is on, with or without an env budget", () => {
    expect(resolveSynthThinking({ deepReasoning: true }, 12000)).toEqual({ tokens: 12000, source: "toggle" });
    expect(resolveSynthThinking({ deepReasoning: true }, 0)).toEqual({
      tokens: DEFAULT_SYNTH_THINKING_TOKENS,
      source: "toggle",
    });
  });

  it("an explicit per-run budget is a per-run choice, so its source is the toggle", () => {
    expect(resolveSynthThinking({ thinkingTokens: 5000 }, 0)).toEqual({ tokens: 5000, source: "toggle" });
    expect(resolveSynthThinking({ thinkingTokens: 5000, deepReasoning: true }, 8000)).toEqual({
      tokens: 5000,
      source: "toggle",
    });
  });

  it("an explicit 0 forces off for this run, and records off even though the env is set", () => {
    expect(resolveSynthThinking({ thinkingTokens: 0 }, 8000)).toEqual({ tokens: 0, source: "off" });
    expect(resolveSynthThinking({ thinkingTokens: 500, deepReasoning: true }, 8000)).toEqual({
      tokens: 0,
      source: "off",
    });
  });

  it("agrees with resolveSynthThinkingBudget on the token count", () => {
    const cases: Array<[Parameters<typeof resolveSynthThinking>[0], number]> = [
      [{}, 8000],
      [{}, 0],
      [{ deepReasoning: true }, 0],
      [{ deepReasoning: true }, 12000],
      [{ thinkingTokens: 5000 }, 0],
      [{ thinkingTokens: 0 }, 8000],
      [{ thinkingTokens: 2048.9 }, 0],
    ];
    for (const [opts, env] of cases) {
      expect(resolveSynthThinking(opts, env).tokens).toBe(resolveSynthThinkingBudget(opts, env));
    }
  });
});
