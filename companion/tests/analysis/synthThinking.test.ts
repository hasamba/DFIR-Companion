import { describe, it, expect } from "vitest";
import {
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
