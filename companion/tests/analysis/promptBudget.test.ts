import { describe, it, expect, afterEach } from "vitest";
import {
  estimateTokens, contextTokens, inputTokenBudget, fitItemsToBudget, batchByBudget, DEFAULT_CONTEXT_TOKENS,
} from "../../src/analysis/promptBudget.js";

describe("promptBudget", () => {
  const prevCtx = process.env.DFIR_AI_CONTEXT_TOKENS;
  const prevMax = process.env.DFIR_AI_MAX_TOKENS;
  afterEach(() => {
    if (prevCtx === undefined) delete process.env.DFIR_AI_CONTEXT_TOKENS; else process.env.DFIR_AI_CONTEXT_TOKENS = prevCtx;
    if (prevMax === undefined) delete process.env.DFIR_AI_MAX_TOKENS; else process.env.DFIR_AI_MAX_TOKENS = prevMax;
  });

  it("estimates ~4 chars per token (rounded up)", () => {
    expect(estimateTokens("")).toBe(0);
    expect(estimateTokens("abcd")).toBe(1);
    expect(estimateTokens("abcde")).toBe(2);
  });

  it("defaults the context window to 128000 and reads DFIR_AI_CONTEXT_TOKENS", () => {
    delete process.env.DFIR_AI_CONTEXT_TOKENS;
    expect(contextTokens()).toBe(DEFAULT_CONTEXT_TOKENS);
    process.env.DFIR_AI_CONTEXT_TOKENS = "200000";
    expect(contextTokens()).toBe(200000);
    process.env.DFIR_AI_CONTEXT_TOKENS = "garbage";
    expect(contextTokens()).toBe(DEFAULT_CONTEXT_TOKENS);   // invalid → default
  });

  it("reserves output + a 5% (≥1000) margin from the input budget", () => {
    // 128000 ctx, 16000 out, margin = 5% = 6400 → 105600.
    expect(inputTokenBudget(128000, 16000)).toBe(105600);
    // tiny ctx → margin floor of 1000.
    expect(inputTokenBudget(10000, 2000)).toBe(10000 - 2000 - 1000);
    // never negative.
    expect(inputTokenBudget(1000, 5000)).toBe(0);
  });

  it("fitItemsToBudget keeps as many leading items as fit (always ≥1; 0 budget = all)", () => {
    const items = ["aaaa", "bbbb", "cccc", "dddd"];   // 1 token each (+1 newline) = 2 each
    expect(fitItemsToBudget(items, (s) => s, 0)).toBe(4);     // disabled → all
    expect(fitItemsToBudget(items, (s) => s, 5)).toBe(2);     // 2 fit (4 tokens), 3rd would be 6 > 5
    expect(fitItemsToBudget(items, (s) => s, 1)).toBe(1);     // oversized first item still kept
    expect(fitItemsToBudget([], (s: string) => s, 100)).toBe(0);
  });

  it("batchByBudget splits by BOTH count and token budget", () => {
    const narrow = ["a", "b", "c", "d", "e"];               // tiny rows
    // count cap of 2 → [[a,b],[c,d],[e]]
    expect(batchByBudget(narrow, 2, (s) => s, 0).map((b) => b.length)).toEqual([2, 2, 1]);

    // A wide row forces an early split even under the count cap. Each "wide" ≈ 25 tokens.
    const wide = ["x".repeat(100), "y".repeat(100), "z".repeat(100)];
    const batches = batchByBudget(wide, 50, (s) => s, 30);   // budget 30 tokens → ~1 wide row per batch
    expect(batches.map((b) => b.length)).toEqual([1, 1, 1]);

    // An item larger than the whole budget still becomes its own batch (never dropped).
    const huge = batchByBudget(["q".repeat(1000)], 50, (s) => s, 10);
    expect(huge).toEqual([["q".repeat(1000)]]);
  });
});
