import { describe, it, expect } from "vitest";
import { effortForBudget } from "../../src/providers/claudeEffort.js";

// The claude-code provider has no token budget knob — the CLI takes a coarse `--effort` tier
// instead (#1468). This table pins the budget → tier mapping the dashboard's 🧠 toggle relies on.
describe("effortForBudget", () => {
  it.each([
    [undefined, undefined],
    [Number.NaN, undefined],
    [0, undefined],
    [1023, undefined],
    [1024, "medium"],
    [7999, "medium"],
    [8000, "high"],
    [31999, "high"],
    [32000, "xhigh"],
    [1e9, "xhigh"],
  ] as const)("maps a budget of %s to %s", (tokens, expected) => {
    expect(effortForBudget(tokens)).toBe(expected);
  });

  it("never asks for the CLI's `max` tier", () => {
    for (const t of [32000, 100_000, 1e9, Number.MAX_SAFE_INTEGER]) {
      expect(effortForBudget(t)).not.toBe("max");
    }
  });
});
