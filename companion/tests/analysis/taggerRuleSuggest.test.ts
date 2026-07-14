import { describe, it, expect } from "vitest";
import { parse as parseYaml } from "yaml";
import {
  suggestedRuleResponseSchema,
  sanitizeSuggestedRule,
  slugifyRuleId,
} from "../../src/analysis/taggerRuleSuggest.js";
import { compileRuleset } from "../../src/analysis/taggerRules.js";

describe("slugifyRuleId", () => {
  it("lowercases, replaces non-alphanumerics with underscores, trims", () => {
    expect(slugifyRuleId("Windows Log Cleared!")).toBe("windows_log_cleared");
  });
  it("falls back when the input has no usable characters", () => {
    expect(slugifyRuleId("!!!")).toBe("rule");
  });
});

describe("sanitizeSuggestedRule", () => {
  it("returns a decline when the model declines", () => {
    const parsed = suggestedRuleResponseSchema.parse({
      decline: "Counting logons over time isn't expressible as a single-event rule.",
    });
    const out = sanitizeSuggestedRule(parsed);
    expect(out.kind).toBe("decline");
    if (out.kind === "decline") expect(out.reason).toMatch(/single-event/);
  });

  it("produces a valid single-entry YAML rule from a well-formed reply", () => {
    const parsed = suggestedRuleResponseSchema.parse({
      ruleId: "Windows Log Cleared",
      explanation: "Matches Security 1102 log-clear events.",
      rule: {
        description: "Security event log cleared",
        any: [{ field: "message", contains: ["1102", "audit log was cleared"] }],
        tags: ["log-cleared", "defense-evasion"],
        mitre: ["T1070.001"],
        severity: "High",
      },
    });
    const out = sanitizeSuggestedRule(parsed);
    expect(out.kind).toBe("rule");
    if (out.kind === "rule") {
      expect(out.ruleId).toBe("windows_log_cleared");
      const doc = parseYaml(out.ruleYaml);
      expect(Object.keys(doc)).toEqual(["windows_log_cleared"]);
      expect(() => compileRuleset(doc)).not.toThrow();
    }
  });

  it("declines (never returns a broken rule) when the rule does not compile", () => {
    const parsed = suggestedRuleResponseSchema.parse({
      ruleId: "bad",
      explanation: "x",
      rule: { any: [{ field: "not_a_real_field", contains: "x" }], tags: ["t"] },
    });
    const out = sanitizeSuggestedRule(parsed);
    expect(out.kind).toBe("decline");
    if (out.kind === "decline") expect(out.reason).toMatch(/not_a_real_field|valid rule/i);
  });

  it("declines when the generated rule is too large", () => {
    const parsed = suggestedRuleResponseSchema.parse({
      ruleId: "huge",
      explanation: "x",
      rule: { any: [{ field: "message", contains: "a".repeat(8001) }], tags: ["t"] },
    });
    const out = sanitizeSuggestedRule(parsed);
    expect(out.kind).toBe("decline");
    if (out.kind === "decline") expect(out.reason).toMatch(/too large/i);
  });

  it("declines when the model returns no rule and no decline text", () => {
    const parsed = suggestedRuleResponseSchema.parse({ ruleId: "", explanation: "" });
    const out = sanitizeSuggestedRule(parsed);
    expect(out.kind).toBe("decline");
  });
});
