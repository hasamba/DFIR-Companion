import { describe, expect, it } from "vitest";
import { WatsonRiskNotAccepted } from "../../../../src/analysis/ai/watson/proposalErrors.js";
import { steFallback, steReason, steReasons } from "../../../../src/analysis/ai/watson/velo/vqlReasonSte.js";
import { plainRisk, ruleFor } from "../../../../src/analysis/ai/watson/velo/vqlRiskClass.js";
import { FIXED_REASONS, SAMPLES, reasonsOf } from "./reasonSamples.js";

// Task 10 fix round: every launch-check reason reaches the chat as ASD-STE100 sentences (display
// only). The stored reason text, and what vqlRiskClass matches, stays byte-identical.

const ALL_REASONS = [...new Set([...FIXED_REASONS, ...SAMPLES.flatMap(([vql]) => reasonsOf(vql))])];
const sentences = (text: string): string[] => text.split(/(?<=[.?!])\s+/).filter(Boolean);
const words = (s: string): number => s.split(/\s+/).filter(Boolean).length;

describe("launch-check reasons in ASD-STE100", () => {
  it("covers the full reason enumeration", () => {
    expect(ALL_REASONS.length).toBeGreaterThan(50);
    expect(ALL_REASONS.every((r) => ruleFor(r))).toBe(true);
  });

  it.each(ALL_REASONS)("maps %s to STE copy, not to the fallback", (reason) => {
    const ste = steReason(reason);
    expect(ste).not.toBe(steFallback(reason));
    expect(ste).toMatch(/^[A-Z'].*\.$/s);
    for (const s of sentences(ste)) expect(words(s), s).toBeLessThanOrEqual(20);
    expect(ste).not.toMatch(/;|—|\bmay\b|\bwould normally\b|n't\b/);
  });

  it.each([
    ["SELECT * FROM somethingelse()", "somethingelse"],
    ["SELECT * FROM eval(func='x')", "eval"],
    ["SELECT * FROM foo.bar()", "foo.bar"],
    ["SELECT * FROM pslist(1)", "pslist"],
    ["LET Val = 1 SELECT * FROM Val()", "Val"],
    ["SELECT * FROM wmi(query='SELECT * FROM Win32_Evil')", "Win32_Evil"],
    ["SELECT * FROM glob(globs='/x', upload=true)", "upload"],
  ])("keeps the technical name in the STE copy of %s", (vql, name) => {
    expect(steReasons(reasonsOf(vql))).toContain(name);
  });

  it("names the call and its effect for a known call", () => {
    expect(steReason("the VQL calls execve, which is not on Watson's read-only list")).toBe(
      "The query runs a program on the endpoint (execve).",
    );
    expect(
      steReason("the VQL calls artifact Windows.Evil.Thing, which is not on Watson's read-only list"),
    ).toBe("The query uses artifact Windows.Evil.Thing. This artifact is not on the reviewed safe list.");
  });

  it("an unknown reason gets the generic STE line and the raw reason as a code", () => {
    expect(steReason("something new")).toBe(
      'The safety check blocked this query. Reason code: "something new".',
    );
    expect(steReasons(["the VQL is empty", "comments are not allowed"])).toBe(
      "The query is empty. Watson does not accept comments in the query.",
    );
  });

  it("does not change the stored text: the raw reason still classifies and reads as before", () => {
    for (const r of ALL_REASONS) {
      const before = `${r}`;
      steReason(r);
      expect(r).toBe(before);
      expect(ruleFor(r)).toBeDefined();
    }
    const err = new WatsonRiskNotAccepted(["raw plain"], ["The query uses x."]);
    expect(err.reasons).toEqual(["raw plain"]);
    expect(err.message).toBe(
      "This query is risky. The query uses x. Read the query. Then confirm that you accept the risk to launch it.",
    );
    expect(plainRisk("the VQL calls execve, which is not on Watson's read-only list")).toBe(
      "runs a program on the endpoint (execve)",
    );
  });
});
