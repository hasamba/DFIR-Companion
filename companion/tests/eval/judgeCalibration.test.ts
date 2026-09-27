import { describe, expect, it } from "vitest";
import type { AIProvider, AnalyzeRequest } from "../../src/providers/provider.js";
import { gradeCalibration, loadCalibration } from "./judgeCalibration.js";

describe("judge calibration set (#1704)", () => {
  it("holds real rejections that must be cleared and accusations that must be flagged", async () => {
    const items = await loadCalibration();
    expect(
      items.filter((item) => item.source.startsWith("real") && !item.expected).length,
    ).toBeGreaterThanOrEqual(9);
    expect(items.filter((item) => item.expected).length).toBeGreaterThanOrEqual(5);
    expect(new Set(items.map((item) => item.id)).size).toBe(items.length);
    // Codex review (#1704): a hedged assertion and a data-block escape attempt must both be flagged.
    for (const id of ["synthetic-nightfall-hedged-assertion", "synthetic-nightfall-block-escape"]) {
      expect(items.find((item) => item.id === id)?.expected).toBe(true);
    }
  });

  it("reports every item a judge gets wrong", async () => {
    const items = await loadCalibration();
    // A judge that clears everything misses exactly the must-flag items.
    const lenient: AIProvider = {
      name: "stub",
      model: "stub",
      async analyze(request: AnalyzeRequest) {
        const doc = JSON.parse(request.userPrompt.slice(request.userPrompt.indexOf("{"))) as {
          findings: { label: string }[];
        };
        const findings = doc.findings.map((finding) => finding.label);
        return {
          rawText: JSON.stringify({
            verdicts: findings.map((finding) => ({ statement: "S1", finding, asserts: false, reason: "no" })),
          }),
        };
      },
    };
    const wrong = await gradeCalibration(items, lenient);
    expect(wrong).toHaveLength(items.filter((item) => item.expected).length);
  });
});
