import { describe, it, expect } from "vitest";
import { runCsvExtraction, runLogExtraction, runSynthesis } from "./harness.js";
import { scoreExtraction, checkSynthesis, passesExtraction, passesSynthesis } from "./scorer.js";
import { EXTRACTION_FIXTURES, SYNTHESIS_FIXTURES } from "./fixtures.js";

// Phase-1 integration: the MockProvider makes each run deterministic, so these assertions gate the
// pipeline→scorer PLUMBING (and the fixtures), not model quality. The same harness with a real provider
// is Phase 2.
describe("eval harness — extraction fixtures (#64)", () => {
  for (const fx of EXTRACTION_FIXTURES) {
    it(`${fx.modality}: ${fx.name} meets its golden precision/recall`, async () => {
      const produced = fx.modality === "csv"
        ? await runCsvExtraction(fx.canned, fx.input)
        : await runLogExtraction(fx.canned, fx.input);
      expect(produced.length).toBeGreaterThan(0);       // the pipeline actually emitted events
      const score = scoreExtraction(fx.golden, produced, { toleranceMinutes: 5 });
      expect(passesExtraction(score, fx.thresholds)).toBe(true);
    });
  }

  it("catches a regression: a missed detection drops recall below threshold", async () => {
    const fx = EXTRACTION_FIXTURES[0];
    const produced = await runCsvExtraction(fx.canned, fx.input);
    // Add a golden expectation nothing produced satisfies → recall must fall, gate must fail.
    const withMissed = [...fx.golden, { keywords: ["data exfiltration to external host"] }];
    const score = scoreExtraction(withMissed, produced);
    expect(score.falseNegatives).toBe(1);
    expect(passesExtraction(score)).toBe(false);
  });
});

describe("eval harness — synthesis fixtures (#64)", () => {
  for (const fx of SYNTHESIS_FIXTURES) {
    it(`${fx.name}: covered, grounded, nothing invented`, async () => {
      const { events, findings } = await runSynthesis(fx.canned, fx.seedEvents);
      const report = checkSynthesis(events, findings);
      // Every seeded Critical/High event is covered (deterministic backfill guarantees it)…
      expect(report.highSeverity.uncovered).toEqual([]);
      // …no finding references an event id absent from the timeline (no hallucinated refs)…
      expect(report.danglingEventRefs).toEqual([]);
      expect(passesSynthesis(report)).toBe(true);
    });
  }
});
