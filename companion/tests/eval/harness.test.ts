import { describe, it, expect } from "vitest";
import { runExtractionFixture, runSynthesisFixture, mockProvider } from "./harness.js";
import { scoreExtraction, checkSynthesis, passesExtraction, passesSynthesis } from "./scorer.js";
import { EXTRACTION_FIXTURES, SYNTHESIS_FIXTURES } from "./fixtures.js";

// Phase-1 integration: a MockProvider (built from each fixture's canned response) makes every run
// deterministic, so these assertions gate the pipeline→scorer PLUMBING and the fixtures — not model
// quality. The identical runners with a REAL provider are Phase 2 (`npm run eval:real`, non-blocking).
describe("eval harness — extraction fixtures (#64)", () => {
  for (const fx of EXTRACTION_FIXTURES) {
    it(`${fx.modality}: ${fx.name} meets its golden precision/recall`, async () => {
      const produced = await runExtractionFixture(fx, mockProvider(fx.canned));
      expect(produced.length).toBeGreaterThan(0);       // the pipeline actually emitted events
      const score = scoreExtraction(fx.golden, produced, { toleranceMinutes: 5 });
      expect(passesExtraction(score, fx.thresholds)).toBe(true);
    });
  }

  it("catches a regression: a missed detection drops recall below threshold", async () => {
    const fx = EXTRACTION_FIXTURES[0];
    const produced = await runExtractionFixture(fx, mockProvider(fx.canned));
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
      const { events, findings } = await runSynthesisFixture(fx, mockProvider(fx.canned));
      const report = checkSynthesis(events, findings);
      // Every seeded Critical/High event is covered (deterministic backfill guarantees it)…
      expect(report.highSeverity.uncovered).toEqual([]);
      // …no finding references an event id absent from the timeline (no hallucinated refs)…
      expect(report.danglingEventRefs).toEqual([]);
      expect(passesSynthesis(report)).toBe(true);
    });
  }
});
