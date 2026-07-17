import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it, expect } from "vitest";
import {
  runExtractionFixture, runScreenshotFixture, runSynthesisFixture, mockProvider,
  loadRealScreenshotFixtures, runRealScreenshotFixture,
} from "./harness.js";
import { scoreExtraction, checkSynthesis, passesExtraction, passesSynthesis } from "./scorer.js";
import { EXTRACTION_FIXTURES, SCREENSHOT_FIXTURES, SYNTHESIS_FIXTURES } from "./fixtures.js";

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

// The vision path (analyzeWindow) driven MOCK-ONLY: a canned delta + stub image, so this gates the
// analyzeWindow→scorer plumbing without any committed screenshot. Real vision grading stays deferred.
describe("eval harness — screenshot fixtures (#64)", () => {
  for (const fx of SCREENSHOT_FIXTURES) {
    it(`screenshot: ${fx.name} meets its golden precision/recall`, async () => {
      const produced = await runScreenshotFixture(fx, mockProvider(fx.canned));
      expect(produced.length).toBeGreaterThan(0);       // analyzeWindow actually emitted events
      const score = scoreExtraction(fx.golden, produced, { toleranceMinutes: 5 });
      expect(passesExtraction(score, fx.thresholds)).toBe(true);
    });
  }
});

// Real screenshot grading (#135) sources images + goldens from a local, uncommitted directory. These
// tests exercise the loader + runner plumbing with a MockProvider (deterministic, no real image bytes
// are actually decoded by analyzeWindow) — grading against the REAL vision model is exactly what
// `npm run eval:real:screenshots` does manually against a locally configured DFIR_EVAL_SCREENSHOT_DIR.
describe("eval harness — real screenshot loader (#135)", () => {
  it("returns [] for a directory that doesn't exist — a clean skip, not a throw", async () => {
    const fixtures = await loadRealScreenshotFixtures(join(tmpdir(), "dfir-eval-does-not-exist"));
    expect(fixtures).toEqual([]);
  });

  it("loads image+sidecar pairs and skips an image with no valid sidecar", async () => {
    const dir = await mkdtemp(join(tmpdir(), "dfir-eval-screenshots-"));
    await writeFile(join(dir, "task.webp"), "not a real image, just bytes");
    await writeFile(join(dir, "task.json"), JSON.stringify({
      tabTitle: "Velociraptor — Task Scheduler",
      url: "https://velociraptor.local/app",
      golden: [{ keywords: ["powershell"], mitreTechniques: ["T1053.005"] }],
    }));
    await writeFile(join(dir, "orphan.png"), "no sidecar for this one");
    await writeFile(join(dir, "notes.txt"), "not an image — ignored entirely");

    const fixtures = await loadRealScreenshotFixtures(dir);
    expect(fixtures).toHaveLength(1);
    expect(fixtures[0]).toMatchObject({
      name: "task",
      mimeType: "image/webp",
      tabTitle: "Velociraptor — Task Scheduler",
      golden: [{ keywords: ["powershell"], mitreTechniques: ["T1053.005"] }],
    });
  });

  it("runRealScreenshotFixture drives analyzeWindow off the real image path", async () => {
    const dir = await mkdtemp(join(tmpdir(), "dfir-eval-screenshots-"));
    await writeFile(join(dir, "task.webp"), "placeholder bytes");
    await writeFile(join(dir, "task.json"), JSON.stringify({ golden: [] }));
    const [fx] = await loadRealScreenshotFixtures(dir);

    const canned = JSON.stringify({
      findings: [], iocs: [], mitreTechniques: [], threadsOpened: [], threadsClosed: [],
      timelineNote: "", summary: "eval",
      forensicEvents: [{ id: "e1", timestamp: "2026-06-01T02:13:00Z", description: "Scheduled task launches hidden powershell", severity: "High", mitreTechniques: ["T1053.005"], asset: "WS02" }],
    });
    const produced = await runRealScreenshotFixture(fx, mockProvider(canned));
    expect(produced).toHaveLength(1);
    expect(produced[0].description).toContain("powershell");
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
