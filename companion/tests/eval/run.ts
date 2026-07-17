// CLI runner for the eval harness (issue #64) — CI-friendly summary + exit codes.
//
//   npm run eval[:extraction|:synthesis]        deterministic MockProvider run (Phase 1) — safe to gate PRs
//   npm run eval:real[:extraction|:synthesis]   REAL provider run (Phase 2) — non-blocking; needs DFIR_AI_*
//
// Phase 1 (default) drives every fixture with a MockProvider, so it's deterministic and verifies the harness
// + scorer, not model quality. Phase 2 (`--real`) swaps in the env-configured provider to score the CURRENT
// prompt's actual output against the golden expectations — the real regression signal. It's non-blocking:
// it is NOT wired into `npm test`, and if no provider is configured it SKIPS (exit 0) so CI never breaks.
//
// Exit codes: 0 = all pass (or real-mode skipped), 1 = a gate failed, 2 = a runner error.

import { config as loadDotenv } from "dotenv";
import { visionEnv } from "../../src/config/aiEnv.js";
import { runExtractionFixture, runScreenshotFixture, runSynthesisFixture, mockProvider, realProviderOrNull } from "./harness.js";
import {
  scoreExtraction, checkSynthesis, passesExtraction, passesSynthesis,
  formatExtractionReport, formatSynthesisReport, REAL_THRESHOLDS,
  type Thresholds,
} from "./scorer.js";
import { EXTRACTION_FIXTURES, SCREENSHOT_FIXTURES, SYNTHESIS_FIXTURES } from "./fixtures.js";
import type { AIProvider } from "../../src/providers/provider.js";

// In mock mode each fixture is driven by its OWN canned response, so the provider is chosen per fixture; in
// real mode a single env-configured provider is shared. `override` sets the gate for real runs (relaxed).
type ProviderFor<T> = (fx: T) => AIProvider;

async function runExtraction(providerFor: ProviderFor<(typeof EXTRACTION_FIXTURES)[number]>, override?: Thresholds): Promise<boolean> {
  let allPass = true;
  for (const fx of EXTRACTION_FIXTURES) {
    const produced = await runExtractionFixture(fx, providerFor(fx));
    const score = scoreExtraction(fx.golden, produced, { toleranceMinutes: 5 });
    const thresholds = fx.thresholds ?? override;
    console.log(formatExtractionReport(fx.name, score, thresholds));
    allPass = passesExtraction(score, thresholds) && allPass;
  }
  return allPass;
}

// Screenshot fixtures drive the vision path (analyzeWindow). MOCK-ONLY: each is driven by its own canned
// delta against a stub image, so it gates the plumbing + scorer without shipping evidence. Real vision
// grading is deferred (see README), so the runner never invokes this in --real mode.
async function runScreenshots(): Promise<boolean> {
  let allPass = true;
  for (const fx of SCREENSHOT_FIXTURES) {
    const produced = await runScreenshotFixture(fx, mockProvider(fx.canned));
    const score = scoreExtraction(fx.golden, produced, { toleranceMinutes: 5 });
    console.log(formatExtractionReport(`${fx.name} (screenshot)`, score, fx.thresholds));
    allPass = passesExtraction(score, fx.thresholds) && allPass;
  }
  return allPass;
}

async function runSynthesis(providerFor: ProviderFor<(typeof SYNTHESIS_FIXTURES)[number]>): Promise<boolean> {
  let allPass = true;
  for (const fx of SYNTHESIS_FIXTURES) {
    const { events, findings } = await runSynthesisFixture(fx, providerFor(fx));
    const report = checkSynthesis(events, findings);
    console.log(formatSynthesisReport(fx.name, report));
    allPass = passesSynthesis(report) && allPass;
  }
  return allPass;
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  const real = argv.includes("--real");
  const positional = argv.find((a) => !a.startsWith("--"));
  const mode = positional === "extraction" || positional === "synthesis" ? positional : "all";

  // Resolve the provider selector + gate. Real mode uses the env-configured model (dotenv-loaded like
  // verify-ai); if none is configured it's a graceful skip, not a failure.
  let extractionProvider: ProviderFor<{ canned: string }>;
  let synthesisProvider: ProviderFor<{ canned: string }>;
  let override: Thresholds | undefined;
  if (real) {
    loadDotenv({ quiet: true });
    const provider = realProviderOrNull();
    if (!provider) {
      console.log("eval --real: no AI provider configured (set DFIR_AI_SYNTH_* or DFIR_VISION_*) — skipped.");
      process.exit(0);
    }
    // Report the TEXT model — that's what realProviderOrNull() resolves and what these fixtures grade.
    const model = process.env.DFIR_AI_SYNTH_MODEL ?? visionEnv(process.env, "MODEL") ?? "(default)";
    console.log(`eval --real: provider ${provider.name}, model ${model}\n`);
    extractionProvider = synthesisProvider = () => provider;
    override = REAL_THRESHOLDS;
  } else {
    extractionProvider = synthesisProvider = (fx) => mockProvider(fx.canned);
  }

  let ok = true;
  if (mode === "extraction" || mode === "all") {
    ok = (await runExtraction(extractionProvider, override)) && ok;
    // Screenshot fixtures are mock-only. In --real mode there's no committed evidence to grade the vision
    // model against, so skip them (deliberate — see README) rather than run them against a stub image.
    if (real) console.log("\nscreenshot fixtures: mock-only — skipped in --real mode (see README)");
    else ok = (await runScreenshots()) && ok;
  }
  if (mode === "synthesis" || mode === "all") ok = (await runSynthesis(synthesisProvider)) && ok;
  console.log(ok ? "\nEVAL PASSED" : "\nEVAL FAILED");
  process.exit(ok ? 0 : 1);
}

main().catch((err) => { console.error(err); process.exit(2); });
