// CLI runner for the eval harness (issue #64) — CI-friendly summary + exit codes.
//
//   npm run eval:extraction   → runs every extraction fixture, prints precision/recall, exits 1 on any fail
//   npm run eval:synthesis    → runs every synthesis fixture, prints coverage/hallucination, exits 1 on fail
//   npm run eval              → both
//
// Phase 1: fixtures are driven by a MockProvider, so this is deterministic and safe to gate PRs on — it
// verifies the harness + scorer, not model quality. Phase 2 will add a `--real` mode that swaps in the
// env-configured provider (gated on DFIR_AI_KEY) and runs non-blocking against the golden screenshot set.

import { runCsvExtraction, runLogExtraction, runSynthesis } from "./harness.js";
import {
  scoreExtraction, checkSynthesis, passesExtraction, passesSynthesis,
  formatExtractionReport, formatSynthesisReport,
} from "./scorer.js";
import { EXTRACTION_FIXTURES, SYNTHESIS_FIXTURES } from "./fixtures.js";

async function runExtraction(): Promise<boolean> {
  let allPass = true;
  for (const fx of EXTRACTION_FIXTURES) {
    const produced = fx.modality === "csv"
      ? await runCsvExtraction(fx.canned, fx.input)
      : await runLogExtraction(fx.canned, fx.input);
    const score = scoreExtraction(fx.golden, produced, { toleranceMinutes: 5 });
    console.log(formatExtractionReport(fx.name, score, fx.thresholds));
    allPass = allPass && passesExtraction(score, fx.thresholds);
  }
  return allPass;
}

async function runSynthesisEval(): Promise<boolean> {
  let allPass = true;
  for (const fx of SYNTHESIS_FIXTURES) {
    const { events, findings } = await runSynthesis(fx.canned, fx.seedEvents);
    const report = checkSynthesis(events, findings);
    console.log(formatSynthesisReport(fx.name, report));
    allPass = allPass && passesSynthesis(report);
  }
  return allPass;
}

async function main(): Promise<void> {
  const mode = process.argv[2] ?? "all";
  let ok = true;
  if (mode === "extraction" || mode === "all") ok = (await runExtraction()) && ok;
  if (mode === "synthesis" || mode === "all") ok = (await runSynthesisEval()) && ok;
  console.log(ok ? "\nEVAL PASSED" : "\nEVAL FAILED");
  process.exit(ok ? 0 : 1);
}

main().catch((err) => { console.error(err); process.exit(2); });
