import { performance } from "node:perf_hooks";
import { config as loadDotenv } from "dotenv";
import { visionEnv } from "../../src/config/aiEnv.js";
import { ProviderError, type AIProvider } from "../../src/providers/provider.js";
import { buildProvider } from "../../src/server.js";
import { writeEvaluationReport, writeNoRegressionAttestation } from "./artifacts.js";
import { compareWithBaseline, createBaseline, readBaseline, writeBaseline } from "./baseline.js";
import { parseEvalCli, type EvalCliOptions } from "./cli.js";
import { loadGoldenCorpus, type GoldenCorpus } from "./corpus.js";
import { runCorpusSuite } from "./corpusRunner.js";
import { EXTRACTION_FIXTURES, SCREENSHOT_FIXTURES } from "./fixtures.js";
import {
  loadRealScreenshotFixtures,
  mockProvider,
  realProviderOrNull,
  runExtractionFixture,
  runRealScreenshotFixture,
  runScreenshotFixture,
} from "./harness.js";
import { evaluationIdentity } from "./identity.js";
import { MeteredProvider } from "./meter.js";
import {
  buildEvaluationReport,
  reportExitCode,
  type EvaluationExtractionResult,
  type EvaluationReport,
  type EvaluationReportInput,
  type EvaluationResources,
} from "./report.js";
import {
  formatExtractionReport,
  passesExtraction,
  REAL_THRESHOLDS,
  scoreExtraction,
  type Thresholds,
} from "./scorer.js";

type ExtractionFixture = (typeof EXTRACTION_FIXTURES)[number];
type ScreenshotFixture = (typeof SCREENSHOT_FIXTURES)[number];
type ProviderFor<T> = (fixture: T) => AIProvider;

function measuredResources(metered: MeteredProvider, started: number): EvaluationResources {
  return { ...metered.snapshot(), durationMs: performance.now() - started };
}

function failureStatus(error: unknown, real: boolean) {
  if (error instanceof ProviderError) {
    return { status: "provider_failed" as const, errorKind: error.kind };
  }
  return real
    ? { status: "quality_failed" as const, errorKind: "invalid-model-output" }
    : { status: "runner_failed" as const, errorKind: "deterministic-runner-error" };
}

async function runExtractionCase(
  fixture: ExtractionFixture,
  provider: AIProvider,
  thresholds: Thresholds | undefined,
  real: boolean,
): Promise<EvaluationExtractionResult> {
  const metered = new MeteredProvider(provider);
  const started = performance.now();
  try {
    const produced = await runExtractionFixture(fixture, metered);
    const score = scoreExtraction(fixture.golden, produced, { toleranceMinutes: 5 });
    const gate = fixture.thresholds ?? thresholds;
    console.log(formatExtractionReport(fixture.name, score, gate));
    return {
      id: fixture.name,
      modality: fixture.modality,
      status: passesExtraction(score, gate) ? "passed" : "quality_failed",
      precision: score.precision,
      recall: score.recall,
      resources: measuredResources(metered, started),
    };
  } catch (error) {
    const failure = failureStatus(error, real);
    console.log(`[FAIL] extraction: ${fixture.name} — ${failure.errorKind}`);
    console.log(`  ${error instanceof Error ? error.message : String(error)}`);
    return {
      id: fixture.name,
      modality: fixture.modality,
      status: failure.status,
      precision: 0,
      recall: 0,
      resources: measuredResources(metered, started),
      errorKind: failure.errorKind,
    };
  }
}

async function runExtraction(
  providerFor: ProviderFor<ExtractionFixture>,
  thresholds: Thresholds | undefined,
  real: boolean,
): Promise<EvaluationExtractionResult[]> {
  const results: EvaluationExtractionResult[] = [];
  for (const fixture of EXTRACTION_FIXTURES) {
    results.push(await runExtractionCase(fixture, providerFor(fixture), thresholds, real));
  }
  return results;
}

async function runMockScreenshotCase(fixture: ScreenshotFixture): Promise<EvaluationExtractionResult> {
  const metered = new MeteredProvider(mockProvider(fixture.canned));
  const started = performance.now();
  try {
    const produced = await runScreenshotFixture(fixture, metered);
    const score = scoreExtraction(fixture.golden, produced, { toleranceMinutes: 5 });
    console.log(formatExtractionReport(`${fixture.name} (screenshot)`, score, fixture.thresholds));
    return {
      id: fixture.name,
      modality: "screenshot",
      status: passesExtraction(score, fixture.thresholds) ? "passed" : "quality_failed",
      precision: score.precision,
      recall: score.recall,
      resources: measuredResources(metered, started),
    };
  } catch (error) {
    const failure = failureStatus(error, false);
    return {
      id: fixture.name,
      modality: "screenshot",
      status: failure.status,
      precision: 0,
      recall: 0,
      resources: measuredResources(metered, started),
      errorKind: failure.errorKind,
    };
  }
}

async function runMockScreenshots(): Promise<EvaluationExtractionResult[]> {
  const results: EvaluationExtractionResult[] = [];
  for (const fixture of SCREENSHOT_FIXTURES) {
    results.push(await runMockScreenshotCase(fixture));
  }
  return results;
}

async function runRealScreenshots(provider: AIProvider | undefined): Promise<EvaluationExtractionResult[]> {
  const directory = process.env.DFIR_EVAL_SCREENSHOT_DIR;
  if (!directory || !provider) {
    console.log("screenshot fixtures: local directory or vision provider absent — skipped");
    return [];
  }
  const fixtures = await loadRealScreenshotFixtures(directory);
  if (!fixtures.length) {
    console.log(`screenshot fixtures: no valid image/sidecar pairs in ${directory} — skipped`);
    return [];
  }
  const results: EvaluationExtractionResult[] = [];
  for (const fixture of fixtures) {
    const metered = new MeteredProvider(provider);
    const started = performance.now();
    try {
      const produced = await runRealScreenshotFixture(fixture, metered);
      const thresholds = fixture.thresholds ?? REAL_THRESHOLDS;
      const score = scoreExtraction(fixture.golden, produced, { toleranceMinutes: 5 });
      console.log(formatExtractionReport(`${fixture.name} (screenshot)`, score, thresholds));
      results.push({
        id: fixture.name,
        modality: "screenshot",
        status: passesExtraction(score, thresholds) ? "passed" : "quality_failed",
        precision: score.precision,
        recall: score.recall,
        resources: measuredResources(metered, started),
      });
    } catch (error) {
      const failure = failureStatus(error, true);
      console.log(`[FAIL] extraction: ${fixture.name} (screenshot) — ${failure.errorKind}`);
      results.push({
        id: fixture.name,
        modality: "screenshot",
        status: failure.status,
        precision: 0,
        recall: 0,
        resources: measuredResources(metered, started),
        errorKind: failure.errorKind,
      });
    }
  }
  return results;
}

async function applyBaseline(
  input: EvaluationReportInput,
  options: EvalCliOptions,
): Promise<EvaluationReport> {
  if (!options.baselinePath) {
    return buildEvaluationReport({
      ...input,
      ...(options.requireBaseline ? { runnerError: "a baseline is required but none was supplied" } : {}),
    });
  }
  const preliminary = buildEvaluationReport(input);
  const baseline = await readBaseline(options.baselinePath);
  return buildEvaluationReport({
    ...input,
    baselineComparison: compareWithBaseline(baseline, preliminary.summary, preliminary.identity),
  });
}

async function writeRequestedArtifacts(report: EvaluationReport, options: EvalCliOptions): Promise<void> {
  let reportHash: string | undefined;
  if (options.outputPath) {
    reportHash = await writeEvaluationReport(options.outputPath, report);
    console.log(`evaluation report: ${options.outputPath}`);
  }
  if (options.baselineDirectory && report.outcome === "passed") {
    const path = await writeBaseline(
      options.baselineDirectory,
      createBaseline(report.identity, report.summary, report.createdAt),
    );
    console.log(`candidate baseline: ${path}`);
  }
  if (options.attestationPath) {
    if (!options.outputPath || !reportHash) {
      throw new Error("--attestation requires --output so the report can be hash-pinned");
    }
    await writeNoRegressionAttestation(options.attestationPath, options.outputPath, reportHash, report);
    console.log(`no-regression attestation: ${options.attestationPath}`);
  }
}

async function skippedReport(options: EvalCliOptions, reason: string): Promise<EvaluationReport> {
  const corpus = await loadGoldenCorpus();
  const identity = await evaluationIdentity({ name: "unconfigured", model: "unconfigured" }, corpus.hash);
  return buildEvaluationReport({
    identity,
    corpusVersion: corpus.version,
    cases: [],
    extraction: [],
    screenshot: [],
    createdAt: new Date().toISOString(),
    ...(options.requireProvider ? { providerFailureReason: reason } : { skippedReason: reason }),
  });
}

function requiredProvider(provider: AIProvider | undefined, role: "text" | "vision"): AIProvider {
  if (!provider) throw new Error(`${role} provider was required after configuration validation`);
  return provider;
}

function modeIncludes(options: EvalCliOptions, section: Exclude<EvalCliOptions["mode"], "all">) {
  return options.mode === "all" || options.mode === section;
}

async function runSelectedSections(
  options: EvalCliOptions,
  corpus: GoldenCorpus,
  textProvider: AIProvider | undefined,
  visionProvider: AIProvider | undefined,
) {
  const extraction = modeIncludes(options, "extraction")
    ? await runExtraction(
        options.real
          ? () => requiredProvider(textProvider, "text")
          : (fixture) => mockProvider(fixture.canned),
        options.real ? REAL_THRESHOLDS : undefined,
        options.real,
      )
    : [];
  const screenshot = modeIncludes(options, "screenshots")
    ? options.real
      ? await runRealScreenshots(visionProvider)
      : await runMockScreenshots()
    : [];
  const cases = modeIncludes(options, "synthesis")
    ? await runCorpusSuite(
        corpus,
        options.real
          ? () => requiredProvider(textProvider, "text")
          : (fixture) => mockProvider(fixture.canned),
        options.real,
      )
    : [];
  return { extraction, screenshot, cases };
}

async function execute(options: EvalCliOptions): Promise<EvaluationReport> {
  if (options.real) loadDotenv({ quiet: true });
  const corpus = await loadGoldenCorpus();
  const textProvider = options.real ? realProviderOrNull() : undefined;
  const visionProvider = options.real ? buildProvider() : undefined;
  const needsText = options.mode !== "screenshots";
  if (options.real && needsText && !textProvider) {
    return skippedReport(options, "no text AI provider is configured");
  }
  if (options.real && options.mode === "screenshots" && !visionProvider) {
    return skippedReport(options, "no vision AI provider is configured");
  }
  const identityProvider = options.real
    ? requiredProvider(
        options.mode === "screenshots" ? visionProvider : textProvider,
        options.mode === "screenshots" ? "vision" : "text",
      )
    : { name: "mock", model: "mock-model" };
  const { extraction, screenshot, cases } = await runSelectedSections(
    options,
    corpus,
    textProvider,
    visionProvider,
  );
  const identity = await evaluationIdentity(identityProvider, corpus.hash);
  return applyBaseline(
    {
      identity,
      corpusVersion: corpus.version,
      cases,
      extraction,
      screenshot,
      createdAt: new Date().toISOString(),
      ...(options.mode === "screenshots" && options.real && screenshot.length === 0
        ? { skippedReason: "real screenshot set is not configured" }
        : {}),
    },
    options,
  );
}

async function main(): Promise<void> {
  const options = parseEvalCli(process.argv.slice(2));
  const report = await execute(options);
  await writeRequestedArtifacts(report, options);
  const model = options.real
    ? (process.env.DFIR_AI_SYNTH_MODEL ?? visionEnv(process.env, "MODEL") ?? "(default)")
    : "mock-model";
  console.log(`\nevaluation outcome: ${report.outcome} (model ${model})`);
  process.exitCode = reportExitCode(report.outcome);
}

void main().catch((error: unknown) => {
  console.error(`evaluation runner error: ${(error as Error).message}`);
  process.exitCode = 2;
});
