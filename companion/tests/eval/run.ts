import { createHash } from "node:crypto";
import { performance } from "node:perf_hooks";
import { config as loadDotenv } from "dotenv";
import { visionEnv } from "../../src/config/aiEnv.js";
import { ProviderError, type AIProvider } from "../../src/providers/provider.js";
import { buildProvider } from "../../src/server.js";
import { writeEvaluationReport, writeNoRegressionAttestation } from "./artifacts.js";
import { compareWithBaseline, createBaseline, readBaseline, writeBaseline } from "./baseline.js";
import { parseEvalCli, type EvalCliOptions } from "./cli.js";
import { attestationPreflight } from "./preflight.js";
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
  computeDirtyCaseAggregate,
  reportExitCode,
  type EvaluationCaseResult,
  type EvaluationExpectedCounts,
  type EvaluationExtractionResult,
  type EvaluationReport,
  type EvaluationReportInput,
  type EvaluationResources,
} from "./report.js";
import {
  DEFAULT_THRESHOLDS,
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

// The thresholds a row was scored against, copied so the report can re-judge the fixture's mean
// over several runs (#1579). A row that failed before scoring carries no gate: its status decides.
function gateOf(thresholds: Thresholds): { minPrecision: number; minRecall: number } {
  return { minPrecision: thresholds.minPrecision, minRecall: thresholds.minRecall };
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
    const gate = fixture.thresholds ?? thresholds ?? DEFAULT_THRESHOLDS;
    console.log(formatExtractionReport(fixture.name, score, gate));
    return {
      id: fixture.name,
      modality: fixture.modality,
      status: passesExtraction(score, gate) ? "passed" : "quality_failed",
      precision: score.precision,
      recall: score.recall,
      resources: measuredResources(metered, started),
      gate: gateOf(gate),
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
    const gate = fixture.thresholds ?? DEFAULT_THRESHOLDS;
    console.log(formatExtractionReport(`${fixture.name} (screenshot)`, score, gate));
    return {
      id: fixture.name,
      modality: "screenshot",
      status: passesExtraction(score, gate) ? "passed" : "quality_failed",
      precision: score.precision,
      recall: score.recall,
      resources: measuredResources(metered, started),
      gate: gateOf(gate),
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

// Which screenshots, goldens and thresholds were graded (#1579): a baseline measured on one set
// is not comparable with a run on another, however similar the scores look.
async function realScreenshotSetHash(): Promise<string | undefined> {
  const directory = process.env.DFIR_EVAL_SCREENSHOT_DIR;
  if (!directory) return undefined;
  const fixtures = await loadRealScreenshotFixtures(directory);
  const material = fixtures.map((f) => ({
    name: f.name,
    tabTitle: f.tabTitle,
    url: f.url,
    timestamp: f.timestamp,
    golden: f.golden,
    thresholds: f.thresholds,
  }));
  return createHash("sha256").update(JSON.stringify(material)).digest("hex");
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
        gate: gateOf(thresholds),
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
    baselineComparison: compareWithBaseline(baseline, preliminary.summary, preliminary.identity, {
      real: options.real,
      runs: options.runs,
      mode: options.mode,
    }),
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
      createBaseline(report.identity, report.summary, report.createdAt, {
        runs: options.runs,
        mode: options.mode,
      }),
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

type NoRunReason = Pick<EvaluationReportInput, "skippedReason" | "providerFailureReason" | "runnerError">;

// A report for a run that never called a model: no provider is built, and every row list is empty.
async function emptyReport(options: EvalCliOptions, reason: NoRunReason): Promise<EvaluationReport> {
  const corpus = await loadGoldenCorpus();
  const identity = await evaluationIdentity({ name: "unconfigured", model: "unconfigured" }, corpus.hash);
  return buildEvaluationReport({
    identity,
    corpusVersion: corpus.version,
    cases: [],
    extraction: [],
    screenshot: [],
    createdAt: new Date().toISOString(),
    real: options.real,
    runs: options.runs,
    mode: options.mode,
    ...reason,
  });
}

async function skippedReport(options: EvalCliOptions, reason: string): Promise<EvaluationReport> {
  return emptyReport(
    options,
    options.requireProvider ? { providerFailureReason: reason } : { skippedReason: reason },
  );
}

function requiredProvider(provider: AIProvider | undefined, role: "text" | "vision"): AIProvider {
  if (!provider) throw new Error(`${role} provider was required after configuration validation`);
  return provider;
}

function modeIncludes(options: EvalCliOptions, section: Exclude<EvalCliOptions["mode"], "all">) {
  return options.mode === "all" || options.mode === section;
}

interface SectionResults {
  extraction: EvaluationExtractionResult[];
  screenshot: EvaluationExtractionResult[];
  cases: EvaluationCaseResult[];
}

async function runSelectedSections(
  options: EvalCliOptions,
  corpus: GoldenCorpus,
  textProvider: AIProvider | undefined,
  visionProvider: AIProvider | undefined,
): Promise<SectionResults> {
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

// #1579: run 1 keeps each row's id; run k >= 2 suffixes it so ids stay unique across the report.
// Every row carries its 1-based run number.
function tagRun<T extends { id: string }>(rows: readonly T[], runIndex: number): T[] {
  return rows.map((row) => ({
    ...row,
    id: runIndex === 1 ? row.id : `${row.id}#run${runIndex}`,
    runIndex,
  }));
}

interface RepeatedResults extends SectionResults {
  expected: EvaluationExpectedCounts;
}

// Runs the selected sections options.runs times, one after another (never in parallel, so a
// provider rate limit sees the same load as a single run). Expected counts are for ONE run.
async function runRepeated(
  options: EvalCliOptions,
  corpus: GoldenCorpus,
  textProvider: AIProvider | undefined,
  visionProvider: AIProvider | undefined,
): Promise<RepeatedResults> {
  const pooled: SectionResults = { extraction: [], screenshot: [], cases: [] };
  let firstRunScreenshots = 0;
  for (let runIndex = 1; runIndex <= options.runs; runIndex++) {
    if (options.runs > 1) console.log(`\n=== evaluation run ${runIndex} of ${options.runs} ===`);
    const run = await runSelectedSections(options, corpus, textProvider, visionProvider);
    if (runIndex === 1) firstRunScreenshots = run.screenshot.length;
    pooled.extraction.push(...tagRun(run.extraction, runIndex));
    pooled.screenshot.push(...tagRun(run.screenshot, runIndex));
    pooled.cases.push(...tagRun(run.cases, runIndex));
  }
  const expected: EvaluationExpectedCounts = {
    extraction: modeIncludes(options, "extraction") ? EXTRACTION_FIXTURES.length : 0,
    cases: modeIncludes(options, "synthesis") ? corpus.cases.length : 0,
    screenshot: modeIncludes(options, "screenshots") ? firstRunScreenshots : 0,
  };
  return { ...pooled, expected };
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
  const { extraction, screenshot, cases, expected } = await runRepeated(
    options,
    corpus,
    textProvider,
    visionProvider,
  );
  // #1579: pin the vision model too, but only when real screenshots were actually graded with it.
  const vision = options.real && screenshot.length > 0 ? visionProvider : undefined;
  const identity = await evaluationIdentity(
    identityProvider,
    corpus.hash,
    vision,
    vision ? await realScreenshotSetHash() : undefined,
  );
  return applyBaseline(
    {
      identity,
      corpusVersion: corpus.version,
      cases,
      extraction,
      screenshot,
      createdAt: new Date().toISOString(),
      real: options.real, // single source of truth — same flag runCorpusSuite already used (#1224)
      runs: options.runs,
      mode: options.mode,
      expected,
      ...(options.mode === "screenshots" && options.real && screenshot.length === 0
        ? { skippedReason: "real screenshot set is not configured" }
        : {}),
    },
    options,
  );
}

function logDirtyCaseAggregate(report: EvaluationReport): void {
  // #1224: on a real run the outcome no longer requires every case to individually pass, so a
  // wall of per-case [FAIL] lines above a "passed" outcome would read as self-contradictory —
  // print the actual aggregate-vs-floor numbers the outcome was decided on.
  if (report.cases.length === 0) return;
  const aggregate = computeDirtyCaseAggregate(report.cases);
  const pct = (value: number): string => `${(value * 100).toFixed(1)}%`;
  console.log(
    `dirty-case aggregate recall (floor ${pct(REAL_THRESHOLDS.minRecall)}): ` +
      `claims ${pct(aggregate.claimRecall)} / iocs ${pct(aggregate.iocRecall)} / ` +
      `uncertainty ${pct(aggregate.uncertaintyRecall)} / next-steps ${pct(aggregate.nextStepRecall)}`,
  );
}

// #1579: an attestation run with the wrong shape is refused before any provider is built, so no
// model call is paid for. The runner-failed report is still written so CI uploads the reason.
async function refuseAttestation(options: EvalCliOptions, reason: string): Promise<void> {
  const report = await emptyReport(options, { runnerError: reason });
  if (options.outputPath) {
    await writeEvaluationReport(options.outputPath, report);
    console.log(`evaluation report: ${options.outputPath}`);
  }
  console.error(`evaluation runner error: ${reason}`);
  console.log(`\nevaluation outcome: ${report.outcome}`);
  process.exitCode = reportExitCode(report.outcome);
}

async function main(): Promise<void> {
  const options = parseEvalCli(process.argv.slice(2));
  const refusal = attestationPreflight(options);
  if (refusal) return refuseAttestation(options, refusal);
  const report = await execute(options);
  await writeRequestedArtifacts(report, options);
  const model = options.real
    ? (process.env.DFIR_AI_SYNTH_MODEL ?? visionEnv(process.env, "MODEL") ?? "(default)")
    : "mock-model";
  if (options.real) logDirtyCaseAggregate(report);
  console.log(`\nevaluation outcome: ${report.outcome} (model ${model})`);
  process.exitCode = reportExitCode(report.outcome);
}

void main().catch((error: unknown) => {
  console.error(`evaluation runner error: ${(error as Error).message}`);
  process.exitCode = 2;
});
