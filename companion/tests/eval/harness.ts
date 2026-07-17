// Eval harness (issue #64) — drives the REAL pipeline extraction/synthesis entry points and hands the
// output to the pure scorer. The harness is provider-parameterized:
//   - Phase 1 (deterministic, CI-gating): pass a MockProvider built from a fixture's canned response, so
//     what's gated is the pipeline plumbing + scoring math, at zero token cost.
//   - Phase 2 (real, non-blocking): pass the env-configured provider (`realProviderOrNull()`) to score the
//     CURRENT prompt's actual output against the golden expectations. Same runners, same scorer, same fixtures.

import { mkdtemp, readdir, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, extname, join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { buildRuntimePipeline, buildProvider, buildSynthesisProvider } from "../../src/server.js";
import { MockProvider, type AIProvider, type AnalyzeImage } from "../../src/providers/provider.js";
import { emptyState, type InvestigationState } from "../../src/analysis/stateTypes.js";
import type { CaptureMetadata } from "../../src/types.js";
import type { GoldenEvent, ProducedEvent, ProducedFinding, Thresholds } from "./scorer.js";
import type { ExtractionFixture, ScreenshotFixture, SynthesisFixture } from "./fixtures.js";

const IMPORTED_AT = "2026-06-01T00:00:00Z"; // fixed clock input — keeps runs reproducible

export interface EvalPipeline {
  pipeline: ReturnType<typeof buildRuntimePipeline>;
  stateStore: StateStore;
  caseId: string;
}

// Convenience: a MockProvider that always returns `canned` (Phase-1 deterministic runs).
export function mockProvider(canned: string): MockProvider {
  return new MockProvider("mock", canned);
}

// The env-configured real provider (Phase-2 runs), or undefined when none is configured — callers skip
// gracefully so a missing key never fails CI. dotenv is loaded by the runner.
//
// Deliberately the TEXT model (`buildSynthesisProvider()`, i.e. DFIR_AI_SYNTH_MODEL falling back to
// the vision model DFIR_VISION_MODEL), not `buildProvider()`: every path these fixtures exercise — analyzeCsv, analyzeLog,
// synthesize — runs on the text model in production. Grading the vision model here would score a model
// production never uses for this work.
export function realProviderOrNull(): AIProvider | undefined {
  return buildSynthesisProvider() ?? buildProvider();
}

const stubImageLoader = async (): Promise<AnalyzeImage> => ({ base64: "AAAA", mimeType: "image/webp" });

// Build a fresh, isolated pipeline backed by a temp case, driven by the given provider. `imageLoader`
// defaults to a stub (placeholder bytes, no real image ever decoded) for the mock/text fixtures; real
// screenshot grading (below) passes one that reads actual image bytes off disk.
export async function makeEvalPipeline(
  provider: AIProvider,
  caseId = "eval",
  imageLoader: (caseId: string, screenshotFile: string) => Promise<AnalyzeImage> = stubImageLoader,
): Promise<EvalPipeline> {
  const root = await mkdtemp(join(tmpdir(), "dfir-eval-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  await store.createCase({ caseId, name: "eval", investigator: "eval", aiProvider: provider.name });
  const pipeline = buildRuntimePipeline({
    provider, synthesisProvider: provider, stateStore, store,
    imageLoader,
  });
  return { pipeline, stateStore, caseId };
}

export function producedEvents(state: InvestigationState): ProducedEvent[] {
  return state.forensicTimeline.map((e) => ({
    id: e.id, timestamp: e.timestamp, description: e.description, severity: e.severity,
    mitreTechniques: e.mitreTechniques, asset: e.asset, relatedFindingIds: e.relatedFindingIds,
  }));
}

export function producedFindings(state: InvestigationState): ProducedFinding[] {
  return state.findings.map((f) => ({
    id: f.id, severity: f.severity, confidence: f.confidence, confidenceReason: f.confidenceReason,
    relatedEventIds: f.relatedEventIds, relatedIocs: f.relatedIocs,
  }));
}

// Run one extraction fixture (CSV or generic-log) through the pipeline with `provider` and return the
// produced events. In mock mode `provider` returns the fixture's canned delta; in real mode it's the model.
export async function runExtractionFixture(fx: ExtractionFixture, provider: AIProvider): Promise<ProducedEvent[]> {
  const { pipeline, caseId } = await makeEvalPipeline(provider);
  const state = fx.modality === "csv"
    ? await pipeline.analyzeCsv(caseId, fx.input, { label: `${fx.name}.csv`, idPrefix: "m1", importedAt: IMPORTED_AT })
    : await pipeline.analyzeLog(caseId, fx.input, { label: `${fx.name}.log`, idPrefix: "l1", importedAt: IMPORTED_AT });
  return producedEvents(state);
}

// Run one screenshot fixture through the VISION path (`analyzeWindow`) and return the produced events.
// MOCK-ONLY in practice: the provider returns the fixture's canned delta and makeEvalPipeline's stub
// imageLoader supplies placeholder bytes, so no real screenshot is decoded or shipped. This exercises the
// analyzeWindow plumbing + scorer — the one modality the CSV/log runners can't reach.
export async function runScreenshotFixture(fx: ScreenshotFixture, provider: AIProvider): Promise<ProducedEvent[]> {
  const { pipeline, caseId } = await makeEvalPipeline(provider);
  const captures = fx.captures.map((c) => ({ ...c, caseId })); // bind synthetic captures to the temp case
  const state = await pipeline.analyzeWindow(caseId, captures);
  return producedEvents(state);
}

// --- Real vision-model grading (issue #135) ---------------------------------------------------------
//
// SCREENSHOT_FIXTURES above is mock-only by design (no real screenshot may be committed). This section
// drives analyzeWindow against ACTUAL screenshots + the REAL vision provider, sourced entirely from a
// local, uncommitted directory pointed to by DFIR_EVAL_SCREENSHOT_DIR — never from the repo.

export interface RealScreenshotFixture {
  name: string;             // derived from the image's basename
  imagePath: string;        // absolute path to the screenshot file
  mimeType: string;
  tabTitle: string;
  url: string;
  timestamp?: string;       // capture time; defaults to IMPORTED_AT if the sidecar omits it
  golden: GoldenEvent[];
  thresholds?: Thresholds;
}

const IMAGE_MIME_BY_EXT: Record<string, string> = {
  ".webp": "image/webp", ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
};

interface ScreenshotSidecar {
  tabTitle?: string;
  url?: string;
  timestamp?: string;
  golden: GoldenEvent[];
  thresholds?: Thresholds;
}

// Load real screenshot fixtures from a local directory: each image (.png/.jpg/.jpeg/.webp) is paired
// with a same-basename `.json` sidecar holding `{ tabTitle?, url?, timestamp?, golden, thresholds? }`.
// An image without a valid sidecar is skipped with a warning, not a hard failure — a local set can be
// built up incrementally. A missing/unset directory returns [] rather than throwing, so callers can
// treat "nothing configured" and "nothing found" the same way: a clean skip.
export async function loadRealScreenshotFixtures(dir: string): Promise<RealScreenshotFixture[]> {
  let entries: string[];
  try {
    entries = await readdir(dir);
  } catch {
    return [];
  }
  const fixtures: RealScreenshotFixture[] = [];
  for (const entry of entries.sort()) {
    const ext = extname(entry).toLowerCase();
    const mimeType = IMAGE_MIME_BY_EXT[ext];
    if (!mimeType) continue;
    const base = entry.slice(0, -ext.length);
    const sidecarPath = join(dir, `${base}.json`);
    let sidecar: ScreenshotSidecar;
    try {
      sidecar = JSON.parse(await readFile(sidecarPath, "utf8"));
    } catch {
      console.warn(`eval --real: ${entry} has no valid ${base}.json sidecar — skipped`);
      continue;
    }
    fixtures.push({
      name: base,
      imagePath: join(dir, entry),
      mimeType,
      tabTitle: sidecar.tabTitle ?? base,
      url: sidecar.url ?? "https://eval.local/",
      timestamp: sidecar.timestamp,
      golden: sidecar.golden ?? [],
      thresholds: sidecar.thresholds,
    });
  }
  return fixtures;
}

// Run one real screenshot fixture through analyzeWindow: reads the actual image bytes off disk and
// hands them to `provider` (the real, vision-scoped provider — see realProviderOrNull's note on why
// the TEXT provider used by the other --real fixtures is the wrong model for this modality).
export async function runRealScreenshotFixture(fx: RealScreenshotFixture, provider: AIProvider): Promise<ProducedEvent[]> {
  const bytes = await readFile(fx.imagePath);
  const image: AnalyzeImage = { base64: bytes.toString("base64"), mimeType: fx.mimeType };
  const { pipeline, caseId } = await makeEvalPipeline(provider, "eval", async () => image);
  const capture: CaptureMetadata = {
    caseId,
    sequenceNumber: 1,
    timestamp: fx.timestamp ?? IMPORTED_AT,
    url: fx.url,
    tabTitle: fx.tabTitle,
    triggerType: "timer",
    contentHash: `real-${fx.name}`,
    isDuplicate: false,
    screenshotFile: basename(fx.imagePath),
  };
  const state = await pipeline.analyzeWindow(caseId, [capture]);
  return producedEvents(state);
}

// Run one synthesis fixture: seed its pre-canned timeline, synthesize with `provider`, and return the final
// (events, findings) — exercising the full synthesis pass incl. the deterministic grounding/backfill
// guarantees the eval verifies.
export async function runSynthesisFixture(fx: SynthesisFixture, provider: AIProvider): Promise<{ events: ProducedEvent[]; findings: ProducedFinding[] }> {
  const { pipeline, stateStore, caseId } = await makeEvalPipeline(provider);
  const seeded = emptyState(caseId);
  seeded.forensicTimeline.push(...fx.seedEvents);
  await stateStore.save(seeded);
  const state = await pipeline.synthesize(caseId, { force: true });
  return { events: producedEvents(state), findings: producedFindings(state) };
}
