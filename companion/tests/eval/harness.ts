// Eval harness (issue #64) — drives the REAL pipeline extraction/synthesis entry points and hands the
// output to the pure scorer. The harness is provider-parameterized:
//   - Phase 1 (deterministic, CI-gating): pass a MockProvider built from a fixture's canned response, so
//     what's gated is the pipeline plumbing + scoring math, at zero token cost.
//   - Phase 2 (real, non-blocking): pass the env-configured provider (`realProviderOrNull()`) to score the
//     CURRENT prompt's actual output against the golden expectations. Same runners, same scorer, same fixtures.

import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { buildRuntimePipeline, buildProvider } from "../../src/server.js";
import { MockProvider, type AIProvider } from "../../src/providers/provider.js";
import { emptyState, type InvestigationState } from "../../src/analysis/stateTypes.js";
import type { ProducedEvent, ProducedFinding } from "./scorer.js";
import type { ExtractionFixture, SynthesisFixture } from "./fixtures.js";

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
// gracefully so a missing key never fails CI. Mirrors scripts/verify-ai.ts. dotenv is loaded by the runner.
export function realProviderOrNull(): AIProvider | undefined {
  return buildProvider();
}

// Build a fresh, isolated pipeline backed by a temp case, driven by the given provider.
export async function makeEvalPipeline(provider: AIProvider, caseId = "eval"): Promise<EvalPipeline> {
  const root = await mkdtemp(join(tmpdir(), "dfir-eval-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  await store.createCase({ caseId, name: "eval", investigator: "eval", aiProvider: provider.name });
  const pipeline = buildRuntimePipeline({
    provider, synthesisProvider: provider, stateStore, store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
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
