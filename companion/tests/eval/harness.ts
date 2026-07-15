// Eval harness (issue #64, Phase 1) — drives the REAL pipeline extraction/synthesis entry points and hands
// the output to the pure scorer. Phase 1 uses a MockProvider so a fixture's canned model response makes the
// run deterministic: what gets gated is the pipeline plumbing + the scoring math, at zero token cost, in
// normal CI. Phase 2 swaps `makeEvalPipeline`'s MockProvider for the env-configured `buildProvider()` and
// points the same runners at real screenshots — the scorer and fixtures are unchanged.

import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { buildRuntimePipeline } from "../../src/server.js";
import { MockProvider } from "../../src/providers/provider.js";
import { emptyState, type ForensicEvent, type InvestigationState } from "../../src/analysis/stateTypes.js";
import type { ProducedEvent, ProducedFinding } from "./scorer.js";

const IMPORTED_AT = "2026-06-01T00:00:00Z"; // fixed clock input — keeps runs reproducible

export interface EvalPipeline {
  pipeline: ReturnType<typeof buildRuntimePipeline>;
  stateStore: StateStore;
  caseId: string;
}

// Build a fresh, isolated pipeline backed by a temp case and a MockProvider that always returns `canned`.
export async function makeEvalPipeline(canned: string, caseId = "eval"): Promise<EvalPipeline> {
  const root = await mkdtemp(join(tmpdir(), "dfir-eval-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  await store.createCase({ caseId, name: "eval", investigator: "eval", aiProvider: "mock" });
  const provider = new MockProvider("mock", canned);
  const pipeline = buildRuntimePipeline({
    provider, synthesisProvider: provider, stateStore, store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  return { pipeline, stateStore, caseId };
}

// Map an InvestigationState's forensic timeline to the scorer's ProducedEvent shape.
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

// Run CSV extraction against the canned response and return the produced events.
export async function runCsvExtraction(canned: string, csvText: string): Promise<ProducedEvent[]> {
  const { pipeline, caseId } = await makeEvalPipeline(canned);
  const state = await pipeline.analyzeCsv(caseId, csvText, { label: "eval.csv", idPrefix: "m1", importedAt: IMPORTED_AT });
  return producedEvents(state);
}

// Run generic-log extraction against the canned response and return the produced events.
export async function runLogExtraction(canned: string, logText: string): Promise<ProducedEvent[]> {
  const { pipeline, caseId } = await makeEvalPipeline(canned);
  const state = await pipeline.analyzeLog(caseId, logText, { label: "eval.log", idPrefix: "l1", importedAt: IMPORTED_AT });
  return producedEvents(state);
}

// Seed a pre-canned timeline, run synthesize against the canned response, and return the final
// (events, findings) for checkSynthesis — exercising the full synthesis pass incl. the deterministic
// grounding/backfill guarantees the eval verifies.
export async function runSynthesis(canned: string, seedEvents: ForensicEvent[]): Promise<{ events: ProducedEvent[]; findings: ProducedFinding[] }> {
  const { pipeline, stateStore, caseId } = await makeEvalPipeline(canned);
  const seeded = emptyState(caseId);
  seeded.forensicTimeline.push(...seedEvents);
  await stateStore.save(seeded);
  const state = await pipeline.synthesize(caseId, { force: true });
  return { events: producedEvents(state), findings: producedFindings(state) };
}
