import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SynthMetaStore } from "../../src/analysis/synthMeta.js";
import { SecondOpinionStore } from "../../src/analysis/secondOpinionStore.js";
import { MockProvider } from "../../src/providers/provider.js";
import type { AIProvider, AnalyzeRequest, AnalyzeResult } from "../../src/providers/provider.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";

// Per-model performance telemetry (issue #74): synthesize() and secondOpinion() should stamp
// model-quality signals onto synth-meta — the model used, findings vs the deterministic
// high-severity backfill, parse retries, and (for secondOpinion) the cross-model agreement rate —
// so DFIR_AI_MODEL / DFIR_AI_SYNTH_MODEL / DFIR_AI_SECOND_OPINION_MODEL can be compared empirically.

function event(id: string, timestamp: string, severity: ForensicEvent["severity"] = "Info", description = "benign"): ForensicEvent {
  return { id, timestamp, description, severity, mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [] };
}

// A minimal, valid synthesis delta covering ONE event (e2) with ONE finding — e1 (seeded as
// Critical, elsewhere) is deliberately left uncovered so the deterministic high-severity safety
// net has to backfill it.
const DELTA = JSON.stringify({
  findings: [{ id: "f1", severity: "Medium", title: "Suspicious login", description: "d", relatedIocs: [], mitreTechniques: [], status: "open", relatedEventIds: ["e2"] }],
  iocs: [], mitreTechniques: [], threadsOpened: [], threadsClosed: [], timelineNote: "", summary: "s", forensicEvents: [],
});

// Fails (invalid JSON) for the first `failCount` calls, then returns `goodText`. Lets a test assert
// synth-meta's parseRetries without withRetry's real backoff slowing the suite (backoffMs is set to
// ~0 in makePipeline below).
class FlakyProvider implements AIProvider {
  readonly name = "flaky";
  readonly model = "flaky-model";
  private calls = 0;
  constructor(private readonly failCount: number, private readonly goodText: string) {}
  async analyze(_req: AnalyzeRequest): Promise<AnalyzeResult> {
    this.calls++;
    return { rawText: this.calls <= this.failCount ? "not valid json" : this.goodText };
  }
}

async function makeCase() {
  const root = await mkdtemp(join(tmpdir(), "dfir-modelperf-"));
  const caseStore = new CaseStore(root);
  await caseStore.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
  const stateStore = new StateStore(caseStore);
  const synthMetaStore = new SynthMetaStore(caseStore);
  const seeded = emptyState("c1");
  seeded.forensicTimeline.push(event("e1", "2026-05-20T09:00:00.000Z", "Critical", "ransomware note dropped"));
  seeded.forensicTimeline.push(event("e2", "2026-05-20T09:05:00.000Z", "Info", "logon"));
  await stateStore.save(seeded);
  return { caseStore, stateStore, synthMetaStore };
}

// No Critical/High event here (unlike makeCase()) — the second-opinion test cares only about the
// agreement/delta arithmetic, and a shared deterministic backfill finding would itself count as an
// (uninteresting) agreement between A and B, muddying the expected counts below.
async function makeSecondOpinionCase() {
  const root = await mkdtemp(join(tmpdir(), "dfir-modelperf-so-"));
  const caseStore = new CaseStore(root);
  await caseStore.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
  const stateStore = new StateStore(caseStore);
  const synthMetaStore = new SynthMetaStore(caseStore);
  const seeded = emptyState("c1");
  seeded.forensicTimeline.push(event("e2", "2026-05-20T09:05:00.000Z", "Info", "logon"));
  await stateStore.save(seeded);
  return { caseStore, stateStore, synthMetaStore };
}

describe("per-model performance telemetry (#74)", () => {
  it("records the synthesis model, findings count, and high-severity backfill count", async () => {
    const { stateStore, synthMetaStore } = await makeCase();
    const provider = new MockProvider("mock", DELTA, "sonnet-5");
    const pipeline = new AnalysisPipeline({
      provider, synthesisProvider: provider, stateStore, synthMetaStore,
      imageLoader: async () => ({ base64: "A", mimeType: "image/webp" }),
    });

    await pipeline.synthesize("c1");

    const meta = await synthMetaStore.load("c1");
    expect(meta.synthModel).toBe("mock/sonnet-5");
    expect(meta.findingsCount).toBe(2);              // f1 (model) + the backfilled e1 finding
    expect(meta.highSeverityBackfillCount).toBe(1);   // e1 (Critical, uncited) recovered by the safety net
    expect(meta.parseRetries).toBe(0);
  });

  it("prefers the configured synthesisModelLabel over the provider's raw name/model", async () => {
    const { stateStore, synthMetaStore } = await makeCase();
    const provider = new MockProvider("mock", DELTA, "sonnet-5");
    const pipeline = new AnalysisPipeline({
      provider, synthesisProvider: provider, stateStore, synthMetaStore,
      synthesisModelLabel: "Primary (Claude Sonnet 5)",
      imageLoader: async () => ({ base64: "A", mimeType: "image/webp" }),
    });

    await pipeline.synthesize("c1");

    expect((await synthMetaStore.load("c1")).synthModel).toBe("Primary (Claude Sonnet 5)");
  });

  it("counts parse retries the synthesis call needed", async () => {
    const { stateStore, synthMetaStore } = await makeCase();
    const provider = new FlakyProvider(2, DELTA); // fails twice, succeeds on the 3rd (default retries=3)
    const pipeline = new AnalysisPipeline({
      provider, synthesisProvider: provider, stateStore, synthMetaStore, backoffMs: 1,
      imageLoader: async () => ({ base64: "A", mimeType: "image/webp" }),
    });

    await pipeline.synthesize("c1");

    expect((await synthMetaStore.load("c1")).parseRetries).toBe(2);
  });

  it("records a second-opinion agreement snapshot without disturbing the synth-model fields", async () => {
    const { caseStore, stateStore, synthMetaStore } = await makeSecondOpinionCase();
    const secondOpinionStore = new SecondOpinionStore(caseStore);
    const primary = new MockProvider("primary", DELTA, "sonnet-5");
    // Second opinion (dry-run) delta: same shared finding as f1 PLUS one B raises that A doesn't —
    // one delta (b_only), so agreementRate = 1 / (1 + 1) = 0.5.
    const secondOpinionDelta = JSON.stringify({
      findings: [
        { id: "f1", severity: "Medium", title: "Suspicious login", description: "d", relatedIocs: [], mitreTechniques: [], status: "open", relatedEventIds: ["e2"] },
        { id: "g2", severity: "High", title: "B only finding", description: "d2", relatedIocs: [], mitreTechniques: [], status: "open", relatedEventIds: [] },
      ],
      iocs: [], mitreTechniques: [], threadsOpened: [], threadsClosed: [], timelineNote: "", summary: "s2", forensicEvents: [],
    });
    const secondOpinionProvider = new MockProvider("second", secondOpinionDelta, "gpt-5");
    const pipeline = new AnalysisPipeline({
      provider: primary, synthesisProvider: primary, stateStore, synthMetaStore,
      secondOpinionProvider, secondOpinionStore,
      synthesisModelLabel: "primary/sonnet-5", secondOpinionModelLabel: "second/gpt-5",
      imageLoader: async () => ({ base64: "A", mimeType: "image/webp" }),
    });

    await pipeline.secondOpinion("c1");

    const meta = await synthMetaStore.load("c1");
    expect(meta.secondOpinionPerf).toEqual({
      modelA: "primary/sonnet-5",
      modelB: "second/gpt-5",
      agreementCount: 1,
      deltaCount: 1,
      agreementRate: 0.5,
      at: expect.any(String),
    });
    // secondOpinion()'s Pass-0 re-synthesis still stamped the ordinary synth-model fields.
    expect(meta.synthModel).toBe("primary/sonnet-5");
  });
});
