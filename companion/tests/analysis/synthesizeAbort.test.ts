import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SynthMetaStore } from "../../src/analysis/synthMeta.js";
import type { AnalyzeRequest, AnalyzeResult } from "../../src/providers/provider.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";

/**
 * A SUPERSEDED SYNTHESIS MUST STOP, NOT FINISH.
 *
 * `exclusive: true` on the synthesis job means the newest "the case changed, re-derive it" kick
 * subsumes every older one: JobManager.dropForExclusiveRegistration aborts the old job's signal,
 * removes its row, and frees the case's single concurrency slot so the new run can start.
 *
 * That only works if the old run actually stops. It did not. `synthesize` handed `signal` to the
 * model call and never looked at it again, so a run whose provider does not abort mid-call — the
 * claude-code provider completed a 6-minute call after its signal was aborted — went on to fold the
 * delta, PERSIST it over the newer run's work, record an analysis run, and start the second-look
 * sweep, which is itself another full synthesis. Two top-level runs then held the whole case state
 * at once: state loads went from 0.6 s to 140 s, RSS from 451 MB to 986 MB, and neither run reached
 * its terminal `ai_status` — which is what left the header pill reading "AI: synthesizing…" with no
 * job left to explain it.
 *
 * So the contract is: once the signal is aborted, nothing downstream of the model call runs.
 */

let caseStore: CaseStore;
let stateStore: StateStore;

function event(id: string, timestamp: string, description: string): ForensicEvent {
  return {
    id,
    timestamp,
    description,
    severity: "Medium",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
  };
}

function delta(): string {
  return JSON.stringify({
    findings: [
      {
        id: "f1",
        severity: "High",
        title: "synth finding",
        description: "d",
        relatedIocs: [],
        mitreTechniques: [],
        status: "open",
        relatedEventIds: [],
      },
    ],
    iocs: [],
    mitreTechniques: [],
    attackerPath: "p",
    summary: "s",
    forensicEvents: [],
    threadsOpened: [],
    threadsClosed: [],
    timelineNote: "",
  });
}

/**
 * A provider that IGNORES the abort signal and answers normally — the real failure mode. A provider
 * that rejects on abort would make this test pass without any check in `synthesize`.
 */
function deafProvider(rawText: string, during?: () => void) {
  return {
    name: "deaf",
    model: "deaf-model",
    analyze: async (_req: AnalyzeRequest): Promise<AnalyzeResult> => {
      during?.();
      return { rawText };
    },
  };
}

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-synth-abort-"));
  caseStore = new CaseStore(root);
  await caseStore.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
  stateStore = new StateStore(caseStore);
});

describe("synthesize — a superseded run stops at the next stage boundary", () => {
  it("does not persist the delta when the signal aborts while the model is answering", async () => {
    const seeded = emptyState("c1");
    seeded.forensicTimeline.push(event("e1", "2026-01-04T00:00:00.000Z", "the real lead"));
    await stateStore.save(seeded);
    const synthMetaStore = new SynthMetaStore(caseStore);

    // Superseded mid-call, exactly as dropForExclusiveRegistration does it.
    const controller = new AbortController();
    const pipeline = new AnalysisPipeline({
      provider: deafProvider(delta(), () => controller.abort()),
      stateStore,
      synthMetaStore,
      imageLoader: async () => ({ base64: "A", mimeType: "image/webp" }),
    });

    await expect(pipeline.synthesize("c1", { signal: controller.signal })).rejects.toThrow();

    // The newer run owns the case now; this one must have written nothing.
    const after = await stateStore.load("c1");
    expect(after.findings).toHaveLength(0);
    expect(after.lastSummary).not.toBe("s");
    expect((await synthMetaStore.load("c1")).lastSynthesizedAt).toBe(""); // the store's "never ran"
  });

  it("does not call the model at all when the signal is already aborted", async () => {
    const seeded = emptyState("c1");
    seeded.forensicTimeline.push(event("e1", "2026-01-04T00:00:00.000Z", "the real lead"));
    await stateStore.save(seeded);

    let calls = 0;
    const controller = new AbortController();
    controller.abort();
    const pipeline = new AnalysisPipeline({
      provider: {
        name: "deaf",
        model: "deaf-model",
        analyze: async (): Promise<AnalyzeResult> => {
          calls += 1;
          return { rawText: delta() };
        },
      },
      stateStore,
      imageLoader: async () => ({ base64: "A", mimeType: "image/webp" }),
    });

    await expect(pipeline.synthesize("c1", { signal: controller.signal })).rejects.toThrow();
    expect(calls).toBe(0); // a superseded run must not spend a prompt either
  });
});
