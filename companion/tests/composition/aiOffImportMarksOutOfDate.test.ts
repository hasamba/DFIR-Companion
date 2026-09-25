// #1599: an import that lands while the case's AI is off starts no synthesis — by design. The case
// must still say its conclusions are out of date, not "up to date — live analysis paused" over
// evidence the model never saw.
import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { SynthMetaStore } from "../../src/analysis/synthMeta.js";
import { createCaptureAnalysis } from "../../src/composition/captureAnalysis.js";
import type { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { pollFor } from "../helpers/poll.js";

async function harness(enabled: boolean) {
  const root = await mkdtemp(join(tmpdir(), "dfir-aioff-mark-"));
  const store = new CaseStore(root);
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const synthMetaStore = new SynthMetaStore(store);
  const synthesized: string[] = [];
  const pipeline = {
    hasSynthesisProvider: () => true,
    synthesize: async (caseId: string) => {
      synthesized.push(caseId);
      return {};
    },
  } as unknown as AnalysisPipeline;
  const analysis = createCaptureAnalysis({
    store,
    options: { pipeline, synthMetaStore },
    hasAiProvider: () => true,
    getControl: async () => ({ enabled, lastAnalyzedSeq: 0 }),
    setControl: async () => ({ enabled, lastAnalyzedSeq: 0 }),
    recordAiError: () => {},
    autoEnrichIfEnabled: () => {},
    dispatchNotify: () => {},
  });
  return { analysis, synthMetaStore, synthesized };
}

describe("an import completing with AI off (#1599)", () => {
  it("starts no synthesis and marks the conclusions out of date", async () => {
    const h = await harness(false);
    h.analysis.resynthesizeInBackground("c1");
    await pollFor(
      "the out-of-date marker",
      async () => (await h.synthMetaStore.load("c1")).outOfDate ?? null,
    );
    expect((await h.synthMetaStore.load("c1")).outOfDate?.reason).toBe("new evidence while AI was off");
    expect(h.synthesized).toEqual([]);
  });

  it("with AI on it runs the synthesis and marks nothing", async () => {
    const h = await harness(true);
    h.analysis.resynthesizeInBackground("c1");
    await pollFor("the synthesis run", async () => (h.synthesized.length > 0 ? true : null));
    expect((await h.synthMetaStore.load("c1")).outOfDate ?? null).toBeNull();
  });
});
