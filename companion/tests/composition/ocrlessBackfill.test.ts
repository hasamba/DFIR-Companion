// Turning AI on for an OCR-less install must still synthesize the imported evidence.
//
// `hasAiProvider()` asks about the VISION model; `hasSynthesisProvider()` asks about the TEXT model
// and falls back to the vision one. The file header for captureAnalysis.ts opens by warning that
// these are not interchangeable and that gating synthesis on the first "would break an OCR-less
// install that only sets DFIR_AI_SYNTH_PROVIDER — it imports evidence fine and would then never
// synthesize it."
//
// backfill() did exactly that. Its first guard returned on `!hasAiProvider()` with the message
// "AI on — no AI model configured", which on a text-only install is both false (a synthesis model
// IS configured) and terminal: no synthesis was scheduled, so switching AI on for an import-only
// case did nothing whatsoever.
//
// Note this is the OPPOSITE of the "stuck pill" originally suspected. That one is unreachable:
// hasSynthesisProvider() is `synthesisProvider ?? provider`, so a configured vision model makes
// BOTH true and the guards cannot disagree in that direction. They only disagree text-only.
import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { createCaptureAnalysis } from "../../src/composition/captureAnalysis.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import type { AppOptions } from "../../src/composition/appOptions.js";
import { pollFor } from "../helpers/poll.js";

const EVENT: ForensicEvent = {
  id: "e0",
  timestamp: "2026-04-22T11:41:00Z",
  description: "imported evidence",
  severity: "High",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
  asset: "WIN11",
  sources: ["Sysmon"],
};

interface Seen {
  status: string;
  detail?: string;
}

/** `vision`/`text` mirror which of the two providers the install actually configures. */
async function harness(opts: { vision: boolean; text: boolean }) {
  const root = await mkdtemp(join(tmpdir(), "dfir-ocrless-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(cases);
  const s = emptyState("c1");
  s.forensicTimeline.push(EVENT);
  await stateStore.save(s);

  const modelCalls: string[] = [];
  const stub = (label: string) =>
    ({
      name: label,
      analyze: async () => {
        modelCalls.push(label);
        throw new Error("model reached");
      },
    }) as never;

  const pipeline = new AnalysisPipeline({
    stateStore,
    ...(opts.vision ? { provider: stub("vision") } : {}),
    ...(opts.text ? { synthesisProvider: stub("text") } : {}),
    imageLoader: async () => ({ data: Buffer.from(""), mediaType: "image/png" }) as never,
  });

  const seen: Seen[] = [];
  const options = {
    pipeline,
    stateStore,
    autoSynthesize: true,
    autoSynthesizeDebounceMs: 20,
    onAiStatus: (_c: string, e: Seen) => seen.push(e),
  } as unknown as AppOptions;

  const analysis = createCaptureAnalysis({
    store: cases,
    options,
    // Mirrors server.ts, where this is `aiConfigured` = Boolean(the vision provider).
    hasAiProvider: () => pipeline.hasAiProvider(),
    getControl: async () => ({ enabled: true, lastAnalyzedSeq: 0 }),
    setControl: async () => ({ enabled: true, lastAnalyzedSeq: 0 }),
    recordAiError: () => {},
    autoEnrichIfEnabled: () => {},
    dispatchNotify: () => {},
  });
  return { analysis, seen, modelCalls, pipeline };
}

describe("the two provider guards", () => {
  it("cannot disagree when a vision model is configured", async () => {
    const { pipeline } = await harness({ vision: true, text: false });
    expect(pipeline.hasAiProvider()).toBe(true);
    // Why the originally-suspected stuck pill is unreachable: vision implies text.
    expect(pipeline.hasSynthesisProvider()).toBe(true);
  });
});

describe("AI switched on for an OCR-less install (text model only)", () => {
  it("does not claim that no AI model is configured", async () => {
    const { analysis, seen } = await harness({ vision: false, text: true });
    await analysis.backfill("c1");
    expect(seen.map((e) => e.detail ?? "")).not.toContain("AI on — no AI model configured");
  });

  it("synthesizes the imported evidence instead of going quietly idle", async () => {
    const { analysis, modelCalls } = await harness({ vision: false, text: true });
    await analysis.backfill("c1");
    await pollFor(
      () => `the text model to be reached, saw ${JSON.stringify(modelCalls)}`,
      async () => (modelCalls.includes("text") ? true : undefined),
    );
    expect(modelCalls).toContain("text");
  });
});

describe("AI switched on with no model at all", () => {
  it("still says so, and still ends on a terminal status", async () => {
    const { analysis, seen, modelCalls } = await harness({ vision: false, text: false });
    await analysis.backfill("c1");
    expect(seen).toHaveLength(1);
    expect(seen[0].status).toBe("idle");
    expect(seen[0].detail).toBe("AI on — no AI model configured");
    expect(modelCalls).toEqual([]);
  });
});
