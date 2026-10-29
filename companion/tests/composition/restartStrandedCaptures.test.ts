// #2249: captures waiting in the in-memory buffer were lost on every restart. Nothing seeded the
// buffer at startup and the sweep only drains the buffer, so a sub-window tail was never analyzed.
// The first sweep after start now re-derives what each AI-on case still owes from captures.jsonl,
// through the same path #2248's recovery uses, and respects its hold and attempt cap.
import { describe, it, expect } from "vitest";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createCaptureAnalysis } from "../../src/composition/captureAnalysis.js";
import type { AppOptions } from "../../src/composition/appOptions.js";
import type { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import type { AiControl } from "../../src/analysis/aiControl.js";
import type { CaptureMetadata } from "../../src/types.js";

interface Setup {
  control?: Partial<AiControl>;
  hasAiProvider?: boolean;
  backoffMs?: number;
}

async function harness(caseIds: string[], setup: Setup = {}) {
  const root = await mkdtemp(join(tmpdir(), "dfir-restart-stranded-"));
  const store = new CaseStore(root);
  const controls = new Map<string, AiControl>();
  for (const caseId of caseIds) {
    await store.createCase({ caseId, name: "n", investigator: "i", aiProvider: null });
    controls.set(caseId, { enabled: true, lastAnalyzedSeq: 0, ...setup.control });
  }
  const calls: { caseId: string; seqs: number[] }[] = [];
  const pipeline = {
    analyzeWindow: async (caseId: string, win: CaptureMetadata[]) => {
      calls.push({ caseId, seqs: win.map((c) => c.sequenceNumber) });
    },
    hasSynthesisProvider: () => false,
  } as unknown as AnalysisPipeline;
  const options = {
    pipeline,
    flushIntervalMs: 0,
    windowSize: 2,
    captureRecovery: { backoffMs: setup.backoffMs ?? 0 },
  } as unknown as AppOptions;
  const analysis = createCaptureAnalysis({
    store,
    options,
    hasAiProvider: () => setup.hasAiProvider ?? true,
    getControl: async (c) => controls.get(c)!,
    setControl: async (c, patch) => {
      const next = { ...controls.get(c)!, ...patch };
      controls.set(c, next);
      return next;
    },
    recordAiError: () => {},
    autoEnrichIfEnabled: () => {},
    dispatchNotify: () => {},
  });
  const logCaptures = async (caseId: string, ...seqs: number[]) => {
    const logPath = store.capturesLogPath(caseId);
    await mkdir(dirname(logPath), { recursive: true });
    const lines = seqs.map((s) => JSON.stringify({ sequenceNumber: s, isDuplicate: false }));
    await writeFile(logPath, lines.join("\n") + "\n");
  };
  return { analysis, calls, controls, logCaptures };
}

describe("captures stranded by a restart are analyzed (#2249)", () => {
  it("analyzes the logged-but-never-flushed tail in windowSize slices", async () => {
    const h = await harness(["a"]);
    await h.logCaptures("a", 1, 2, 3);
    await h.analysis.resumeAfterRestart();
    expect(h.calls).toEqual([
      { caseId: "a", seqs: [1, 2] },
      { caseId: "a", seqs: [3] },
    ]);
    expect(h.controls.get("a")!.lastAnalyzedSeq).toBe(3);
  });

  it("analyzes nothing for a case with AI off", async () => {
    const h = await harness(["a"], { control: { enabled: false } });
    await h.logCaptures("a", 1, 2);
    await h.analysis.resumeAfterRestart();
    expect(h.calls).toEqual([]);
  });

  it("analyzes nothing when no vision model is configured", async () => {
    const h = await harness(["a"], { hasAiProvider: false });
    await h.logCaptures("a", 1);
    await h.analysis.resumeAfterRestart();
    expect(h.calls).toEqual([]);
  });

  it("does not resend a hold that gave up, but still analyzes the newer tail", async () => {
    const h = await harness(["a"], {
      control: {
        lastAnalyzedSeq: 0,
        analysisHold: { failedSeqs: [1], analyzedThrough: 2, attempts: 3, gaveUp: true },
      },
    });
    await h.logCaptures("a", 1, 2, 3, 4);
    await h.analysis.resumeAfterRestart();
    expect(h.calls).toEqual([{ caseId: "a", seqs: [3, 4] }]);
    expect(h.controls.get("a")!.lastAnalyzedSeq).toBe(0);
    expect(h.controls.get("a")!.analysisHold).toMatchObject({ failedSeqs: [1], gaveUp: true });
  });

  it("recovers a held window that is due, together with the tail", async () => {
    const h = await harness(["a"], {
      control: { analysisHold: { failedSeqs: [1], analyzedThrough: 2, attempts: 0 } },
    });
    await h.logCaptures("a", 1, 2, 3);
    await h.analysis.resumeAfterRestart();
    expect(h.calls).toEqual([{ caseId: "a", seqs: [1, 3] }]);
    expect(h.controls.get("a")!.lastAnalyzedSeq).toBe(3);
    expect(h.controls.get("a")!.analysisHold).toBeUndefined();
  });

  it("covers every AI-on case", async () => {
    const h = await harness(["a", "b"]);
    await h.logCaptures("a", 1);
    await h.logCaptures("b", 5);
    await h.analysis.resumeAfterRestart();
    expect(h.calls).toHaveLength(2);
    expect(h.calls).toEqual(
      expect.arrayContaining([
        { caseId: "a", seqs: [1] },
        { caseId: "b", seqs: [5] },
      ]),
    );
  });
});
