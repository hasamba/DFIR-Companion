// #2250: the AI off→on backfill could lower lastAnalyzedSeq under a live flush, kept sending
// screenshots after the analyst paused AI, and left the dashboard on "analyzing" when getControl
// threw (the route fires it with `void`, so the rejection went unhandled).
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

const CASE_ID = "c2250";

interface Hooks {
  onWindow?: (seqs: number[]) => Promise<void> | void;
  getControlThrows?: boolean;
}

async function harness(hooks: Hooks = {}) {
  const root = await mkdtemp(join(tmpdir(), "dfir-backfill-safety-"));
  const store = new CaseStore(root);
  await store.createCase({ caseId: CASE_ID, name: "n", investigator: "i", aiProvider: null });
  const calls: number[][] = [];
  const pipeline = {
    analyzeWindow: async (_c: string, win: CaptureMetadata[]) => {
      const seqs = win.map((c) => c.sequenceNumber);
      calls.push(seqs);
      await hooks.onWindow?.(seqs);
    },
    hasSynthesisProvider: () => false,
  } as unknown as AnalysisPipeline;
  const statuses: { status: string; detail?: string }[] = [];
  const options = {
    pipeline,
    flushIntervalMs: 0,
    windowSize: 2,
    captureRecovery: { backoffMs: 0 },
    onAiStatus: (_c: string, s: { status: string; detail?: string }) => statuses.push(s),
  } as unknown as AppOptions;
  let control = { enabled: true, lastAnalyzedSeq: 0 } as AiControl;
  const watermarks: number[] = [];
  const aiErrors: string[] = [];
  const analysis = createCaptureAnalysis({
    store,
    options,
    hasAiProvider: () => true,
    getControl: async () => {
      if (hooks.getControlThrows) throw new Error("control unreadable");
      return control;
    },
    setControl: async (_c, patch) => {
      control = { ...control, ...patch };
      watermarks.push(control.lastAnalyzedSeq);
      return control;
    },
    recordAiError: (_c, phase) => aiErrors.push(phase),
    autoEnrichIfEnabled: () => {},
    dispatchNotify: () => {},
  });
  const logCaptures = async (...seqs: number[]) => {
    const logPath = store.capturesLogPath(CASE_ID);
    await mkdir(dirname(logPath), { recursive: true });
    const lines = seqs.map((s) => JSON.stringify({ sequenceNumber: s, isDuplicate: false }));
    await writeFile(logPath, lines.join("\n") + "\n");
  };
  const cap = (seq: number) => ({ sequenceNumber: seq, isDuplicate: false }) as unknown as CaptureMetadata;
  return {
    analysis,
    calls,
    statuses,
    watermarks,
    aiErrors,
    logCaptures,
    cap,
    control: () => control,
    pause: () => (control = { ...control, enabled: false }),
  };
}

describe("AI off→on backfill (#2250)", () => {
  it("never lowers the watermark when a live flush lands during the catch-up", async () => {
    let flushDuring: Promise<void> | undefined;
    const h = await harness({
      onWindow: (seqs) => {
        // While the first catch-up window is in flight, a live capture (seq 10) is flushed.
        if (seqs[0] === 1 && !flushDuring) {
          h.analysis.captureBuffers.set(CASE_ID, [h.cap(10)]);
          flushDuring = h.analysis.flush(CASE_ID);
        }
      },
    });
    await h.logCaptures(1, 2, 3, 4);
    await h.analysis.backfill(CASE_ID);
    await flushDuring;
    for (let i = 1; i < h.watermarks.length; i++) {
      expect(h.watermarks[i]).toBeGreaterThanOrEqual(h.watermarks[i - 1]);
    }
    expect(h.control().lastAnalyzedSeq).toBe(10);
    // Seq 10 went out once — the catch-up left it to the live buffer that held it.
    expect(h.calls.flat().filter((s) => s === 10)).toHaveLength(1);
  });

  it("stops between windows once the analyst pauses AI", async () => {
    const h = await harness({
      onWindow: (seqs) => {
        if (seqs[0] === 1) h.pause();
      },
    });
    await h.logCaptures(1, 2, 3, 4, 5, 6);
    await h.analysis.backfill(CASE_ID);
    expect(h.calls).toEqual([[1, 2]]);
    expect(h.control().lastAnalyzedSeq).toBe(2); // the rest stays owed for the next AI on
    expect(h.statuses.at(-1)?.status).toBe("idle");
  });

  it("a throw before the catch-up starts ends on a terminal error status, not a rejection", async () => {
    const h = await harness({ getControlThrows: true });
    await h.logCaptures(1);
    await expect(h.analysis.backfill(CASE_ID)).resolves.toBeUndefined();
    expect(h.statuses.at(-1)).toMatchObject({ status: "error", detail: "control unreadable" });
    expect(h.aiErrors).toEqual(["extracting"]);
  });
});
