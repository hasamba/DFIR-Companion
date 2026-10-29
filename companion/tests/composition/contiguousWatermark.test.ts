// #2249 (Codex review): the watermark used to jump to a successful window's highest sequence
// number, so any owed capture below that window — one a restart stranded in the memory-only buffer,
// say — was skipped for good. A navigation capture flushes before the first sweep runs restart
// recovery, so "seq 1 buffered, restart, seq 2 flushed" lost seq 1. The watermark now only ever
// advances contiguously: an owed capture below a successful window is held, then recovered.
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

const CASE_ID = "a";

async function harness(initial: Partial<AiControl> = {}) {
  const root = await mkdtemp(join(tmpdir(), "dfir-contiguous-watermark-"));
  const store = new CaseStore(root);
  await store.createCase({ caseId: CASE_ID, name: "n", investigator: "i", aiProvider: null });
  // The control lives on "disk": it survives a new captureAnalysis instance, the buffer does not.
  let control: AiControl = { enabled: true, lastAnalyzedSeq: 0, ...initial };
  const calls: number[][] = [];
  let logReads = 0;
  const start = () => {
    const pipeline = {
      analyzeWindow: async (_caseId: string, win: CaptureMetadata[]) => {
        calls.push(win.map((c) => c.sequenceNumber));
      },
      hasSynthesisProvider: () => false,
    } as unknown as AnalysisPipeline;
    const options = {
      pipeline,
      flushIntervalMs: 0,
      windowSize: 5,
      captureRecovery: { backoffMs: 0 },
    } as unknown as AppOptions;
    const countingStore = new Proxy(store, {
      get(target, prop, receiver) {
        if (prop === "capturesLogPath") {
          return (caseId: string) => {
            logReads += 1;
            return target.capturesLogPath(caseId);
          };
        }
        const value = Reflect.get(target, prop, receiver);
        return typeof value === "function" ? value.bind(target) : value;
      },
    });
    return createCaptureAnalysis({
      store: countingStore,
      options,
      hasAiProvider: () => true,
      getControl: async () => control,
      setControl: async (_c, patch) => {
        control = { ...control, ...patch };
        return control;
      },
      recordAiError: () => {},
      autoEnrichIfEnabled: () => {},
      dispatchNotify: () => {},
    });
  };
  const cap = (seq: number, isDuplicate = false) =>
    ({ sequenceNumber: seq, isDuplicate }) as unknown as CaptureMetadata;
  const writeLog = async (...caps: CaptureMetadata[]) => {
    const logPath = store.capturesLogPath(CASE_ID);
    await mkdir(dirname(logPath), { recursive: true });
    await writeFile(logPath, caps.map((c) => JSON.stringify(c)).join("\n") + "\n");
  };
  return {
    start,
    cap,
    writeLog,
    calls,
    control: () => control,
    logReads: () => logReads,
    resetLogReads: () => {
      logReads = 0;
    },
  };
}

describe("the analysis watermark never passes an unanalyzed screenshot (#2249)", () => {
  it("a capture stranded by a restart survives a new flush that lands before the first sweep", async () => {
    const h = await harness();
    // Before the restart: seq 1 was logged and buffered, never flushed.
    const before = h.start();
    before.captureBuffers.set(CASE_ID, [h.cap(1)]);
    await h.writeLog(h.cap(1));

    // After the restart: a navigation capture (seq 2) flushes before the first sweep.
    const after = h.start();
    await h.writeLog(h.cap(1), h.cap(2));
    after.captureBuffers.set(CASE_ID, [h.cap(2)]);
    await after.flush(CASE_ID);
    expect(h.calls).toEqual([[2]]);
    expect(h.control().lastAnalyzedSeq).toBe(0);
    expect(h.control().analysisHold).toMatchObject({ failedSeqs: [1], analyzedThrough: 2 });

    // The first sweep's restart recovery then analyzes seq 1, and only seq 1.
    await after.resumeAfterRestart();
    expect(h.calls).toEqual([[2], [1]]);
    expect(h.control().lastAnalyzedSeq).toBe(2);
    expect(h.control().analysisHold).toBeUndefined();
  });

  it("duplicates in the gap do not create a hold", async () => {
    const h = await harness();
    const analysis = h.start();
    await h.writeLog(h.cap(1, true), h.cap(2, true), h.cap(3));
    analysis.captureBuffers.set(CASE_ID, [h.cap(3)]);
    await analysis.flush(CASE_ID);
    expect(h.control().lastAnalyzedSeq).toBe(3);
    expect(h.control().analysisHold).toBeUndefined();
  });

  it("a held gap capture that later flushes normally releases the hold", async () => {
    const h = await harness();
    const analysis = h.start();
    await h.writeLog(h.cap(1), h.cap(2));
    analysis.captureBuffers.set(CASE_ID, [h.cap(2)]);
    await analysis.flush(CASE_ID);
    expect(h.control().analysisHold).toMatchObject({ failedSeqs: [1] });
    analysis.captureBuffers.set(CASE_ID, [h.cap(1)]);
    await analysis.flush(CASE_ID);
    expect(h.control().analysisHold).toBeUndefined();
    expect(h.control().lastAnalyzedSeq).toBe(2);
  });

  it("a capture still waiting in the live buffer is not held", async () => {
    const h = await harness();
    const analysis = h.start();
    await h.writeLog(h.cap(1), h.cap(2));
    // The AI off-to-on catch-up analyzes seq 2 while seq 1 sits in the buffer. Seq 1 goes out with
    // the next flush, so holding it as well would analyze it twice.
    analysis.captureBuffers.set(CASE_ID, [h.cap(1)]);
    await analysis.backfill(CASE_ID);
    expect(h.calls).toEqual([[2]]);
    expect(h.control().analysisHold).toBeUndefined();
  });

  it("does not read the capture log when the window follows the watermark contiguously", async () => {
    const h = await harness({ lastAnalyzedSeq: 4 });
    const analysis = h.start();
    await h.writeLog(h.cap(5, true), h.cap(6));
    h.resetLogReads();
    // The duplicate rides in the same window, so it accounts for seq 5 without a log read.
    analysis.captureBuffers.set(CASE_ID, [h.cap(5, true), h.cap(6)]);
    await analysis.flush(CASE_ID);
    expect(h.logReads()).toBe(0);
    expect(h.control().lastAnalyzedSeq).toBe(6);
  });

  it("keeps an existing hold's failures and adds the skipped capture above its high mark", async () => {
    const h = await harness({
      lastAnalyzedSeq: 0,
      analysisHold: { failedSeqs: [1], analyzedThrough: 2, attempts: 1 },
    });
    const analysis = h.start();
    await h.writeLog(h.cap(1), h.cap(2), h.cap(3), h.cap(4));
    analysis.captureBuffers.set(CASE_ID, [h.cap(4)]);
    await analysis.flush(CASE_ID);
    expect(h.control().analysisHold).toMatchObject({ failedSeqs: [1, 3], analyzedThrough: 4, attempts: 1 });
    expect(h.control().lastAnalyzedSeq).toBe(0);
  });
});
