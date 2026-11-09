// #2498: an analyst who accepts the gap left by screenshots the AI could not analyze had no way to
// clear the hold. "Skip" must make those captures permanently not owed — a restart or an AI off→on
// catch-up may never retry them — while every other owed capture stays owed.
import { describe, it, expect } from "vitest";
import { mkdtemp, mkdir, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createCaptureAnalysis } from "../../src/composition/captureAnalysis.js";
import { pendingCaptures, skipHoldPatch } from "../../src/composition/captureRecovery.js";
import { holdToken, type AiControl } from "../../src/analysis/aiControl.js";
import type { AppOptions } from "../../src/composition/appOptions.js";
import type { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import type { CaptureMetadata } from "../../src/types.js";

const CASE_ID = "c2498";
const MARKER = "pending_analysis.json";

const cap = (seq: number, isDuplicate = false) =>
  ({ sequenceNumber: seq, isDuplicate }) as unknown as CaptureMetadata;
const caps = (...seqs: number[]) => seqs.map((s) => cap(s));
const owedSeqs = (captures: CaptureMetadata[], control: AiControl) =>
  pendingCaptures(captures, control).map((c) => c.sequenceNumber);

describe("skipHoldPatch — what a skip leaves owed (#2498)", () => {
  it("failed captures above analyzedThrough stop being owed (releaseHold alone left them owed)", () => {
    const control: AiControl = {
      enabled: true,
      lastAnalyzedSeq: 0,
      analysisHold: { failedSeqs: [1, 2], analyzedThrough: 0, attempts: 3, gaveUp: true },
    };
    const log = caps(1, 2);
    const { patch, skipped, remaining } = skipHoldPatch(control, log);
    expect(skipped).toEqual([1, 2]);
    expect(remaining).toEqual([]);
    const after = { ...control, ...patch };
    expect(after.analysisHold).toBeUndefined();
    expect(owedSeqs(log, after)).toEqual([]);
  });

  it("keeps a newer capture that never failed owed", () => {
    const control: AiControl = {
      enabled: true,
      lastAnalyzedSeq: 4,
      analysisHold: { failedSeqs: [5, 6, 9, 10], analyzedThrough: 8, attempts: 3, gaveUp: true },
    };
    const log = caps(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12);
    const { patch, skipped } = skipHoldPatch(control, log);
    expect(skipped).toEqual([5, 6, 9, 10]);
    expect(owedSeqs(log, { ...control, ...patch })).toEqual([11, 12]);
  });

  it("walks over duplicates and failed captures missing from the log", () => {
    const control: AiControl = {
      enabled: true,
      lastAnalyzedSeq: 0,
      analysisHold: { failedSeqs: [1, 3], analyzedThrough: 0, attempts: 1 },
    };
    const log = [cap(1), cap(2, true), cap(4)];
    const { patch, skipped } = skipHoldPatch(control, log);
    expect(skipped).toEqual([1, 3]);
    expect(owedSeqs(log, { ...control, ...patch })).toEqual([4]);
  });

  it("never drops an owed capture sitting between failed ones: the rest stays held", () => {
    const control: AiControl = {
      enabled: true,
      lastAnalyzedSeq: 0,
      analysisHold: { failedSeqs: [1, 2, 4], analyzedThrough: 0, attempts: 3, gaveUp: true },
    };
    // 3 never failed and was never analyzed: it is owed and must stay owed.
    const log = caps(1, 2, 3, 4, 5);
    const { patch, skipped, remaining } = skipHoldPatch(control, log);
    expect(skipped).toEqual([1, 2]);
    expect(remaining).toEqual([4]);
    const after = { ...control, ...patch };
    expect(after.analysisHold?.failedSeqs).toEqual([4]);
    expect(owedSeqs(log, after)).toEqual([3, 4, 5]);
  });

  it("stops at a capture waiting in the live buffer", () => {
    const control: AiControl = {
      enabled: true,
      lastAnalyzedSeq: 0,
      analysisHold: { failedSeqs: [1, 3], analyzedThrough: 0, attempts: 3, gaveUp: true },
    };
    const { skipped, remaining } = skipHoldPatch(control, caps(1, 2, 3), new Set([2]));
    expect(skipped).toEqual([1]);
    expect(remaining).toEqual([3]);
  });

  it("is a no-op without a hold", () => {
    const control: AiControl = { enabled: true, lastAnalyzedSeq: 3 };
    expect(skipHoldPatch(control, caps(1, 2, 3))).toEqual({ patch: {}, skipped: [], remaining: [] });
  });
});

describe("holdToken", () => {
  it("is stable for the same captures and changes when they change", () => {
    const a = { failedSeqs: [2, 1], analyzedThrough: 0, attempts: 0 };
    const b = { failedSeqs: [1, 2], analyzedThrough: 5, attempts: 2 };
    expect(holdToken(a)).toBe(holdToken(b));
    expect(holdToken({ ...a, failedSeqs: [1, 2, 3] })).not.toBe(holdToken(a));
    expect(holdToken(undefined)).toBeUndefined();
  });
});

async function harness() {
  const root = await mkdtemp(join(tmpdir(), "dfir-skip-held-"));
  const store = new CaseStore(root);
  await store.createCase({ caseId: CASE_ID, name: "n", investigator: "i", aiProvider: null });
  const calls: number[][] = [];
  let failing = false;
  let gate: Promise<void> = Promise.resolve();
  const pipeline = {
    analyzeWindow: async (_caseId: string, win: CaptureMetadata[]) => {
      calls.push(win.map((c) => c.sequenceNumber));
      await gate;
      if (failing) throw new Error("provider down");
    },
    hasSynthesisProvider: () => false,
  } as unknown as AnalysisPipeline;
  const statuses: { status: string; detail?: string }[] = [];
  const options = {
    pipeline,
    flushIntervalMs: 0,
    captureRecovery: { maxAttempts: 1, backoffMs: 0 },
    onAiStatus: (_c: string, s: { status: string; detail?: string }) => statuses.push(s),
  } as unknown as AppOptions;
  let control = { enabled: true, lastAnalyzedSeq: 0 } as AiControl;
  const analysis = createCaptureAnalysis({
    store,
    options,
    hasAiProvider: () => true,
    getControl: async () => control,
    setControl: async (_c, patch) => (control = { ...control, ...patch }),
    recordAiError: () => {},
    autoEnrichIfEnabled: () => {},
    dispatchNotify: () => {},
  });
  const logCaptures = async (...seqs: number[]) => {
    const logPath = store.capturesLogPath(CASE_ID);
    await mkdir(dirname(logPath), { recursive: true });
    await writeFile(logPath, seqs.map((s) => JSON.stringify(cap(s))).join("\n") + "\n");
  };
  const flushWindow = async (...seqs: number[]) => {
    analysis.captureBuffers.set(
      CASE_ID,
      seqs.map((s) => cap(s)),
    );
    await analysis.flush(CASE_ID);
  };
  const markerExists = () =>
    stat(join(store.stateDir(CASE_ID), MARKER)).then(
      () => true,
      () => false,
    );
  return {
    analysis,
    calls,
    statuses,
    control: () => control,
    setFailing: (v: boolean) => (failing = v),
    /** Hold every model call until the returned release() is called. */
    blockCalls: () => {
      let release!: () => void;
      gate = new Promise<void>((r) => (release = r));
      return release;
    },
    store,
    logCaptures,
    flushWindow,
    markerExists,
  };
}

describe("skipHeldScreenshots — the composition path (#2498)", () => {
  it("clears the hold and the marker, reports idle, and a later catch-up never retries them", async () => {
    const h = await harness();
    await h.logCaptures(1, 2, 3, 4);
    h.setFailing(true);
    await h.flushWindow(1, 2, 3, 4);
    expect(h.control().analysisHold?.failedSeqs).toEqual([1, 2, 3, 4]);
    expect(await h.markerExists()).toBe(true);

    const token = holdToken(h.control().analysisHold)!;
    const result = await h.analysis.skipHeldScreenshots(CASE_ID, token);
    expect(result).toMatchObject({ outcome: "skipped", skipped: [1, 2, 3, 4], remaining: [] });
    expect(result.lastError).toBe("provider down");
    expect(h.control().analysisHold).toBeUndefined();
    expect(await h.markerExists()).toBe(false);
    expect(h.statuses.at(-1)).toEqual(expect.objectContaining({ status: "idle" }));
    expect(h.statuses.at(-1)?.detail).toBeUndefined();

    // AI off→on, the analyst's catch-up: nothing skipped is sent again.
    h.setFailing(false);
    const before = h.calls.length;
    await h.analysis.backfill(CASE_ID);
    expect(h.calls.slice(before)).toEqual([]);
  });

  it("refuses a stale token: the hold changed since the analyst saw it", async () => {
    const h = await harness();
    await h.logCaptures(1, 2, 3, 4);
    h.setFailing(true);
    await h.flushWindow(1, 2);
    const shown = holdToken(h.control().analysisHold)!;
    await h.flushWindow(3, 4); // the hold grows after the button was shown
    const result = await h.analysis.skipHeldScreenshots(CASE_ID, shown);
    expect(result.outcome).toBe("stale");
    expect(h.control().analysisHold?.failedSeqs).toEqual([1, 2, 3, 4]);
  });

  it("re-checks the case after waiting in the queue: a case closed meanwhile is not changed", async () => {
    const h = await harness();
    await h.logCaptures(1, 2, 3, 4);
    h.setFailing(true);
    await h.flushWindow(1, 2);
    const token = holdToken(h.control().analysisHold)!;
    const before = h.control();
    // A window is running; the skip queues behind it, and the case is closed while it waits.
    const release = h.blockCalls();
    h.analysis.captureBuffers.set(CASE_ID, [cap(3), cap(4)]);
    const running = h.analysis.flush(CASE_ID);
    const queued = h.analysis.skipHeldScreenshots(CASE_ID, token);
    await h.store.setCaseStatus(CASE_ID, "closed");
    h.setFailing(false);
    release();
    await running;
    const result = await queued;
    expect(result.outcome).toBe("frozen");
    expect(h.control().analysisHold?.failedSeqs).toEqual(before.analysisHold?.failedSeqs);
  });

  it("answers 'none' when nothing is held", async () => {
    const h = await harness();
    const result = await h.analysis.skipHeldScreenshots(CASE_ID, "anything");
    expect(result).toMatchObject({ outcome: "none", skipped: [] });
  });
});
