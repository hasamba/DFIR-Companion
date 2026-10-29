// #2265: three gaps left after #2248/#2249's failed-window recovery.
//   1. The AI status read plain "idle" while failed screenshots were still owed.
//   2. A throw outside the window loop (control read, log read) did not count as a recovery
//      attempt, so the 5-minute sweep retried it forever.
//   3. A restart while a live window was in flight could lose that window, when a later window had
//      already moved the watermark past it. The in-flight window is now recorded before the call.
import { describe, it, expect } from "vitest";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createCaptureAnalysis } from "../../src/composition/captureAnalysis.js";
import { adoptInFlight } from "../../src/composition/captureRecovery.js";
import { describeAnalysisHold, type AiControl } from "../../src/analysis/aiControl.js";
import { deriveAiState } from "../../src/analysis/aiState.js";
import type { AppOptions } from "../../src/composition/appOptions.js";
import type { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import type { CaptureMetadata } from "../../src/types.js";

const CASE_ID = "c2265";

interface HarnessOpts {
  maxAttempts?: number;
  control?: Partial<AiControl>;
  windowSize?: number;
}

async function harness(opts: HarnessOpts = {}) {
  const root = await mkdtemp(join(tmpdir(), "dfir-recovery-gaps-"));
  const store = new CaseStore(root);
  await store.createCase({ caseId: CASE_ID, name: "n", investigator: "i", aiProvider: null });
  let control = { enabled: true, lastAnalyzedSeq: 0, ...opts.control };
  const calls: number[][] = [];
  const controlDuringCall: (AiControl | undefined)[] = [];
  let failing = false;
  let controlThrows = false;
  let controlReads = 0;
  const pipeline = {
    analyzeWindow: async (_caseId: string, win: CaptureMetadata[]) => {
      calls.push(win.map((c) => c.sequenceNumber));
      controlDuringCall.push(control);
      if (failing) throw new Error("provider down");
    },
    hasSynthesisProvider: () => false,
  } as unknown as AnalysisPipeline;
  const statuses: { status: string; detail?: string }[] = [];
  const options = {
    pipeline,
    flushIntervalMs: 0,
    ...(opts.windowSize ? { windowSize: opts.windowSize } : {}),
    captureRecovery: { maxAttempts: opts.maxAttempts ?? 3, backoffMs: 0 },
    onAiStatus: (_c: string, s: { status: string; detail?: string }) => statuses.push(s),
  } as unknown as AppOptions;
  const analysis = createCaptureAnalysis({
    store,
    options,
    hasAiProvider: () => true,
    getControl: async () => {
      controlReads += 1;
      if (controlThrows) throw new Error("ai-control.json unreadable");
      return control;
    },
    setControl: async (_c, patch) => (control = { ...control, ...patch }),
    recordAiError: () => {},
    autoEnrichIfEnabled: () => {},
    dispatchNotify: () => {},
  });
  const cap = (seq: number) => ({ sequenceNumber: seq, isDuplicate: false }) as unknown as CaptureMetadata;
  const logCaptures = async (...seqs: number[]) => {
    const logPath = store.capturesLogPath(CASE_ID);
    await mkdir(dirname(logPath), { recursive: true });
    await writeFile(logPath, seqs.map((s) => JSON.stringify(cap(s))).join("\n") + "\n");
  };
  const flushWindow = async (...seqs: number[]) => {
    analysis.captureBuffers.set(CASE_ID, seqs.map(cap));
    await analysis.flush(CASE_ID);
  };
  return {
    store,
    analysis,
    calls,
    statuses,
    controlDuringCall,
    control: () => control,
    setFailing: (v: boolean) => (failing = v),
    setControlThrows: (v: boolean) => (controlThrows = v),
    controlReads: () => controlReads,
    logCaptures,
    flushWindow,
  };
}

describe("the AI status names held screenshots instead of reading idle (#2265 item 1)", () => {
  it("a later good window reports the held screenshots, not plain idle", async () => {
    const h = await harness();
    await h.logCaptures(1, 2, 3, 4, 5, 6, 7, 8);
    h.setFailing(true);
    await h.flushWindow(1, 2, 3, 4);
    h.setFailing(false);
    await h.flushWindow(5, 6, 7, 8);
    expect(h.statuses.at(-1)).toMatchObject({
      status: "idle",
      detail: "4 screenshot(s) waiting for retry",
    });
  });

  it("a plain idle carries no hold detail once nothing is owed", async () => {
    const h = await harness();
    await h.logCaptures(1, 2);
    await h.flushWindow(1, 2);
    expect(h.statuses.at(-1)?.status).toBe("idle");
    expect(h.statuses.at(-1)?.detail).toBeUndefined();
  });

  it("describes a hold that gave up as needing the analyst", () => {
    expect(describeAnalysisHold({ failedSeqs: [1, 2], analyzedThrough: 0, attempts: 3, gaveUp: true })).toBe(
      "2 screenshot(s) could not be analyzed — turn AI off and on to retry",
    );
    expect(describeAnalysisHold(undefined)).toBeUndefined();
  });

  it("the derived pill state (GET /ai-state) reports the hold, not 'up to date'", () => {
    const hold = (gaveUp: boolean) => ({ failedSeqs: [3], analyzedThrough: 4, attempts: 1, gaveUp });
    const waiting = deriveAiState({
      aiConfigured: true,
      enabled: true,
      screenshotHold: { detail: describeAnalysisHold(hold(false))!, gaveUp: false },
    });
    expect(waiting).toMatchObject({ state: "idle", detail: "1 screenshot(s) waiting for retry" });
    const gaveUp = deriveAiState({
      aiConfigured: true,
      enabled: true,
      screenshotHold: { detail: describeAnalysisHold(hold(true))!, gaveUp: true },
    });
    expect(gaveUp).toMatchObject({
      state: "error",
      detail: "1 screenshot(s) could not be analyzed — turn AI off and on to retry",
    });
  });
});

describe("a throw inside recovery counts against the attempt cap (#2265 item 2)", () => {
  it("an unreadable capture log uses up recovery attempts and then gives up", async () => {
    const h = await harness({ maxAttempts: 2 });
    await h.logCaptures(1, 2);
    h.setFailing(true);
    await h.flushWindow(1, 2);
    // Replace the log with a directory: every read now fails with EISDIR, not ENOENT.
    const logPath = h.store.capturesLogPath(CASE_ID);
    const { rm } = await import("node:fs/promises");
    await rm(logPath, { force: true });
    await mkdir(logPath, { recursive: true });
    for (let i = 0; i < 5; i++) await h.analysis.recover(CASE_ID);
    expect(h.control().analysisHold).toMatchObject({ attempts: 2, gaveUp: true, failedSeqs: [1, 2] });
    expect(h.calls).toHaveLength(1); // only the live window ever reached the provider
  });

  it("a control store that keeps throwing stops being retried after the cap", async () => {
    const h = await harness({ maxAttempts: 2 });
    await h.logCaptures(1);
    h.setFailing(true);
    await h.flushWindow(1);
    h.setControlThrows(true);
    // Never rejects: the sweep fires recover() with `void`, so a rejection would go unhandled.
    for (let i = 0; i < 2; i++) await expect(h.analysis.recover(CASE_ID)).resolves.toBeUndefined();
    const readsAtCap = h.controlReads();
    for (let i = 0; i < 3; i++) await h.analysis.recover(CASE_ID);
    expect(h.controlReads()).toBe(readsAtCap);
  });
});

describe("a window in flight across a restart is recovered (#2265 item 3)", () => {
  it("records the in-flight window before the call and clears it on success", async () => {
    const h = await harness();
    await h.logCaptures(1, 2);
    await h.flushWindow(1, 2);
    expect(h.controlDuringCall[0]?.inFlightSeqs).toEqual([1, 2]);
    expect(h.control().inFlightSeqs).toBeUndefined();
    expect(h.control().lastAnalyzedSeq).toBe(2);
  });

  it("moves a failed in-flight window into the hold", async () => {
    const h = await harness();
    await h.logCaptures(1, 2);
    h.setFailing(true);
    await h.flushWindow(1, 2);
    expect(h.control().inFlightSeqs).toBeUndefined();
    expect(h.control().analysisHold).toMatchObject({ failedSeqs: [1, 2] });
  });

  it("a restart recovers an in-flight window a later window had already passed", async () => {
    // The process died during the call for 5–6, after 7–8 had moved the watermark to 8.
    const h = await harness({ control: { lastAnalyzedSeq: 8, inFlightSeqs: [5, 6] }, windowSize: 2 });
    await h.logCaptures(1, 2, 3, 4, 5, 6, 7, 8);
    await h.analysis.resumeAfterRestart();
    expect(h.calls).toEqual([[5, 6]]);
    expect(h.control().lastAnalyzedSeq).toBe(8);
    expect(h.control().analysisHold).toBeUndefined();
    expect(h.control().inFlightSeqs).toBeUndefined();
  });

  it("an in-flight window still above the watermark is simply dropped — it is owed anyway", () => {
    const control: AiControl = { enabled: true, lastAnalyzedSeq: 4, inFlightSeqs: [5, 6] };
    expect(adoptInFlight(control)).toEqual({ inFlightSeqs: undefined });
  });

  it("joins an existing hold without resetting its attempts", () => {
    const control: AiControl = {
      enabled: true,
      lastAnalyzedSeq: 0,
      inFlightSeqs: [3],
      analysisHold: { failedSeqs: [1], analyzedThrough: 4, attempts: 2 },
    };
    expect(adoptInFlight(control)).toEqual({
      inFlightSeqs: undefined,
      lastAnalyzedSeq: 0,
      analysisHold: { failedSeqs: [1, 3], analyzedThrough: 4, attempts: 2 },
    });
  });

  it("a flush after a restart keeps the stale in-flight window owed", async () => {
    const h = await harness({ control: { lastAnalyzedSeq: 8, inFlightSeqs: [5, 6] } });
    await h.logCaptures(1, 2, 3, 4, 5, 6, 7, 8, 9);
    await h.flushWindow(9);
    expect(h.control().analysisHold).toMatchObject({ failedSeqs: [5, 6] });
    expect(h.control().lastAnalyzedSeq).toBe(4);
    h.calls.length = 0;
    await h.analysis.recover(CASE_ID);
    expect(h.calls).toEqual([[5, 6]]);
    expect(h.control().lastAnalyzedSeq).toBe(9);
  });
});
