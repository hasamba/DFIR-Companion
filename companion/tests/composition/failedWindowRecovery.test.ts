// #2248: a failed screenshot window was never retried. flush emptied the buffer before the call,
// the catch only wrote a marker, and the next good window moved lastAnalyzedSeq past the failed
// captures — so even an AI off→on backfill skipped them. The watermark is now held below the
// lowest failed capture, and a capped, backed-off recovery re-derives the held captures from
// captures.jsonl. The failed buffer is NOT re-queued: a permanent error would then resend a batch
// that grows with every capture.
import { describe, it, expect } from "vitest";
import { mkdtemp, mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createCaptureAnalysis } from "../../src/composition/captureAnalysis.js";
import type { AppOptions } from "../../src/composition/appOptions.js";
import type { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import type { AiControl } from "../../src/analysis/aiControl.js";
import type { CaptureMetadata } from "../../src/types.js";

const CASE_ID = "c2248";
const MARKER = "pending_analysis.json";

interface HarnessOpts {
  maxAttempts?: number;
  backoffMs?: number;
}

async function harness(opts: HarnessOpts = {}) {
  const root = await mkdtemp(join(tmpdir(), "dfir-window-recovery-"));
  const store = new CaseStore(root);
  await store.createCase({ caseId: CASE_ID, name: "n", investigator: "i", aiProvider: null });
  const calls: number[][] = [];
  let failing = false;
  const pipeline = {
    analyzeWindow: async (_caseId: string, win: CaptureMetadata[]) => {
      calls.push(win.map((c) => c.sequenceNumber));
      if (failing) throw new Error("provider down");
    },
    hasSynthesisProvider: () => false,
  } as unknown as AnalysisPipeline;
  const statuses: { status: string; detail?: string }[] = [];
  const options = {
    pipeline,
    flushIntervalMs: 0,
    captureRecovery: { maxAttempts: opts.maxAttempts ?? 3, backoffMs: opts.backoffMs ?? 0 },
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
    logCaptures,
    flushWindow,
    markerExists,
    readMarker: async () => JSON.parse(await readFile(join(store.stateDir(CASE_ID), MARKER), "utf8")),
  };
}

describe("a failed screenshot window is recovered, not skipped (#2248)", () => {
  it("holds the watermark below the failed window when a later window succeeds", async () => {
    const h = await harness();
    await h.logCaptures(1, 2, 3, 4, 5, 6, 7, 8);
    h.setFailing(true);
    await h.flushWindow(1, 2, 3, 4);
    h.setFailing(false);
    await h.flushWindow(5, 6, 7, 8);
    expect(h.control().lastAnalyzedSeq).toBe(0);
    // The failed captures are still owed, so the diagnostics marker stays.
    expect(await h.markerExists()).toBe(true);
  });

  it("recovery analyzes the failed captures from captures.jsonl, and only those", async () => {
    const h = await harness();
    await h.logCaptures(1, 2, 3, 4, 5, 6, 7, 8);
    h.setFailing(true);
    await h.flushWindow(1, 2, 3, 4);
    h.setFailing(false);
    await h.flushWindow(5, 6, 7, 8);
    h.calls.length = 0;
    await h.analysis.recover(CASE_ID);
    expect(h.calls).toEqual([[1, 2, 3, 4]]);
    expect(h.control().lastAnalyzedSeq).toBe(8);
    expect(h.control().analysisHold).toBeUndefined();
    expect(await h.markerExists()).toBe(false);
    expect(h.statuses.at(-1)).toMatchObject({ status: "idle" });
  });

  it("a permanent failure is retried at most maxAttempts times, then stops and stays visible", async () => {
    const h = await harness({ maxAttempts: 2 });
    await h.logCaptures(1, 2);
    h.setFailing(true);
    await h.flushWindow(1, 2);
    for (let i = 0; i < 5; i++) await h.analysis.recover(CASE_ID);
    expect(h.calls).toHaveLength(1 + 2); // the live window, then two recovery attempts
    expect(h.control().analysisHold).toMatchObject({ gaveUp: true, failedSeqs: [1, 2] });
    expect(h.control().lastAnalyzedSeq).toBe(0);
    expect(await h.markerExists()).toBe(true);
    expect((await h.readMarker()).error).toBe("provider down");
    expect(h.statuses.at(-1)).toMatchObject({ status: "error" });
  });

  it("waits out the backoff before a recovery attempt", async () => {
    const h = await harness({ backoffMs: 60_000 });
    await h.logCaptures(1);
    h.setFailing(true);
    await h.flushWindow(1);
    h.setFailing(false);
    await h.analysis.recover(CASE_ID);
    expect(h.calls).toHaveLength(1); // not due yet — no extra paid call
  });

  it("does not recover while AI is paused for the case", async () => {
    const h = await harness();
    await h.logCaptures(1);
    h.setFailing(true);
    await h.flushWindow(1);
    h.setFailing(false);
    h.control().enabled = false;
    await h.analysis.recover(CASE_ID);
    expect(h.calls).toHaveLength(1);
  });

  it("the AI off→on backfill re-analyzes the held captures but not the windows that succeeded", async () => {
    const h = await harness();
    await h.logCaptures(1, 2, 3, 4, 5, 6, 7, 8);
    h.setFailing(true);
    await h.flushWindow(1, 2, 3, 4);
    h.setFailing(false);
    await h.flushWindow(5, 6, 7, 8);
    h.calls.length = 0;
    await h.analysis.backfill(CASE_ID);
    expect(h.calls).toEqual([[1, 2, 3, 4]]);
    expect(h.control().lastAnalyzedSeq).toBe(8);
  });
});
