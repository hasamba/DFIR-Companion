// #2152: the pending_analysis.json failure marker is written when an analysis window fails. It
// used a bare writeFile (a crash mid-write left torn JSON) and carried a `pending` field nothing
// ever read back — backfill re-derives the un-analyzed window from lastAnalyzedSeq. It now goes
// through atomicWrite, drops `pending`, and is best-effort: a marker write that fails must not
// swallow the "error" status the analyst sees.
import { describe, it, expect, afterEach } from "vitest";
import { mkdtemp, mkdir, readFile, readdir, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createCaptureAnalysis } from "../../src/composition/captureAnalysis.js";
import type { AppOptions } from "../../src/composition/appOptions.js";
import type { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import type { AiControl } from "../../src/analysis/aiControl.js";
import type { CaptureMetadata } from "../../src/types.js";

const CASE_ID = "c2152";
const MARKER = "pending_analysis.json";

async function harness(analyzeWindow: () => Promise<void>) {
  const root = await mkdtemp(join(tmpdir(), "dfir-pending-marker-"));
  const store = new CaseStore(root);
  await store.createCase({ caseId: CASE_ID, name: "n", investigator: "i", aiProvider: null });
  const statuses: { status: string; detail?: string }[] = [];
  const pipeline = { analyzeWindow, hasSynthesisProvider: () => false } as unknown as AnalysisPipeline;
  const options = {
    pipeline,
    flushIntervalMs: 0,
    onAiStatus: (_caseId: string, s: { status: string; detail?: string }) => statuses.push(s),
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
  const stateDir = store.stateDir(CASE_ID);
  const feed = (seq: number) =>
    analysis.captureBuffers.set(CASE_ID, [{ sequenceNumber: seq } as unknown as CaptureMetadata]);
  const tmpLeftovers = async () => (await readdir(stateDir)).filter((f) => f.includes(".tmp"));
  return { analysis, statuses, stateDir, feed, tmpLeftovers };
}

const savedRetries = process.env.DFIR_ATOMIC_WRITE_RETRIES;
afterEach(() => {
  if (savedRetries === undefined) delete process.env.DFIR_ATOMIC_WRITE_RETRIES;
  else process.env.DFIR_ATOMIC_WRITE_RETRIES = savedRetries;
});

describe("pending_analysis.json failure marker (#2152)", () => {
  it("is written whole, carries the error and no write-only pending field", async () => {
    const h = await harness(async () => {
      throw new Error("provider down");
    });
    h.feed(1);
    await h.analysis.flush(CASE_ID);
    const marker = JSON.parse(await readFile(join(h.stateDir, MARKER), "utf8"));
    expect(marker.error).toBe("provider down");
    expect(marker).not.toHaveProperty("pending");
    expect(await h.tmpLeftovers()).toEqual([]);
    expect(h.statuses.at(-1)).toMatchObject({ status: "error", detail: "provider down" });
    // Diagnostics counts failed cases by the marker's presence alone.
    expect((await stat(join(h.stateDir, MARKER))).isFile()).toBe(true);
  });

  it("a marker write that fails still pushes the error status and does not reject", async () => {
    process.env.DFIR_ATOMIC_WRITE_RETRIES = "1"; // Windows reports EPERM, a retried code
    const h = await harness(async () => {
      throw new Error("provider down");
    });
    await mkdir(join(h.stateDir, MARKER)); // the rename onto a directory fails
    h.feed(1);
    await expect(h.analysis.flush(CASE_ID)).resolves.toBeUndefined();
    expect(h.statuses.at(-1)).toMatchObject({ status: "error", detail: "provider down" });
    expect(await h.tmpLeftovers()).toEqual([]);
  });

  it("is removed again once a later window analyzes cleanly", async () => {
    let fail = true;
    const h = await harness(async () => {
      if (fail) throw new Error("provider down");
    });
    h.feed(1);
    await h.analysis.flush(CASE_ID);
    expect((await stat(join(h.stateDir, MARKER))).isFile()).toBe(true);
    fail = false;
    h.feed(2);
    await h.analysis.flush(CASE_ID);
    await expect(stat(join(h.stateDir, MARKER))).rejects.toThrow();
  });
});
