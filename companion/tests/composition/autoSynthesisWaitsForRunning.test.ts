// #1608: an automatic synthesis kick waits for a RUNNING synthesis instead of superseding it.
//
// Superseding aborts the older run, but its model call is still billed (an HTTP provider closes the
// socket after the upstream started generating; a CLI provider may run on). An import landing
// mid-synthesis paid for two model calls and showed one result. Now the kick waits, and one
// follow-up run covers everything that arrived meanwhile. The analyst's own "run now" still
// supersedes, and an analyst Cancel is not undone by a waiting kick.
import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { JobManager } from "../../src/analysis/jobManager.js";
import { createCaptureAnalysis } from "../../src/composition/captureAnalysis.js";
import type { AppOptions } from "../../src/composition/appOptions.js";
import type { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import type { AiControl } from "../../src/analysis/aiControl.js";
import { pollFor } from "../helpers/poll.js";

const CASE_ID = "case-1608";

interface Run {
  signal?: AbortSignal;
  release: () => void;
}

async function harness() {
  const root = await mkdtemp(join(tmpdir(), "dfir-1608-"));
  const store = new CaseStore(root);
  const jobManager = new JobManager({ perCaseConcurrency: 1 });
  const runs: Run[] = [];
  const pipeline = {
    hasSynthesisProvider: () => true,
    synthesize: (_caseId: string, opts: { signal?: AbortSignal } = {}) =>
      new Promise((resolve, reject) => {
        opts.signal?.addEventListener("abort", () => {
          const err = new Error("synthesis superseded by a newer run");
          err.name = "AbortError";
          reject(err);
        });
        runs.push({ ...(opts.signal ? { signal: opts.signal } : {}), release: () => resolve({}) });
      }),
  } as unknown as AnalysisPipeline;
  const marks: string[] = [];
  const control = { enabled: true };
  const statuses: { status: string; detail?: string }[] = [];
  const options = {
    pipeline,
    jobManager,
    autoSynthesize: true,
    autoSynthesizeDebounceMs: 5,
    synthMetaStore: { markOutOfDate: async (_c: string, reason: string) => void marks.push(reason) },
    onAiStatus: (_caseId: string, s: { status: string; detail?: string }) => statuses.push(s),
  } as unknown as AppOptions;
  const analysis = createCaptureAnalysis({
    store,
    options,
    hasAiProvider: () => true,
    getControl: async () => ({ enabled: control.enabled }) as AiControl,
    setControl: async () => ({ enabled: true }) as AiControl,
    recordAiError: () => {},
    autoEnrichIfEnabled: () => {},
    dispatchNotify: () => {},
  });
  const runningCount = (n: number) =>
    pollFor(`${n} synthesis run(s) to start, saw ${runs.length}`, async () =>
      runs.length === n ? true : undefined,
    );
  const settle = () => new Promise((r) => setTimeout(r, 60)); // several retry periods
  return { analysis, jobManager, runs, marks, statuses, control, runningCount, settle };
}

describe("an automatic synthesis kick while a synthesis is running (#1608)", () => {
  it("does not abort the running call, and runs once afterwards however many kicks arrived", async () => {
    const { analysis, runs, runningCount, settle } = await harness();
    analysis.resynthesizeInBackground(CASE_ID);
    await runningCount(1);

    for (let i = 0; i < 3; i++) analysis.resynthesizeInBackground(CASE_ID); // three more imports land
    analysis.scheduleSynthesis(CASE_ID); // and a live kick
    await settle();

    expect(runs[0].signal?.aborted, "the paid-for run must not be superseded").toBe(false);
    expect(runs).toHaveLength(1);

    runs[0].release();
    await runningCount(2);
    await settle();
    expect(runs, "every waiting kick collapses into one follow-up run").toHaveLength(2);
    runs[1].release();
  });

  it("the debounced live kick waits for a running re-synthesis too", async () => {
    const { analysis, runs, runningCount, settle } = await harness();
    analysis.resynthesizeInBackground(CASE_ID);
    await runningCount(1);

    analysis.scheduleSynthesis(CASE_ID);
    await settle();
    expect(runs[0].signal?.aborted).toBe(false);
    expect(runs).toHaveLength(1);

    runs[0].release();
    await runningCount(2);
    runs[1].release();
  });

  it("still supersedes a QUEUED synthesis, which has made no model call yet", async () => {
    const { analysis, jobManager, runs, runningCount } = await harness();
    const importJob = jobManager.register({ caseId: CASE_ID, kind: "import", label: "evtx" });
    await importJob.ready;
    analysis.resynthesizeInBackground(CASE_ID);
    analysis.resynthesizeInBackground(CASE_ID);
    await pollFor("one surviving queued synthesis", async () =>
      jobManager.list(CASE_ID).filter((j) => j.kind === "synthesis").length === 1 ? true : undefined,
    );
    await jobManager.finish(importJob.jobId);
    await runningCount(1);
    runs[0].release();
  });

  it("an analyst's /dfir synthesize still supersedes the running synthesis", async () => {
    const { analysis, runs, runningCount } = await harness();
    analysis.resynthesizeInBackground(CASE_ID);
    await runningCount(1);

    analysis.resynthesizeInBackground(CASE_ID, { analyst: true });
    await runningCount(2);
    expect(runs[0].signal?.aborted).toBe(true);
    runs[1].release();
  });

  it("does not undo an analyst Cancel: the waiting kick marks the conclusions out of date instead", async () => {
    const { analysis, jobManager, runs, marks, statuses, runningCount, settle } = await harness();
    analysis.resynthesizeInBackground(CASE_ID);
    await runningCount(1);
    analysis.resynthesizeInBackground(CASE_ID); // new evidence arrives, the kick waits

    const running = jobManager.list(CASE_ID).find((j) => j.kind === "synthesis" && j.status === "running");
    await jobManager.cancel(running!.id);
    await pollFor("the waiting kick to mark out of date", async () => (marks.length > 0 ? true : undefined));
    await settle();

    expect(runs, "no fresh run after the analyst's Cancel").toHaveLength(1);
    expect(marks).toEqual(["synthesis cancelled with newer evidence waiting"]);
    expect(statuses.at(-1)?.status).toBe("idle");
  });

  it("a scheduled run in flight plus both kinds of kick still gives exactly one follow-up", async () => {
    const { analysis, runs, runningCount, settle } = await harness();
    analysis.scheduleSynthesis(CASE_ID);
    await runningCount(1);

    analysis.resynthesizeInBackground(CASE_ID);
    analysis.scheduleSynthesis(CASE_ID);
    await settle();
    expect(runs[0].signal?.aborted).toBe(false);

    runs[0].release();
    await runningCount(2);
    await settle();
    expect(runs, "one shared queue for every automatic kick").toHaveLength(2);
    runs[1].release();
  });

  it("a waiting live kick does not start a run after the analyst pauses AI", async () => {
    const { analysis, runs, marks, control, runningCount, settle } = await harness();
    analysis.resynthesizeInBackground(CASE_ID);
    await runningCount(1);
    analysis.scheduleSynthesis(CASE_ID);
    await settle();

    control.enabled = false; // the analyst pauses AI while the kick waits
    runs[0].release();
    await pollFor("the waiting kick to mark out of date", async () => (marks.length > 0 ? true : undefined));
    await settle();

    expect(runs).toHaveLength(1);
    expect(marks).toEqual(["new evidence while AI was off"]);
  });
});
