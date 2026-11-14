// Watson's reaction waits while a synthesis is running, queued or scheduled (spec §4.6, Task 8
// amendment): an import with AI on starts a synthesis, and Watson reacts to its result, not before it.
// A synthesis that ended held (Presidio, a merge gate) or cancelled is not busy.
import { describe, expect, it } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { JobManager } from "../../src/analysis/jobManager.js";
import type { Job } from "../../src/analysis/jobRegistry.js";
import { createCaptureAnalysis } from "../../src/composition/captureAnalysis.js";
import { createSynthesisDeferral } from "../../src/composition/synthesisDeferral.js";
import type { AppOptions } from "../../src/composition/appOptions.js";
import type { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import type { AiControl } from "../../src/analysis/aiControl.js";
import { pollFor } from "../helpers/poll.js";

const CASE_ID = "case-watson-busy";

async function harness(debounceMs = 5) {
  const store = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-watson-busy-")));
  const jobManager = new JobManager({ perCaseConcurrency: 1 });
  const releases: (() => void)[] = [];
  const pipeline = {
    hasSynthesisProvider: () => true,
    synthesize: () => new Promise((resolve) => releases.push(() => resolve({}))),
  } as unknown as AnalysisPipeline;
  const options = {
    pipeline,
    jobManager,
    autoSynthesize: true,
    autoSynthesizeDebounceMs: debounceMs,
    synthMetaStore: { markOutOfDate: async () => undefined },
  } as unknown as AppOptions;
  const analysis = createCaptureAnalysis({
    store,
    options,
    hasAiProvider: () => true,
    getControl: async () => ({ enabled: true }) as AiControl,
    setControl: async () => ({ enabled: true }) as AiControl,
    recordAiError: () => {},
    autoEnrichIfEnabled: () => {},
    dispatchNotify: () => {},
  });
  return { analysis, jobManager, releases };
}

const job = (over: Partial<Job>): Job =>
  ({ id: "j1", caseId: CASE_ID, kind: "synthesis", status: "running", ...over }) as Job;

describe("synthesis busy check for Watson reactions", () => {
  it("a scheduled (debounced) kick is busy before any job exists", async () => {
    const { analysis } = await harness(60_000);
    expect(analysis.synthesisBusy(CASE_ID)).toBe(false);
    analysis.scheduleSynthesis(CASE_ID);
    expect(analysis.synthesisBusy(CASE_ID)).toBe(true);
  });

  it("a running synthesis is busy; once it finishes it is not", async () => {
    const { analysis, releases, jobManager } = await harness();
    analysis.resynthesizeInBackground(CASE_ID);
    await pollFor("the run to start", async () => (releases.length === 1 ? true : undefined));
    expect(analysis.synthesisBusy(CASE_ID)).toBe(true);
    releases[0]();
    await pollFor("the job to end", async () =>
      jobManager.hasActive(CASE_ID, "synthesis") ? undefined : true,
    );
    expect(analysis.synthesisBusy(CASE_ID)).toBe(false);
  });

  it("queued and running synthesis and Second Look jobs are busy; held, cancelled and done ones are not", () => {
    const busyWith = (jobs: Job[]) =>
      createSynthesisDeferral({ jobManager: { list: () => jobs, get: () => undefined }, retryMs: 5 }).busy(
        CASE_ID,
      );
    expect(busyWith([job({ status: "queued" })])).toBe(true);
    expect(busyWith([job({ status: "running" })])).toBe(true);
    expect(busyWith([job({ kind: "second-look", status: "queued" })])).toBe(true);
    expect(busyWith([job({ kind: "second-look", parameters: { resynthesize: false } })])).toBe(false);
    expect(busyWith([job({ status: "succeeded" })])).toBe(false);
    expect(
      busyWith([
        job({
          status: "cancelled",
          failure: {
            code: "held_for_analyst",
            message: "Presidio",
            retryable: false,
            at: "2026-11-01T00:00:00Z",
          },
        }),
      ]),
    ).toBe(false);
    expect(busyWith([job({ status: "cancelled" })])).toBe(false);
    expect(busyWith([job({ kind: "import", status: "running" })])).toBe(false);
  });

  it("a kick waiting behind a running synthesis is busy", () => {
    const jobs = [job({ status: "running" })];
    const deferral = createSynthesisDeferral({
      jobManager: { list: () => jobs, get: () => undefined },
      retryMs: 60_000,
    });
    deferral.defer(
      CASE_ID,
      () => undefined,
      () => undefined,
    );
    jobs.length = 0;
    expect(deferral.busy(CASE_ID), "the waiter still holds a follow-up run").toBe(true);
  });
});
