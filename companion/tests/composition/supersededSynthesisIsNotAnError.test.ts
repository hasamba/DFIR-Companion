// A superseded synthesis is a replaced queue entry, not a failed run.
//
// The registry already says so — dropForExclusiveRegistration REMOVES the row rather than marking
// it cancelled, "because a superseded job is a queue entry that was replaced, not a result". The
// live-synthesis path did not: settleSynthesisRejection recorded every non-gate rejection against
// the AI-error ledger, so an aborted run wrote "synthesis superseded by a newer run" there and lit
// the dashboard's AI-error badge over a case whose synthesis was proceeding normally in the run
// that replaced it.
//
// It only became reachable once synthesize() started honouring its abort signal at the stage
// boundaries (see analysis/ai/synthesis.ts) — before that a superseded run quietly ran to
// completion, which is the bug that fix exists to end.
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
import { countRegistrations } from "../helpers/jobRegistrations.js";

const CASE_ID = "case-superseded-synth";

function abortError(): Error {
  const err = new Error("synthesis superseded by a newer run");
  err.name = "AbortError";
  return err;
}

async function harness() {
  const root = await mkdtemp(join(tmpdir(), "dfir-superseded-"));
  const store = new CaseStore(root);
  const jobManager = new JobManager({ perCaseConcurrency: 1 });
  const kicks = countRegistrations(jobManager, "synthesis");

  // Stands in for the fixed synthesize(): it rejects at its next stage boundary once the run has
  // been superseded, and otherwise waits to be released.
  const started: string[] = [];
  const pipeline = {
    hasSynthesisProvider: () => true,
    synthesize: (caseId: string, opts: { signal?: AbortSignal } = {}) => {
      started.push(caseId);
      return new Promise((resolve, reject) => {
        if (opts.signal) opts.signal.addEventListener("abort", () => reject(abortError()));
        releases.push(() => resolve({}));
      });
    },
  } as unknown as AnalysisPipeline;
  const releases: (() => void)[] = [];

  const statuses: { status: string; detail?: string }[] = [];
  const aiErrors: { phase: string; err: unknown }[] = [];
  const options = {
    pipeline,
    jobManager,
    autoSynthesize: true,
    autoSynthesizeDebounceMs: 1,
    onAiStatus: (_caseId: string, s: { status: string; detail?: string }) => statuses.push(s),
  } as unknown as AppOptions;

  const analysis = createCaptureAnalysis({
    store,
    options,
    hasAiProvider: () => true,
    getControl: async () => ({ enabled: true }) as AiControl,
    setControl: async () => ({ enabled: true }) as AiControl,
    recordAiError: (_caseId: string, phase: string, err: unknown) => aiErrors.push({ phase, err }),
    autoEnrichIfEnabled: () => {},
    dispatchNotify: () => {},
  });

  return { analysis, jobManager, kicks, started, statuses, aiErrors, releases };
}

describe("a live synthesis superseded by a newer kick", () => {
  it("is not written to the AI-error ledger and does not paint the pill red", async () => {
    const { analysis, kicks, started, statuses, aiErrors, releases } = await harness();

    analysis.scheduleSynthesis(CASE_ID); // the debounced live run
    await kicks.waitFor(1);
    await pollFor("the live synthesis to reach the pipeline", async () =>
      started.length === 1 ? true : undefined,
    );

    analysis.resynthesizeInBackground(CASE_ID); // the newer kick supersedes it
    await kicks.waitFor(2);

    // The superseded run's rejection has to settle before anything can be asserted about it.
    await pollFor("the superseded run to settle", async () =>
      statuses.some((s) => s.status === "analyzing" && s.detail?.includes("re-synthesizing"))
        ? true
        : undefined,
    );
    await new Promise((r) => setTimeout(r, 50));

    expect(aiErrors).toEqual([]); // a supersede is not an AI failure
    expect(statuses.map((s) => s.status)).not.toContain("error");

    releases.forEach((release) => release()); // let the surviving run finish so nothing dangles
  });
});
