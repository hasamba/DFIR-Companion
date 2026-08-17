// A multi-file import must produce ONE synthesis run, not one per file.
//
// The dashboard's import picker takes multiple files and POSTs them one at a time
// (public/js/dashboard-unified-import.js), and every completed import fires
// resynthesizeInBackground(). With perCaseConcurrency = 1 those kicks cannot run concurrently, so
// without supersede semantics they stack up in the queue — the reported bug was six "synthesis is
// queued / re-synthesis" cards in the cockpit for one six-file import, each of which would have run
// a full LLM synthesis of the same case.
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

const CASE_ID = "case-multi-import";

async function harness() {
  const root = await mkdtemp(join(tmpdir(), "dfir-resynth-"));
  const store = new CaseStore(root);
  // perCaseConcurrency: 1 without a ledger — the production default when the durable ledger is
  // wired (jobManager.ts), and what makes the kicks queue instead of running side by side.
  const jobManager = new JobManager({ perCaseConcurrency: 1 });
  const kicks = countRegistrations(jobManager, "synthesis");

  const synthesized: string[] = [];
  let releaseSynthesis: () => void = () => {};
  const pipeline = {
    hasSynthesisProvider: () => true,
    synthesize: (caseId: string) => {
      synthesized.push(caseId);
      return new Promise((resolve) => {
        releaseSynthesis = () => resolve({});
      });
    },
  } as unknown as AnalysisPipeline;

  const statuses: { status: string; detail?: string }[] = [];
  const options = {
    pipeline,
    jobManager,
    onAiStatus: (_caseId: string, s: { status: string; detail?: string }) => statuses.push(s),
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

  return {
    analysis,
    jobManager,
    kicks,
    synthesized,
    statuses,
    releaseSynthesis: () => releaseSynthesis(),
  };
}

const KICKS = 6;

const synthesisJobs = (jm: JobManager) => jm.list(CASE_ID).filter((j) => j.kind === "synthesis");

describe("re-synthesis after a multi-file import", () => {
  it("collapses one kick per imported file into a single surviving synthesis job", async () => {
    const { analysis, jobManager, kicks, synthesized, releaseSynthesis } = await harness();

    // Occupy the case's single concurrency slot the way an in-flight import does, so the kicks
    // queue behind it exactly as they did in the bug report.
    const importJob = jobManager.register({ caseId: CASE_ID, kind: "import", label: "evtx" });
    await importJob.ready;

    // Six files in one import → six kicks.
    for (let i = 0; i < KICKS; i++) analysis.resynthesizeInBackground(CASE_ID);
    await kicks.waitFor(KICKS);

    // ONE row, and no wreckage beside it. A superseded kick is REMOVED, not marked `cancelled`:
    // that status is what the ✕ Cancel button produces, so five of them read as five aborts the
    // analyst never ordered — and they crowd the still-queued import out of the jobs popover,
    // which renders a bounded number of rows newest-first.
    const live = synthesisJobs(jobManager);
    expect(live).toHaveLength(1); // the other five superseded each other
    expect(live[0].status).toBe("queued");
    expect(synthesized).toEqual([]); // nothing runs while the import still holds the slot

    // Import finishes → the one surviving kick is admitted and runs once.
    await jobManager.finish(importJob.jobId);
    await pollFor(
      () => `the surviving run to synthesize, last saw ${JSON.stringify(synthesized)}`,
      async () => (synthesized.length > 0 ? true : undefined),
    );
    expect(synthesized).toEqual([CASE_ID]);

    releaseSynthesis();
  });

  it("does not report 'synthesis cancelled' while a newer kick still owns the case", async () => {
    const { analysis, jobManager, kicks, statuses, releaseSynthesis } = await harness();

    const importJob = jobManager.register({ caseId: CASE_ID, kind: "import", label: "evtx" });
    await importJob.ready;
    for (let i = 0; i < KICKS; i++) analysis.resynthesizeInBackground(CASE_ID);
    await kicks.waitFor(KICKS);
    // Give every superseded kick's rejection handler a turn to run before asserting on silence.
    await pollFor(
      () => `${KICKS - 1} superseded kicks, last saw ${KICKS - synthesisJobs(jobManager).length}`,
      async () => (synthesisJobs(jobManager).length === 1 ? true : undefined),
    );

    // A superseded kick must stay silent: the newer run owns the AI status banner, and stomping it
    // to idle leaves the dashboard claiming the case is idle while synthesis is still pending.
    expect(statuses.map((s) => s.detail)).not.toContain("synthesis cancelled");
    expect(statuses.filter((s) => s.status === "idle")).toEqual([]);

    releaseSynthesis();
  });
});
