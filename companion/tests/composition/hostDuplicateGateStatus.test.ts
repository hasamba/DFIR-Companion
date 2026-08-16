// The merge gate is a question, not a crash — and the background re-synthesis path has to say so.
//
// resynthesizeInBackground() catches every throw from synthesize() in one block, so
// HostMergeDecisionRequired came out of it as `jobManager.fail()` plus ai_status "error". The
// analyst saw a red "AI: error" pill and a cockpit card reading "synthesis failed", with nothing
// anywhere naming the decision that was actually being waited on. Both halves are pinned here, and
// so is the case they must not weaken: a genuine failure still fails.
import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { JobManager } from "../../src/analysis/jobManager.js";
import { createCaptureAnalysis } from "../../src/composition/captureAnalysis.js";
import { HostMergeDecisionRequired } from "../../src/analysis/hostDuplicateGate.js";
import type { AppOptions } from "../../src/composition/appOptions.js";
import type { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import type { AiControl } from "../../src/analysis/aiControl.js";
import { pollFor } from "../helpers/poll.js";

const CASE_ID = "case-merge-gate";
const PAIRS = [{ canonical: "win11.windomain.local", other: "win11", reason: "shortname-fqdn" as const }];

async function harness(thrown: unknown) {
  const root = await mkdtemp(join(tmpdir(), "dfir-merge-gate-"));
  const store = new CaseStore(root);
  const jobManager = new JobManager({ perCaseConcurrency: 1 });

  const pipeline = {
    hasSynthesisProvider: () => true,
    // `throw`, not Promise.reject: same rejected promise, and it keeps the lint rule that insists a
    // rejection reason be an Error from arguing with a parameter typed `unknown` on purpose.
    synthesize: async () => {
      throw thrown;
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

  analysis.resynthesizeInBackground(CASE_ID);
  const settled = await pollFor(
    () =>
      `a terminal synthesis job, last saw ${jobManager
        .list(CASE_ID)
        .map((j) => j.status)
        .join(",")}`,
    async () => {
      const job = jobManager.list(CASE_ID).find((j) => j.kind === "synthesis");
      return job && job.status !== "queued" && job.status !== "running" ? job : undefined;
    },
  );
  return { statuses, job: settled };
}

describe("background re-synthesis held by the host-merge gate", () => {
  it("reports blocked rather than error", async () => {
    const { statuses } = await harness(new HostMergeDecisionRequired(PAIRS));
    const last = statuses[statuses.length - 1];
    expect(last.status).toBe("blocked");
    expect(last.detail).toContain("duplicate host");
    expect(statuses.map((s) => s.status)).not.toContain("error");
  });

  // "failed" is what put `synthesis failed` in the cockpit's Running/Failed Work list. The run never
  // failed — it was never allowed to start.
  it("does not leave a failed synthesis job behind", async () => {
    const { job } = await harness(new HostMergeDecisionRequired(PAIRS));
    expect(job?.status).not.toBe("failed");
    expect(job?.status).toBe("cancelled");
  });

  it("still reports a genuine synthesis failure as an error", async () => {
    const { statuses, job } = await harness(new Error("model returned 500"));
    const last = statuses[statuses.length - 1];
    expect(last.status).toBe("error");
    expect(last.detail).toContain("model returned 500");
    expect(job?.status).toBe("failed");
  });
});
