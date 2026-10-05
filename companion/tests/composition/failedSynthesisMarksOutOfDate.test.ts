// #1953: a background synthesis that fails leaves the conclusions behind the evidence. The pill
// shows "error" only while that failed job is the latest ended job; one later clean job (an
// enrichment, an import) used to turn it back to "up to date" over conclusions the model never
// refreshed. A genuine failure now sets the #1599 out-of-date marker. An analyst cancel, a
// supersede and an analyst-decision gate are not failures and set nothing on this path.
//
// Both callers of settleSynthesisRejection are driven: a past fix covered only one of them.
import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { JobManager } from "../../src/analysis/jobManager.js";
import { SynthMetaStore } from "../../src/analysis/synthMeta.js";
import { HostMergeDecisionRequired } from "../../src/analysis/hostDuplicateGate.js";
import { createCaptureAnalysis } from "../../src/composition/captureAnalysis.js";
import type { AppOptions } from "../../src/composition/appOptions.js";
import type { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import type { AiControl } from "../../src/analysis/aiControl.js";
import { pollFor } from "../helpers/poll.js";

const CASE_ID = "c1953";
const PAIRS = [{ canonical: "win11.example.com", other: "win11", reason: "shortname-fqdn" as const }];
const FAILED_REASON = "last synthesis failed";

type Behaviour = { kind: "reject"; err: unknown } | { kind: "wait" };

async function harness(behaviour: Behaviour) {
  const root = await mkdtemp(join(tmpdir(), "dfir-failed-synth-"));
  const store = new CaseStore(root);
  await store.createCase({ caseId: CASE_ID, name: "n", investigator: "i", aiProvider: null });
  const synthMetaStore = new SynthMetaStore(store);
  const jobManager = new JobManager({ perCaseConcurrency: 1 });

  const pipeline = {
    hasSynthesisProvider: () => true,
    synthesize: async (_caseId: string, opts: { signal?: AbortSignal } = {}) => {
      if (behaviour.kind === "reject") throw behaviour.err;
      // Waits until the job is cancelled, then rejects the way synthesize() does on an abort.
      await new Promise<void>((_resolve, reject) => {
        opts.signal?.addEventListener("abort", () => {
          const err = new Error("synthesis cancelled");
          err.name = "AbortError";
          reject(err);
        });
      });
      return {};
    },
  } as unknown as AnalysisPipeline;

  const statuses: { status: string; detail?: string }[] = [];
  const options = {
    pipeline,
    jobManager,
    synthMetaStore,
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
    recordAiError: () => {},
    autoEnrichIfEnabled: () => {},
    dispatchNotify: () => {},
  });

  const synthJob = () => jobManager.list(CASE_ID).find((j) => j.kind === "synthesis");
  const settled = () =>
    pollFor("a terminal synthesis job and its status push", async () => {
      const j = synthJob();
      const terminal = j && j.status !== "queued" && j.status !== "running";
      const pushed = statuses.some((s) => s.status !== "analyzing");
      return terminal && pushed ? j : undefined;
    });
  const marker = async () => (await synthMetaStore.load(CASE_ID)).outOfDate ?? null;

  return { analysis, jobManager, statuses, synthJob, settled, marker };
}

const PATHS = [
  [
    "live (debounced) synthesis",
    (h: Awaited<ReturnType<typeof harness>>) => h.analysis.scheduleSynthesis(CASE_ID),
  ],
  [
    "background re-synthesis",
    (h: Awaited<ReturnType<typeof harness>>) => h.analysis.resynthesizeInBackground(CASE_ID),
  ],
] as const;

describe.each(PATHS)("a failed %s (#1953)", (_name, start) => {
  it("marks the conclusions out of date before it pushes the error", async () => {
    const h = await harness({ kind: "reject", err: new Error("provider timeout") });
    start(h);
    await h.settled();
    expect((await h.marker())?.reason).toBe(FAILED_REASON);
    const last = h.statuses[h.statuses.length - 1];
    expect(last).toMatchObject({ status: "error", detail: "provider timeout" });
  });

  it("does not mark when the run is held at the host-merge gate", async () => {
    const h = await harness({ kind: "reject", err: new HostMergeDecisionRequired(PAIRS) });
    start(h);
    await h.settled();
    expect(await h.marker()).toBeNull();
  });

  it("does not mark when the analyst cancels the run", async () => {
    const h = await harness({ kind: "wait" });
    start(h);
    const job = await pollFor("a running synthesis job", async () =>
      h.synthJob()?.status === "running" ? h.synthJob() : undefined,
    );
    await h.jobManager.cancel(job!.id);
    await h.settled();
    expect(await h.marker()).toBeNull();
  });
});

describe("a superseded synthesis (#1953)", () => {
  it("does not mark the conclusions out of date", async () => {
    const h = await harness({ kind: "wait" });
    h.analysis.scheduleSynthesis(CASE_ID);
    await pollFor("the live synthesis to run", async () =>
      h.synthJob()?.status === "running" ? true : undefined,
    );
    // An analyst "run now" supersedes the live run (#1608: an automatic kick would wait instead).
    h.analysis.resynthesizeInBackground(CASE_ID, { analyst: true });
    await pollFor("the newer run to register", async () =>
      h.jobManager.list(CASE_ID).filter((j) => j.kind === "synthesis").length >= 1 &&
      h.statuses.some((s) => s.detail?.includes("re-synthesizing"))
        ? true
        : undefined,
    );
    await new Promise((r) => setTimeout(r, 50));
    expect(await h.marker()).toBeNull();
    // Release the surviving run so nothing dangles.
    for (const j of h.jobManager.list(CASE_ID)) {
      if (j.status === "running" || j.status === "queued") await h.jobManager.cancel(j.id);
    }
  });
});
