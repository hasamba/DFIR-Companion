// #1976: an analyst-pressed synthesis that fails leaves the conclusions behind the evidence, the same
// way a failed background run does (#1953). The Re-synthesize button (POST /synthesize) and the
// Analysis runs "Replay" of a synthesis run used to fail without the out-of-date marker, so one
// later clean job (an enrichment, an import) turned the pill back to "up to date" over conclusions
// the model never refreshed. A genuine failure now marks. A held run (analyst-decision gate) and an
// analyst cancel are not failures and mark nothing.
import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { AssetOverridesStore } from "../../src/analysis/assetOverrides.js";
import { HostDuplicateDismissalStore } from "../../src/analysis/hostDuplicateDismissals.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { JobManager } from "../../src/analysis/jobManager.js";
import { SynthMetaStore } from "../../src/analysis/synthMeta.js";
import { AnalysisRunStore } from "../../src/analysis/analysisRunStore.js";
import { hashManifestValue } from "../../src/analysis/analysisRunHash.js";
import { getSynthesisPrompt } from "../../src/analysis/pipeline.js";
import { HostMergeDecisionRequired } from "../../src/analysis/hostDuplicateGate.js";
import { createApp } from "../../src/server.js";
import { pollFor } from "../helpers/poll.js";

const CASE_ID = "c1";
const FAILED_REASON = "last synthesis failed";
const PAIRS = [{ canonical: "win11.example.com", other: "win11", reason: "shortname-fqdn" as const }];

type Behaviour = { kind: "reject"; err: unknown } | { kind: "wait" };

let app: ReturnType<typeof createApp>;
let jobManager: JobManager;
let synthMetaStore: SynthMetaStore;
let analysisRunStore: AnalysisRunStore;
let behaviour: Behaviour;

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-synth-route-fail-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: CASE_ID, name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(cases);
  const assetOverridesStore = new AssetOverridesStore(cases);
  const hostDuplicateDismissalStore = new HostDuplicateDismissalStore(cases);
  jobManager = new JobManager({ perCaseConcurrency: 1 });
  synthMetaStore = new SynthMetaStore(cases);
  analysisRunStore = new AnalysisRunStore(cases, { appVersion: "0.33.0" });
  behaviour = { kind: "reject", err: new Error("provider timeout") };

  const pipeline = new AnalysisPipeline({
    stateStore,
    assetOverridesStore,
    hostDuplicateDismissalStore,
    // Configured so the route runs; never called, because synthesize() is stubbed below.
    synthesisProvider: { name: "fake", analyze: async () => "" } as never,
    imageLoader: async () => ({ data: Buffer.from(""), mediaType: "image/png" }) as never,
  });
  // The run itself is stubbed: this file is about what the ROUTE does when it rejects.
  pipeline.synthesize = (async (_caseId: string, opts: { signal?: AbortSignal } = {}) => {
    if (behaviour.kind === "reject") throw behaviour.err;
    await new Promise<void>((_resolve, reject) => {
      opts.signal?.addEventListener("abort", () => {
        const err = new Error("synthesis cancelled");
        err.name = "AbortError";
        reject(err);
      });
    });
    return {};
  }) as unknown as AnalysisPipeline["synthesize"];

  app = createApp(cases, {
    pipeline,
    stateStore,
    assetOverridesStore,
    hostDuplicateDismissalStore,
    jobManager,
    synthMetaStore,
    analysisRunStore,
    appVersion: "0.33.0",
  });

  // An earlier synthesis exists: a case with no conclusions hides the marker (effectiveOutOfDate).
  await synthMetaStore.record(
    CASE_ID,
    { added: [], removed: [], severityChanged: [] },
    "2026-10-01T10:00:00Z",
  );
});

const marker = async () => (await synthMetaStore.load(CASE_ID)).outOfDate ?? null;

/** A later clean job — the one that used to turn the pill back to "up to date". */
async function finishCleanEnrichment(): Promise<void> {
  const job = jobManager.register({ caseId: CASE_ID, kind: "enrichment", label: "enrichment" });
  await job.ready;
  await jobManager.finish(job.jobId);
}

describe("a failed POST /cases/:id/synthesize (#1976)", () => {
  it("marks the conclusions out of date, and a later clean job does not hide it", async () => {
    const res = await request(app).post(`/cases/${CASE_ID}/synthesize`).send({});
    expect(res.status).toBe(500);
    expect((await marker())?.reason).toBe(FAILED_REASON);

    await finishCleanEnrichment();
    const state = await request(app).get(`/cases/${CASE_ID}/ai-state`);
    expect(state.status).toBe(200);
    expect(state.body.outOfDate).toBe(true);
  });

  it("does not mark when the run is held at the host-merge gate", async () => {
    behaviour = { kind: "reject", err: new HostMergeDecisionRequired(PAIRS) };
    const res = await request(app).post(`/cases/${CASE_ID}/synthesize`).send({});
    expect(res.status).toBe(409);
    expect(await marker()).toBeNull();
  });

  it("does not mark when the analyst cancels the run", async () => {
    behaviour = { kind: "wait" };
    const pending = request(app)
      .post(`/cases/${CASE_ID}/synthesize`)
      .send({})
      .then((r) => r);
    const job = await pollFor("a running synthesis job", async () =>
      jobManager.list(CASE_ID).find((j) => j.kind === "synthesis" && j.status === "running"),
    );
    await jobManager.cancel(job.id);
    expect((await pending).status).toBe(499);
    expect(await marker()).toBeNull();
  });
});

describe("a failed synthesis replay (#1976)", () => {
  it("marks the conclusions out of date", async () => {
    await analysisRunStore.record(CASE_ID, {
      id: "synth-parent",
      kind: "synthesis",
      startedAt: "2026-10-01T10:00:00.000Z",
      finishedAt: "2026-10-01T10:00:01.000Z",
      versions: { schema: "synthesis/v1" },
      input: { artifacts: [], eventIds: [], entityIds: [] },
      configuration: { promptHash: hashManifestValue(getSynthesisPrompt()) },
      output: { entityIds: [], hashes: [], claims: [] },
    });
    const res = await request(app).post(`/cases/${CASE_ID}/analysis-runs/synth-parent/replay`);
    expect(res.status).toBe(500);
    expect((await marker())?.reason).toBe(FAILED_REASON);
  });
});
