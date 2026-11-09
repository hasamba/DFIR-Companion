// #2425: the Sigma re-grade apply rewrites and demotes forensic rows. It now runs as a job, so it
// takes the case's one-job slot (it can no longer rewrite rows under a running synthesis), shows in
// the Jobs panel and counts as "busy". Not cancellable. Harness from sigmaRegradeRoutes.test.ts.
import { describe, it, expect, beforeEach, vi } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { StateLock } from "../../src/analysis/stateLock.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { ImportMetaStore } from "../../src/analysis/importMeta.js";
import { ForensicGateControlStore } from "../../src/analysis/forensicGateControl.js";
import { ActivityLogStore } from "../../src/analysis/activityLog.js";
import { SynthMetaStore } from "../../src/analysis/synthMeta.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { createApp } from "../../src/server.js";
import { parseCloudTrail } from "../../src/analysis/awsImport.js";
import { loadBundledSigmaRuleSet } from "../../src/analysis/sigmaBundledRules.js";
import { createSigmaImportGrader } from "../../src/analysis/sigmaImportGrade.js";
import { splitSigmaOverlay } from "../../src/analysis/sigmaRegrade.js";
import type { SigmaRuleSet } from "../../src/analysis/sigmaRuleSet.js";
import { JobManager } from "../../src/analysis/jobManager.js";
import { ImportLock } from "../../src/analysis/importLock.js";
import { isTerminal, type JobStatus } from "../../src/analysis/jobRegistry.js";
import { pollFor } from "../helpers/poll.js";

const ct = (i: number, o: Record<string, unknown>) => ({
  eventVersion: "1.08",
  eventTime: `2026-03-01T10:00:0${i}Z`,
  awsRegion: "us-east-1",
  sourceIPAddress: "198.51.100.7",
  userAgent: "aws-cli/2.15.0",
  userIdentity: {
    type: "IAMUser",
    userName: "alice",
    accountId: "111122223333",
    arn: "arn:aws:iam::111122223333:user/alice",
  },
  recipientAccountId: "111122223333",
  readOnly: false,
  eventID: `id-${i}`,
  ...o,
});

const TEXT = JSON.stringify({
  Records: [
    ct(1, { eventSource: "securityhub.amazonaws.com", eventName: "BatchUpdateFindings" }),
    ct(2, { eventSource: "cloudtrail.amazonaws.com", eventName: "StopLogging" }),
  ],
});

const { set: SET_ON } = loadBundledSigmaRuleSet();
const graded = parseCloudTrail(TEXT, { sigma: createSigmaImportGrader(SET_ON).snapshot() }).events.find((e) =>
  /BatchUpdateFindings/.test(e.description),
)!;
const RULE_ID = splitSigmaOverlay(graded.description, graded.message).ruleIds[0];
const { set: SET_OFF } = loadBundledSigmaRuleSet({ disabled: new Map([[RULE_ID, "noisy here"]]) });

let rules: SigmaRuleSet;
let cases: CaseStore;
let stateStore: StateStore;
let meta: SynthMetaStore;

type StatusPush = { status: string; jobStatus?: JobStatus };

function build(jobManager: JobManager, pushes: StatusPush[] = [], importLock?: ImportLock) {
  const stateLock = new StateLock();
  const pipeline = new AnalysisPipeline({
    stateStore,
    stateLock,
    sigmaGrader: createSigmaImportGrader(() => rules),
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const regradeStatus = () => jobManager.list("c1").find((j) => j.kind === "sigma-regrade")?.status;
  const app = createApp(cases, {
    pipeline,
    stateStore,
    stateLock,
    superTimelineStore: new SuperTimelineStore(cases),
    importMetaStore: new ImportMetaStore(cases),
    forensicGateControlStore: new ForensicGateControlStore(cases),
    activityLogStore: new ActivityLogStore(cases),
    synthMetaStore: meta,
    jobManager,
    ...(importLock ? { importLock } : {}),
    onAiStatus: (_caseId: string, s: { status: string }) =>
      void pushes.push({ status: s.status, jobStatus: regradeStatus() }),
  });
  return { app, pipeline };
}

async function importTrail(app: ReturnType<typeof createApp>): Promise<void> {
  const res = await request(app)
    .post("/cases/c1/import-aws")
    .send({ filename: "cloudtrail.json", text: TEXT });
  expect(res.status).toBe(202);
  await pollFor("the CloudTrail import to settle", async () => {
    const m = await new ImportMetaStore(cases).load("c1");
    return m.lastImportKind === "aws" ? m : undefined;
  });
}

const regradeJobs = (jm: JobManager) => jm.list("c1").filter((j) => j.kind === "sigma-regrade");
const target = async () =>
  (await stateStore.load("c1")).forensicTimeline.find((e) => /BatchUpdateFindings/.test(e.description));
const importsIdle = (jm: JobManager) =>
  pollFor("the import job to end", async () =>
    jm.list("c1").every((j) => isTerminal(j.status)) ? true : undefined,
  );

beforeEach(async () => {
  cases = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-sigma-regrade-job-")));
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  stateStore = new StateStore(cases);
  meta = new SynthMetaStore(cases);
  await meta.record("c1", null as never, "2026-03-01T12:00:00.000Z");
  rules = SET_ON;
});

describe("POST /cases/:id/sigma/regrade runs as a job (#2425)", () => {
  it("creates one sigma-regrade job, succeeded after the 200, labelled with the release", async () => {
    const jobManager = new JobManager();
    const { app } = build(jobManager);
    await importTrail(app);
    rules = SET_OFF;
    const res = await request(app).post("/cases/c1/sigma/regrade").send({});
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body).not.toHaveProperty("changed");
    const jobs = regradeJobs(jobManager);
    expect(jobs).toHaveLength(1);
    expect(jobs[0]).toMatchObject({
      status: "succeeded",
      cancellable: false,
      label: `Sigma re-grade (SigmaHQ ${SET_ON.release})`,
    });
  });

  it("waits behind a job already holding the case's slot and rewrites nothing meanwhile", async () => {
    const jobManager = new JobManager({ globalConcurrency: 1, perCaseConcurrency: 1 });
    const { app } = build(jobManager);
    await importTrail(app);
    await importsIdle(jobManager);
    const before = await target();
    expect(before?.severity).toBe("High");
    const busy = jobManager.register({ caseId: "c1", kind: "synthesis", label: "synthesis" });
    await busy.ready;
    rules = SET_OFF;

    const pending = request(app)
      .post("/cases/c1/sigma/regrade")
      .send({})
      .then((r) => r);
    await pollFor("the re-grade to queue", async () =>
      regradeJobs(jobManager).find((j) => j.status === "queued") ? true : undefined,
    );
    expect(await target()).toEqual(before);

    await jobManager.finish(busy.jobId);
    const res = await pending;
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.counts.lowered).toBe(1);
    expect(regradeJobs(jobManager)[0]?.status).toBe("succeeded");
  });

  it("marks the conclusions out of date after its job ends, so the header gets its idle push", async () => {
    const jobManager = new JobManager();
    const pushes: StatusPush[] = [];
    const { app } = build(jobManager, pushes);
    await importTrail(app);
    await importsIdle(jobManager);
    rules = SET_OFF;
    pushes.length = 0;
    const res = await request(app).post("/cases/c1/sigma/regrade").send({});
    expect(res.status).toBe(200);
    expect((await meta.load("c1")).outOfDate?.reason).toBe("Sigma re-grade");
    const ai = await request(app).get("/cases/c1/ai-state");
    expect(ai.body.outOfDate, JSON.stringify(ai.body)).toBe(true);
    expect(pushes).toContainEqual({ status: "idle", jobStatus: "succeeded" });
  });

  it("an apply that throws fails the job with sigma_regrade_failed", async () => {
    const jobManager = new JobManager();
    const { app } = build(jobManager);
    await importTrail(app);
    rules = SET_OFF;
    vi.spyOn(AnalysisPipeline.prototype, "mergeSigmaRegrade").mockRejectedValueOnce(
      new Error("injected merge failure"),
    );
    const res = await request(app).post("/cases/c1/sigma/regrade").send({});
    vi.restoreAllMocks();
    expect(res.status).toBe(500);
    expect(regradeJobs(jobManager)[0]).toMatchObject({
      status: "failed",
      failure: { code: "sigma_regrade_failed" },
    });
  });

  it("a duplicate POST still answers 409 and creates no second job row", async () => {
    const jobManager = new JobManager({ globalConcurrency: 1, perCaseConcurrency: 1 });
    const { app } = build(jobManager);
    await importTrail(app);
    await importsIdle(jobManager);
    const busy = jobManager.register({ caseId: "c1", kind: "synthesis", label: "synthesis" });
    await busy.ready;
    rules = SET_OFF;
    const first = request(app)
      .post("/cases/c1/sigma/regrade")
      .send({})
      .then((r) => r);
    await pollFor("the first re-grade to queue", async () =>
      regradeJobs(jobManager).length ? true : undefined,
    );
    const second = await request(app).post("/cases/c1/sigma/regrade").send({});
    expect(second.status).toBe(409);
    expect(regradeJobs(jobManager)).toHaveLength(1);
    await jobManager.finish(busy.jobId);
    expect((await first).status).toBe(200);
  });
});

// #2437: the closed-case refusal ran once, before the re-grade waited for its job slot and its
// import section. A re-grade queued behind a synthesis was admitted once closing the case cancelled
// that synthesis, and then rewrote severities in the closed case. It is checked again after each wait.
describe("a re-grade admitted after the case closed is refused (#2437)", () => {
  const close = (app: ReturnType<typeof createApp>) =>
    request(app).patch("/cases/c1/status").send({ status: "closed" });

  it("queued behind a synthesis that closing cancels: 423, nothing rewritten, job not left running", async () => {
    const jobManager = new JobManager({ globalConcurrency: 1, perCaseConcurrency: 1 });
    const { app } = build(jobManager);
    await importTrail(app);
    await importsIdle(jobManager);
    const before = await target();
    const busy = jobManager.register({
      caseId: "c1",
      kind: "synthesis",
      label: "synthesis",
      cancellable: true,
    });
    await busy.ready;
    rules = SET_OFF;

    const pending = request(app)
      .post("/cases/c1/sigma/regrade")
      .send({})
      .then((r) => r);
    await pollFor("the re-grade to queue", async () =>
      regradeJobs(jobManager).find((j) => j.status === "queued") ? true : undefined,
    );
    expect((await close(app)).status).toBe(200);
    expect(jobManager.get(busy.jobId)?.status).toBe("cancelled");

    const res = await pending;
    expect(res.status, JSON.stringify(res.body)).toBe(423);
    expect(res.body.error).toMatch(/closed/);
    expect(await target()).toEqual(before);
    const job = regradeJobs(jobManager)[0];
    expect(isTerminal(job.status), job.status).toBe(true);
    expect(job).toMatchObject({ status: "failed", failure: { code: "case_frozen" } });
  });

  it("waiting on the import section while the case closes: 423 and nothing rewritten", async () => {
    const jobManager = new JobManager();
    const importLock = new ImportLock();
    const { app } = build(jobManager, [], importLock);
    await importTrail(app);
    await importsIdle(jobManager);
    const before = await target();
    rules = SET_OFF;
    const release = await importLock.acquire("c1");

    const pending = request(app)
      .post("/cases/c1/sigma/regrade")
      .send({})
      .then((r) => r);
    await pollFor("the re-grade to hold its job slot", async () =>
      regradeJobs(jobManager).find((j) => j.status === "running") ? true : undefined,
    );
    expect((await close(app)).status).toBe(200);
    release();

    const res = await pending;
    expect(res.status, JSON.stringify(res.body)).toBe(423);
    expect(await target()).toEqual(before);
    expect(regradeJobs(jobManager)[0]).toMatchObject({ status: "failed", failure: { code: "case_frozen" } });
  });
});
