import { describe, it, expect, beforeEach, afterEach } from "vitest";
import request from "supertest";
import { JobManager } from "../../src/analysis/jobManager.js";
import { isHeldJob } from "../../src/analysis/jobRegistry.js";
import { resetLimiters } from "../../src/http/rateLimiter.js";
import { pollFor } from "../helpers/poll.js";
import {
  JEV_JOB_ENV,
  JEV_TEST_MODEL,
  jevJobCase,
  startJevStub,
  type JevMode,
} from "../helpers/jevJobHarness.js";

// #2425: the per-finding containment check is a paid Jev call. It now runs as a job: it shows in
// the Jobs panel, counts as "busy", and takes the case's one-job slot. Not cancellable.

const PATH = "/cases/c1/findings/f1/containment-check";

describe("POST /cases/:id/findings/:findingId/containment-check runs as a job (#2425)", () => {
  const saved: Record<string, string | undefined> = {};
  let mode: JevMode;
  let stub: { close: () => Promise<void> };

  beforeEach(async () => {
    resetLimiters();
    for (const k of JEV_JOB_ENV) saved[k] = process.env[k];
    delete process.env.DFIR_ANONYMIZE;
    mode = "answer";
    stub = await startJevStub(() => mode);
  });

  afterEach(async () => {
    for (const k of JEV_JOB_ENV) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
    await stub.close();
  });

  const checkJob = (jm: JobManager) => jm.list("c1").find((j) => j.kind === "containment-check");
  const settled = (jm: JobManager, status: string) =>
    pollFor(`the containment-check job to be ${status}`, async () =>
      checkJob(jm)?.status === status ? checkJob(jm) : undefined,
    );

  it("a check that answers ends succeeded, not cancellable, carrying the Jev model", async () => {
    const jobManager = new JobManager();
    const { app } = await jevJobCase({ jobManager });
    const res = await request(app).post(PATH).send({});
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    const job = await settled(jobManager, "succeeded");
    expect(job).toMatchObject({
      cancellable: false,
      label: "containment check (finding f1)",
      model: JEV_TEST_MODEL,
      modelProvider: "jev",
    });
  });

  it("an unknown finding answers 404 and fails the job instead of leaving it running", async () => {
    const jobManager = new JobManager();
    const { app } = await jevJobCase({ jobManager });
    const res = await request(app).post("/cases/c1/findings/nope/containment-check").send({});
    expect(res.status).toBe(404);
    const job = await settled(jobManager, "failed");
    expect(job?.failure?.code).toBe("finding_not_found");
  });

  it("a provider failure (502) fails the job", async () => {
    mode = "refuse";
    const jobManager = new JobManager();
    const { app } = await jevJobCase({ jobManager });
    const res = await request(app).post(PATH).send({});
    expect(res.status).toBe(502);
    const job = await settled(jobManager, "failed");
    expect(job?.failure?.code).toBe("containment_check_failed");
  });

  it("a Presidio approval hold holds the job instead of failing it", async () => {
    const jobManager = new JobManager();
    const { app } = await jevJobCase({ jobManager, presidioFlags: true });
    const res = await request(app).post(PATH).send({});
    expect(res.status).toBe(409);
    const job = await settled(jobManager, "cancelled");
    expect(isHeldJob(job)).toBe(true);
  });

  it("waits behind a job already holding the case's slot", async () => {
    const jobManager = new JobManager({ globalConcurrency: 1, perCaseConcurrency: 1 });
    const { app } = await jevJobCase({ jobManager });
    const busy = jobManager.register({ caseId: "c1", kind: "synthesis", label: "synthesis" });
    await busy.ready;

    let answered = false;
    const pending = request(app)
      .post(PATH)
      .send({})
      .then((r) => ((answered = true), r));
    await settled(jobManager, "queued");
    expect(answered).toBe(false);

    await jobManager.finish(busy.jobId);
    const res = await pending;
    expect(res.status).toBe(200);
    await settled(jobManager, "succeeded");
  });
});
