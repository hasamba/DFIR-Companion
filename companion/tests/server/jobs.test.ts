import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { JobLedgerStore } from "../../src/analysis/jobLedgerStore.js";
import { JobManager } from "../../src/analysis/jobManager.js";
import { pollFor } from "../helpers/poll.js";

async function makeApp(jobManager?: JobManager) {
  const root = await mkdtemp(join(tmpdir(), "dfir-jobs-"));
  const store = new CaseStore(root);
  const app = createApp(store, jobManager ? { jobManager } : {});
  return { app };
}

describe("/api/jobs", () => {
  it("returns an empty list when no jobManager is wired", async () => {
    const { app } = await makeApp();
    const res = await request(app).get("/api/jobs");
    expect(res.status).toBe(200);
    expect(res.body.jobs).toEqual([]);
  });

  it("lists jobs newest-first and filters by caseId", async () => {
    const jm = new JobManager();
    jm.register({ caseId: "c1", kind: "import" });
    jm.register({ caseId: "c2", kind: "synthesis", cancellable: true });
    jm.register({ caseId: "c1", kind: "enrichment", cancellable: true });
    const { app } = await makeApp(jm);

    const all = await request(app).get("/api/jobs");
    expect(all.body.jobs.map((j: { kind: string }) => j.kind)).toEqual(["enrichment", "synthesis", "import"]);

    const c1 = await request(app).get("/api/jobs").query({ caseId: "c1" });
    expect(c1.body.jobs.map((j: { kind: string }) => j.kind)).toEqual(["enrichment", "import"]);
  });

  it("GET /api/jobs/:id returns the job or 404", async () => {
    const jm = new JobManager();
    const { jobId } = jm.register({ caseId: "c1", kind: "synthesis", cancellable: true });
    const { app } = await makeApp(jm);

    const ok = await request(app).get(`/api/jobs/${jobId}`);
    expect(ok.status).toBe(200);
    expect(ok.body.id).toBe(jobId);

    const missing = await request(app).get("/api/jobs/nope");
    expect(missing.status).toBe(404);
  });

  it("cancels a cancellable running job (200) and aborts its signal", async () => {
    const jm = new JobManager();
    const { jobId, signal } = jm.register({ caseId: "c1", kind: "synthesis", cancellable: true });
    const { app } = await makeApp(jm);

    const res = await request(app).post(`/api/jobs/${jobId}/cancel`);
    expect(res.status).toBe(200);
    expect(res.body.status).toBe("cancelled");
    expect(signal!.aborted).toBe(true);
  });

  it("rejects cancelling a non-cancellable job (422) and an unknown job (404)", async () => {
    const jm = new JobManager();
    const { jobId } = jm.register({ caseId: "c1", kind: "import" }); // deterministic → not cancellable
    const { app } = await makeApp(jm);

    expect((await request(app).post(`/api/jobs/${jobId}/cancel`)).status).toBe(422);
    expect((await request(app).post("/api/jobs/nope/cancel")).status).toBe(404);
  });

  it("rejects cancelling an already-finished job (409)", async () => {
    const jm = new JobManager();
    const { jobId } = jm.register({ caseId: "c1", kind: "synthesis", cancellable: true });
    await jm.finish(jobId);
    const { app } = await makeApp(jm);

    expect((await request(app).post(`/api/jobs/${jobId}/cancel`)).status).toBe(409);
  });

  it("returns 501 for cancel when no jobManager is wired", async () => {
    const { app } = await makeApp();
    expect((await request(app).post("/api/jobs/anything/cancel")).status).toBe(501);
  });

  it("resumes a restart-interrupted job through the API", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-jobs-resume-"));
    const store = new CaseStore(root);
    await store.createCase({
      caseId: "c1",
      name: "Case",
      investigator: "analyst",
      aiProvider: null,
    });
    const ledger = new JobLedgerStore(store);
    const firstManager = new JobManager({ ledger, id: () => "job_stable" });
    await firstManager.ready();
    const started = firstManager.register({
      caseId: "c1",
      kind: "deep-pass",
      resumable: true,
      maxRetries: 1,
    });
    await started.ready;

    const restarted = new JobManager({ ledger });
    await restarted.ready();
    const app = createApp(store, { jobManager: restarted });
    restarted.registerResumeHandler("deep-pass", async () => {});

    const response = await request(app).post("/api/jobs/job_stable/resume");

    expect(response.status).toBe(202);
    expect(response.body).toMatchObject({
      id: "job_stable",
      status: "queued",
      attempt: 2,
    });
    await pollFor("API-resumed job succeeding", async () => {
      return restarted.get("job_stable")?.status === "succeeded" ? true : undefined;
    });
  });
});
