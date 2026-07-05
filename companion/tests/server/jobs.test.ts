import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { JobManager } from "../../src/analysis/jobManager.js";

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
    jm.finish(jobId);
    const { app } = await makeApp(jm);

    expect((await request(app).post(`/api/jobs/${jobId}/cancel`)).status).toBe(409);
  });

  it("returns 501 for cancel when no jobManager is wired", async () => {
    const { app } = await makeApp();
    expect((await request(app).post("/api/jobs/anything/cancel")).status).toBe(501);
  });
});
