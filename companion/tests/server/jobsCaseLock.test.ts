import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { JobManager } from "../../src/analysis/jobManager.js";

// /api/jobs sits outside /cases/:id, so the per-case password gate never covered it. A job row
// carries a label and stored file names, which are case evidence: a locked case's jobs stay
// hidden until this browser has unlocked that case.

const PASSWORD = "correct-horse";

async function harness() {
  const jobManager = new JobManager({ perCaseConcurrency: 1, globalConcurrency: 1 });
  await jobManager.ready();
  const root = await mkdtemp(join(tmpdir(), "dfir-jobs-lock-"));
  const store = new CaseStore(root);
  const app = createApp(store, { jobManager });
  for (const caseId of ["LOCKED-1", "OPEN-1"]) {
    await request(app).post("/cases").send({ caseId, name: caseId, investigator: "alice" }).expect(201);
  }
  const locked = jobManager.register({
    caseId: "LOCKED-1",
    kind: "import",
    label: "secret-label",
    files: ["secret-evidence.evtx"],
  });
  const open = jobManager.register({ caseId: "OPEN-1", kind: "import", label: "open-label" });
  await request(app).post("/cases/LOCKED-1/password").send({ newPassword: PASSWORD }).expect(200);
  return { app, lockedJobId: locked.jobId, openJobId: open.jobId };
}

async function unlockCookie(app: Parameters<typeof request>[0]): Promise<string> {
  const res = await request(app).post("/cases/LOCKED-1/unlock").send({ password: PASSWORD }).expect(200);
  const cookies = res.headers["set-cookie"] as unknown as string[];
  return cookies.map((c) => c.split(";")[0]).join("; ");
}

describe("jobs routes respect the case password", () => {
  it("leaves a locked case's jobs out of the list without an unlock", async () => {
    const { app, lockedJobId, openJobId } = await harness();
    const all = await request(app).get("/api/jobs").expect(200);
    const ids = (all.body.jobs as { id: string }[]).map((j) => j.id);
    expect(ids).toContain(openJobId);
    expect(ids).not.toContain(lockedJobId);
    expect(JSON.stringify(all.body)).not.toContain("secret-evidence.evtx");

    const scoped = await request(app).get("/api/jobs?caseId=LOCKED-1").expect(200);
    expect(scoped.body.jobs).toEqual([]);
  });

  it("refuses a single read, cancel or resume of a locked case's job without an unlock", async () => {
    const { app, lockedJobId } = await harness();
    const read = await request(app).get(`/api/jobs/${lockedJobId}`).expect(404);
    expect(JSON.stringify(read.body)).not.toContain("secret-label");
    await request(app).post(`/api/jobs/${lockedJobId}/cancel`).expect(404);
    await request(app).post(`/api/jobs/${lockedJobId}/resume`).expect(404);
  });

  it("returns a locked case's jobs once the caller has unlocked it", async () => {
    const { app, lockedJobId } = await harness();
    const cookie = await unlockCookie(app);
    const scoped = await request(app).get("/api/jobs?caseId=LOCKED-1").set("Cookie", cookie).expect(200);
    expect((scoped.body.jobs as { id: string }[]).map((j) => j.id)).toEqual([lockedJobId]);
    const read = await request(app).get(`/api/jobs/${lockedJobId}`).set("Cookie", cookie).expect(200);
    expect(read.body.label).toBe("secret-label");
  });

  it("returns a passwordless case's jobs to anyone", async () => {
    const { app, openJobId } = await harness();
    const read = await request(app).get(`/api/jobs/${openJobId}`).expect(200);
    expect(read.body.label).toBe("open-label");
    const scoped = await request(app).get("/api/jobs?caseId=OPEN-1").expect(200);
    expect((scoped.body.jobs as { id: string }[]).map((j) => j.id)).toEqual([openJobId]);
  });
});
