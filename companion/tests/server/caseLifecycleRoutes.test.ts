import { describe, it, expect } from "vitest";
import { mkdtemp, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { CommentsStore } from "../../src/analysis/comments.js";

const PASSWORD = "correct horse battery staple";

async function harness() {
  const root = await mkdtemp(join(tmpdir(), "dfir-lifecycle-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const commentsStore = new CommentsStore(store);
  const app = createApp(store, { stateStore, commentsStore });
  return { app, store };
}

// /import, /import-file and /synthesize each 501 with "not configured" before they ever look at
// caseMeta.status when options.pipeline is absent — harness() deliberately has no pipeline, so
// those routes' own precondition gate is unreachable-proof against the archived-status guard.
// This variant wires a real (no-AI) pipeline via buildRuntimePipeline, same as
// tests/server/importMissingCase.test.ts, so requests clear that gate and actually reach the
// closed/archived check under test. aiConfigured forces /synthesize's hasAiProvider() gate true
// too, without needing a working AI provider — the archived check short-circuits before any
// AI call would happen.
async function harnessWithPipeline() {
  const root = await mkdtemp(join(tmpdir(), "dfir-lifecycle-pipeline-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const commentsStore = new CommentsStore(store);
  const pipeline = buildRuntimePipeline({
    provider: undefined, synthesisProvider: undefined, stateStore, store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const app = createApp(store, { stateStore, commentsStore, pipeline, aiConfigured: true });
  return { app, store };
}

async function seedCase(app: ReturnType<typeof createApp>, caseId: string, name: string) {
  await request(app).post("/cases").send({ caseId, name, investigator: "alice", aiProvider: "anthropic" });
}

function bufferRequest(req: request.Test): request.Test {
  return req.buffer().parse((r, cb) => {
    const chunks: Buffer[] = [];
    r.on("data", (c: Buffer) => chunks.push(c));
    r.on("end", () => cb(null, Buffer.concat(chunks)));
  });
}

describe("PATCH /cases/:id/status", () => {
  it("rejects 'archived' as a direct status value", async () => {
    const { app } = await harness();
    await seedCase(app, "INC-1", "Case One");
    const res = await request(app).patch("/cases/INC-1/status").send({ status: "archived" });
    expect(res.status).toBe(400);
  });
});

describe("POST /cases/:id/archive (removeFromList)", () => {
  it("keeps the case active by default (no removeFromList)", async () => {
    const { app, store } = await harness();
    await seedCase(app, "INC-2", "Case Two");
    const res = await request(app).post("/cases/INC-2/archive").send({});
    expect(res.status).toBe(200);
    expect(res.body.removedFromList).toBe(false);
    const s = await stat(join(store.casesRoot, "INC-2", "case.json"));
    expect(s.isFile()).toBe(true);
  });

  it("moves the case to _archived/ and sets status when removeFromList is true", async () => {
    const { app, store } = await harness();
    await seedCase(app, "INC-3", "Case Three");
    const res = await request(app).post("/cases/INC-3/archive").send({ removeFromList: true });
    expect(res.status).toBe(200);
    expect(res.body.removedFromList).toBe(true);
    const moved = await stat(join(store.casesRoot, "_archived", "INC-3", "case.json"));
    expect(moved.isFile()).toBe(true);
    const meta = await store.getCaseMeta("INC-3");
    expect(meta?.status).toBe("archived");
  });

  it("400s when the case is already archived", async () => {
    const { app } = await harness();
    await seedCase(app, "INC-3b", "Case Three B");
    await request(app).post("/cases/INC-3b/archive").send({ removeFromList: true });
    const res = await request(app).post("/cases/INC-3b/archive").send({ removeFromList: true });
    expect(res.status).toBe(400);
  });
});

describe("POST /cases/:id/export/encrypted (removeFromList)", () => {
  it("moves the case to _archived/ and sets status when removeFromList is true", async () => {
    const { app, store } = await harness();
    await seedCase(app, "INC-4", "Case Four");
    const res = await request(app)
      .post("/cases/INC-4/export/encrypted")
      .send({ password: PASSWORD, removeFromList: true });
    expect(res.status).toBe(200);
    expect(res.headers["x-case-removed-from-list"]).toBe("true");
    const meta = await store.getCaseMeta("INC-4");
    expect(meta?.status).toBe("archived");
  });

  it("does not remove the case when removeFromList is omitted", async () => {
    const { app, store } = await harness();
    await seedCase(app, "INC-4b", "Case Four B");
    const res = await request(app)
      .post("/cases/INC-4b/export/encrypted")
      .send({ password: PASSWORD });
    expect(res.status).toBe(200);
    expect(res.headers["x-case-removed-from-list"]).toBe("false");
    const meta = await store.getCaseMeta("INC-4b");
    expect(meta?.status).not.toBe("archived");
  });

  it("still returns the encrypted file even if the post-export folder move fails", async () => {
    const { app, store } = await harness();
    await seedCase(app, "INC-4c", "Case Four C");
    const originalArchiveCaseFolder = store.archiveCaseFolder.bind(store);
    (store as any).archiveCaseFolder = async () => { throw new Error("simulated rename failure"); };
    try {
      const res = await request(app)
        .post("/cases/INC-4c/export/encrypted")
        .send({ password: PASSWORD, removeFromList: true });
      expect(res.status).toBe(200);
      expect(res.headers["x-case-removed-from-list"]).toBe("false");
      expect(res.body.length).toBeGreaterThan(0);
    } finally {
      (store as any).archiveCaseFolder = originalArchiveCaseFolder;
    }
  });
});

describe("POST /cases/:id/restore", () => {
  it("restores an archived case back to the active root with status closed", async () => {
    const { app, store } = await harness();
    await seedCase(app, "INC-5", "Case Five");
    await request(app).post("/cases/INC-5/archive").send({ removeFromList: true });

    const res = await request(app).post("/cases/INC-5/restore").send({});
    expect(res.status).toBe(200);
    expect(res.body.status).toBe("closed");
    const s = await stat(join(store.casesRoot, "INC-5", "case.json"));
    expect(s.isFile()).toBe(true);
  });

  it("400s when the case exists but isn't archived", async () => {
    const { app } = await harness();
    await seedCase(app, "INC-6", "Case Six");
    const res = await request(app).post("/cases/INC-6/restore").send({});
    expect(res.status).toBe(400);
  });

  it("404s when the case doesn't exist at all", async () => {
    const { app } = await harness();
    const res = await request(app).post("/cases/ghost-case/restore").send({});
    expect(res.status).toBe(404);
  });
});

describe("Archived-case write guards on other evidence routes", () => {
  it("POST /cases/:id/import returns 423 for an archived case", async () => {
    const { app } = await harnessWithPipeline();
    await seedCase(app, "INC-8", "Case Eight");
    await request(app).post("/cases/INC-8/archive").send({ removeFromList: true });
    const res = await request(app).post("/cases/INC-8/import").send({ csv: "a,b\n1,2" });
    expect(res.status).toBe(423);
  });

  it("POST /cases/:id/import-file returns 423 for an archived case", async () => {
    const { app } = await harnessWithPipeline();
    await seedCase(app, "INC-9", "Case Nine");
    await request(app).post("/cases/INC-9/archive").send({ removeFromList: true });
    const res = await request(app).post("/cases/INC-9/import-file").send({ filename: "x.csv", content: "a,b\n1,2" });
    expect(res.status).toBe(423);
  });

  it("POST /cases/:id/synthesize returns 423 for an archived case", async () => {
    const { app } = await harnessWithPipeline();
    await seedCase(app, "INC-10", "Case Ten");
    await request(app).post("/cases/INC-10/archive").send({ removeFromList: true });
    const res = await request(app).post("/cases/INC-10/synthesize").send({});
    expect(res.status).toBe(423);
  });
});

describe("POST /cases/:id/delete", () => {
  it("400s when the case is open", async () => {
    const { app } = await harness();
    await seedCase(app, "DEL-1", "Case Del One");
    const res = await request(app).post("/cases/DEL-1/delete").send({ archiveFirst: "none" });
    expect(res.status).toBe(400);
  });

  it("deletes a closed case with no archive when archiveFirst is 'none'", async () => {
    const { app, store } = await harness();
    await seedCase(app, "DEL-2", "Case Del Two");
    await request(app).patch("/cases/DEL-2/status").send({ status: "closed" });
    const res = await request(app).post("/cases/DEL-2/delete").send({ archiveFirst: "none" });
    expect(res.status).toBe(200);
    expect(res.body.deleted).toBe(true);
    expect(res.body.archivePath).toBeUndefined();
    await expect(stat(join(store.casesRoot, "DEL-2"))).rejects.toThrow();
  });

  it("archives to ZIP then deletes when archiveFirst is 'zip'", async () => {
    const { app, store } = await harness();
    await seedCase(app, "DEL-3", "Case Del Three");
    await request(app).patch("/cases/DEL-3/status").send({ status: "closed" });
    const res = await request(app).post("/cases/DEL-3/delete").send({ archiveFirst: "zip" });
    expect(res.status).toBe(200);
    expect(res.body.deleted).toBe(true);
    expect(res.body.archivePath).toContain("(no password).zip");
    const zipStat = await stat(res.body.archivePath);
    expect(zipStat.isFile()).toBe(true);
    await expect(stat(join(store.casesRoot, "DEL-3"))).rejects.toThrow();
  });

  it("exports encrypted then deletes when archiveFirst is 'encrypted'", async () => {
    const { app, store } = await harness();
    await seedCase(app, "DEL-4", "Case Del Four");
    await request(app).patch("/cases/DEL-4/status").send({ status: "closed" });
    const res = await bufferRequest(
      request(app).post("/cases/DEL-4/delete").send({ archiveFirst: "encrypted", password: PASSWORD }),
    );
    expect(res.status).toBe(200);
    expect(res.headers["x-case-deleted"]).toBe("true");
    expect((res.body as Buffer).length).toBeGreaterThan(0);
    await expect(stat(join(store.casesRoot, "DEL-4"))).rejects.toThrow();
  });

  it("deletes an already-archived case", async () => {
    const { app, store } = await harness();
    await seedCase(app, "DEL-5", "Case Del Five");
    await request(app).post("/cases/DEL-5/archive").send({ removeFromList: true });
    const res = await request(app).post("/cases/DEL-5/delete").send({ archiveFirst: "none" });
    expect(res.status).toBe(200);
    expect(res.body.deleted).toBe(true);
    await expect(stat(join(store.casesRoot, "_archived", "DEL-5"))).rejects.toThrow();
  });

  it("still returns the archive result if deletion itself fails", async () => {
    const { app, store } = await harness();
    await seedCase(app, "DEL-6", "Case Del Six");
    await request(app).patch("/cases/DEL-6/status").send({ status: "closed" });
    const original = store.deleteCaseFolder.bind(store);
    (store as any).deleteCaseFolder = async () => { throw new Error("simulated delete failure"); };
    try {
      const res = await request(app).post("/cases/DEL-6/delete").send({ archiveFirst: "zip" });
      expect(res.status).toBe(200);
      expect(res.body.deleted).toBe(false);
      expect(res.body.deleteError).toBeTruthy();
      expect(res.body.archivePath).toContain("(no password).zip");
    } finally {
      (store as any).deleteCaseFolder = original;
    }
  });

  it("400s on an invalid archiveFirst value", async () => {
    const { app } = await harness();
    await seedCase(app, "DEL-7", "Case Del Seven");
    await request(app).patch("/cases/DEL-7/status").send({ status: "closed" });
    const res = await request(app).post("/cases/DEL-7/delete").send({ archiveFirst: "bogus" });
    expect(res.status).toBe(400);
  });

  it("404s for a case that doesn't exist", async () => {
    const { app } = await harness();
    const res = await request(app).post("/cases/ghost/delete").send({ archiveFirst: "none" });
    expect(res.status).toBe(404);
  });
});
