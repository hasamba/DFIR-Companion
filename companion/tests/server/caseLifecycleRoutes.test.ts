import { describe, it, expect } from "vitest";
import { mkdtemp, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
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

async function seedCase(app: ReturnType<typeof createApp>, caseId: string, name: string) {
  await request(app).post("/cases").send({ caseId, name, investigator: "alice", aiProvider: "anthropic" });
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
