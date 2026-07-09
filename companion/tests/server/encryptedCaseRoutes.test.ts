import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { CommentsStore } from "../../src/analysis/comments.js";
import { emptyState } from "../../src/analysis/stateTypes.js";

const PASSWORD = "correct horse battery staple";

async function harness() {
  const root = await mkdtemp(join(tmpdir(), "dfir-encroute-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const commentsStore = new CommentsStore(store);
  const app = createApp(store, { stateStore, commentsStore });
  return { app, store, stateStore };
}

async function seedCase(app: ReturnType<typeof createApp>, stateStore: StateStore, store: CaseStore) {
  await request(app).post("/cases").send({ caseId: "INC-1", name: "Case One", investigator: "alice", aiProvider: "anthropic" });
  await stateStore.save({
    ...emptyState("INC-1"),
    findings: [{ id: "f1", severity: "High", title: "t", description: "d", relatedIocs: [], sourceScreenshots: [], mitreTechniques: [], firstSeen: "2026-01-01T00:00:00Z", lastUpdated: "2026-01-01T00:00:00Z", status: "open" }],
    iocs: [{ id: "i1", type: "ip", value: "8.8.8.8", firstSeen: "2026-01-01T00:00:00Z" }],
    forensicTimeline: [{ id: "e1", timestamp: "2026-01-01T00:00:00Z", description: "evt", severity: "High", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [] }],
  });
  await request(app).post("/cases/INC-1/comments").send({ targetType: "ioc", targetId: "i1", text: "looks malicious" });
  await store.saveScreenshot("INC-1", "shot.webp", Buffer.from([1, 2, 3, 4]));
}

function bufferRequest(req: request.Test): request.Test {
  return req.buffer().parse((r, cb) => {
    const chunks: Buffer[] = [];
    r.on("data", (c: Buffer) => chunks.push(c));
    r.on("end", () => cb(null, Buffer.concat(chunks)));
  });
}

async function exportArchive(app: ReturnType<typeof createApp>, caseId: string) {
  const res = await bufferRequest(
    request(app).post(`/cases/${caseId}/export/encrypted`).send({ password: PASSWORD }),
  );
  return (res.body as Buffer).toString("base64");
}

describe("POST /cases/:id/export/encrypted", () => {
  it("returns a .dfircase attachment", async () => {
    const { app, stateStore, store } = await harness();
    await seedCase(app, stateStore, store);
    const res = await bufferRequest(
      request(app).post("/cases/INC-1/export/encrypted").send({ password: PASSWORD }),
    );
    expect(res.status).toBe(200);
    expect(res.headers["content-disposition"]).toContain('attachment; filename="INC-1 - Case One.dfircase"');
    expect((res.body as Buffer).length).toBeGreaterThan(0);
  });

  it("400s on a too-short password", async () => {
    const { app, stateStore, store } = await harness();
    await seedCase(app, stateStore, store);
    const res = await request(app).post("/cases/INC-1/export/encrypted").send({ password: "short" });
    expect(res.status).toBe(400);
  });

  it("404s for an unknown case", async () => {
    const { app } = await harness();
    const res = await request(app).post("/cases/ghost/export/encrypted").send({ password: PASSWORD });
    expect(res.status).toBe(404);
  });

  it("400s on a path-traversal case id instead of reading outside the cases root", async () => {
    const { app } = await harness();
    const res = await request(app)
      .post("/cases/..%2F..%2Fetc/export/encrypted")
      .send({ password: PASSWORD });
    expect(res.status).toBe(400);
  });
});

describe("POST /cases/import/encrypted", () => {
  it("round-trips an encrypted archive into a new case, including evidence", async () => {
    const { app, stateStore, store } = await harness();
    await seedCase(app, stateStore, store);
    const data = await exportArchive(app, "INC-1");

    const imp = await request(app).post("/cases/import/encrypted").send({ data, password: PASSWORD, targetCaseId: "INC-2" });
    expect(imp.status).toBe(201);
    expect(imp.body.caseId).toBe("INC-2");
    expect(imp.body.counts).toMatchObject({ findings: 1, iocs: 1, forensicEvents: 1 });

    const state = await request(app).get("/cases/INC-2/state");
    expect(state.body.caseId).toBe("INC-2");
    expect(state.body.findings).toHaveLength(1);
    expect((await request(app).get("/cases/INC-2/comments")).body.length).toBeGreaterThan(0);

    // evidence bytes travelled too — this is the whole point of replacing the JSON snapshot
    const evidence = await request(app).get("/cases/INC-2/evidence/shot.webp");
    expect(evidence.status).toBe(200);
  });

  it("imports under the archive's own id when no target is given", async () => {
    const { app: app1, stateStore, store } = await harness();
    await seedCase(app1, stateStore, store);
    const data = await exportArchive(app1, "INC-1");

    const { app: app2 } = await harness(); // a separate companion where INC-1 is free
    const imp = await request(app2).post("/cases/import/encrypted").send({ data, password: PASSWORD });
    expect(imp.status).toBe(201);
    expect(imp.body.caseId).toBe("INC-1");
  });

  it("409s when the target case already exists", async () => {
    const { app, stateStore, store } = await harness();
    await seedCase(app, stateStore, store);
    const data = await exportArchive(app, "INC-1");
    const imp = await request(app).post("/cases/import/encrypted").send({ data, password: PASSWORD });
    expect(imp.status).toBe(409);
    expect(imp.body.caseId).toBe("INC-1");
  });

  it("400s on the wrong password", async () => {
    const { app, stateStore, store } = await harness();
    await seedCase(app, stateStore, store);
    const data = await exportArchive(app, "INC-1");
    const imp = await request(app).post("/cases/import/encrypted").send({ data, password: "totally-wrong", targetCaseId: "INC-3" });
    expect(imp.status).toBe(400);
  });

  it("400s on a malformed payload", async () => {
    const { app } = await harness();
    expect((await request(app).post("/cases/import/encrypted").send({ hello: "world" })).status).toBe(400);
    expect((await request(app).post("/cases/import/encrypted").send({ data: "@@@not-base64@@@", password: PASSWORD })).status).toBe(400);
  });
});
