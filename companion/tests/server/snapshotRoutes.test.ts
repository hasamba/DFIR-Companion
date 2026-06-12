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
import { SNAPSHOT_FORMAT } from "../../src/analysis/snapshot.js";

async function harness() {
  const root = await mkdtemp(join(tmpdir(), "dfir-snap-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const commentsStore = new CommentsStore(store);
  // scope is served by an internal store inside createApp, so it needs no option here.
  const app = createApp(store, { stateStore, commentsStore });
  return { app, store, stateStore };
}

async function seedCase(app: ReturnType<typeof createApp>, stateStore: StateStore) {
  await request(app).post("/cases").send({ caseId: "INC-1", name: "Case One", investigator: "alice", aiProvider: "anthropic" });
  await stateStore.save({
    ...emptyState("INC-1"),
    findings: [{ id: "f1", severity: "High", title: "t", description: "d", relatedIocs: [], sourceScreenshots: [], mitreTechniques: [], firstSeen: "2026-01-01T00:00:00Z", lastUpdated: "2026-01-01T00:00:00Z", status: "open" }],
    iocs: [{ id: "i1", type: "ip", value: "8.8.8.8", firstSeen: "2026-01-01T00:00:00Z" }],
    forensicTimeline: [{ id: "e1", timestamp: "2026-01-01T00:00:00Z", description: "evt", severity: "High", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [] }],
  });
  // analyst decisions in other state files
  await request(app).post("/cases/INC-1/comments").send({ targetType: "ioc", targetId: "i1", text: "looks malicious" });
  await request(app).post("/cases/INC-1/scope").send({ start: "2026-01-01T00:00:00Z", end: "2026-01-02T00:00:00Z" });
}

describe("GET /cases/:id/export/snapshot", () => {
  it("bundles investigation data + analyst decisions, excludes machine config", async () => {
    const { app, stateStore } = await harness();
    await seedCase(app, stateStore);

    const res = await request(app).get("/cases/INC-1/export/snapshot");
    expect(res.status).toBe(200);
    expect(res.headers["content-disposition"]).toContain("snapshot-INC-1.json");
    const snap = JSON.parse(res.text);
    expect(snap.format).toBe(SNAPSHOT_FORMAT);
    expect(snap.case.caseId).toBe("INC-1");
    expect(snap.counts).toMatchObject({ findings: 1, iocs: 1, forensicEvents: 1 });
    expect(snap.state).toHaveProperty("investigation.json");
    expect(snap.state).toHaveProperty("comments.json");
    expect(snap.state).toHaveProperty("scope.json");
    // never the AI / machine config files
    expect(snap.state).not.toHaveProperty("ai-control.json");
    expect(snap.state).not.toHaveProperty("enrich-control.json");
  });

  it("404s for an unknown case", async () => {
    const { app } = await harness();
    expect((await request(app).get("/cases/ghost/export/snapshot")).status).toBe(404);
  });
});

describe("POST /snapshots/import", () => {
  it("round-trips a snapshot into a new case", async () => {
    const { app, stateStore } = await harness();
    await seedCase(app, stateStore);
    const snap = JSON.parse((await request(app).get("/cases/INC-1/export/snapshot")).text);

    const imp = await request(app).post("/snapshots/import").send({ snapshot: snap, targetCaseId: "INC-2" });
    expect(imp.status).toBe(201);
    expect(imp.body.caseId).toBe("INC-2");
    expect(imp.body.aiProvider).toBeNull();             // machine config dropped
    expect(imp.body.counts).toMatchObject({ findings: 1, iocs: 1 });

    // the imported case loads with the same investigation data, re-pointed at the new id
    const state = await request(app).get("/cases/INC-2/state");
    expect(state.body.caseId).toBe("INC-2");
    expect(state.body.findings).toHaveLength(1);
    expect(state.body.iocs[0].value).toBe("8.8.8.8");
    // analyst decisions came across too
    expect((await request(app).get("/cases/INC-2/comments")).body.length).toBeGreaterThan(0);
    expect((await request(app).get("/cases/INC-2/scope")).body.start).toBe("2026-01-01T00:00:00.000Z");
  });

  it("imports under the snapshot's own id when no target is given", async () => {
    const { app, stateStore } = await harness();
    await seedCase(app, stateStore);
    const snap = JSON.parse((await request(app).get("/cases/INC-1/export/snapshot")).text);

    // a SEPARATE companion (fresh cases root) where INC-1 is still free
    const { app: app2 } = await harness();
    const imp = await request(app2).post("/snapshots/import").send(snap);   // bare body, no wrapper
    expect(imp.status).toBe(201);
    expect(imp.body.caseId).toBe("INC-1");
  });

  it("409s when the target case already exists", async () => {
    const { app, stateStore } = await harness();
    await seedCase(app, stateStore);
    const snap = JSON.parse((await request(app).get("/cases/INC-1/export/snapshot")).text);
    const imp = await request(app).post("/snapshots/import").send({ snapshot: snap });   // INC-1 exists
    expect(imp.status).toBe(409);
    expect(imp.body.caseId).toBe("INC-1");
  });

  it("400s on a non-snapshot payload", async () => {
    const { app } = await harness();
    expect((await request(app).post("/snapshots/import").send({ hello: "world" })).status).toBe(400);
    expect((await request(app).post("/snapshots/import").send({ snapshot: { format: "dfir-companion-snapshot", version: 999, case: { caseId: "x" }, state: {} } })).status).toBe(400);
  });
});
