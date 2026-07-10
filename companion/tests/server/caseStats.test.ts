import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

const EVENT_A: ForensicEvent = {
  id: "e1", timestamp: "2026-06-01T00:00:00Z", description: "d", severity: "Info",
  mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], asset: "WS-01", sources: ["Sysmon"],
};

async function makeApp() {
  const root = await mkdtemp(join(tmpdir(), "dfir-case-stats-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const pipeline = buildRuntimePipeline({
    provider: undefined, synthesisProvider: undefined, stateStore, store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const app = createApp(store, { pipeline, stateStore });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, stateStore, store };
}

describe("GET /cases/:id/stats", () => {
  it("returns totals, source breakdown, and import velocity for the case", async () => {
    const { app, stateStore, store } = await makeApp();
    const state = emptyState("c1");
    state.forensicTimeline = [EVENT_A];
    await stateStore.save(state);
    await store.appendImport("c1", {
      caseId: "c1", sequenceNumber: 1, importedAt: "2026-06-01T09:00:00Z",
      filename: "f1.csv", originalName: "f1.csv", rows: 10, bytes: 1000,
    });

    const res = await request(app).get("/cases/c1/stats");
    expect(res.status).toBe(200);
    expect(res.body.totals.events).toBe(1);
    expect(res.body.bySource).toEqual([{ source: "Sysmon", count: 1 }]);
    expect(res.body.importVelocity).toEqual([{ date: "2026-06-01", imports: 1, rows: 10 }]);
  });

  it("returns empty stats for a case with no imports yet", async () => {
    const { app } = await makeApp();
    const res = await request(app).get("/cases/c1/stats");
    expect(res.status).toBe(200);
    expect(res.body.totals).toEqual({ events: 0, findings: 0, iocs: 0, assets: 0 });
    expect(res.body.importVelocity).toEqual([]);
  });

  it("404s for an unknown case", async () => {
    const { app } = await makeApp();
    const res = await request(app).get("/cases/does-not-exist/stats");
    expect(res.status).toBe(404);
  });
});
