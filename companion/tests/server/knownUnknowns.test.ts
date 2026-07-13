import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { emptyState, type Finding } from "../../src/analysis/stateTypes.js";

function finding(id: string, mitre: string[]): Finding {
  return { id, severity: "Critical", title: id, description: "", relatedIocs: [], sourceScreenshots: [], mitreTechniques: mitre,
    firstSeen: "2026-01-01T00:00:00Z", lastUpdated: "2026-01-01T00:00:00Z", status: "open" };
}

async function makeApp() {
  const root = await mkdtemp(join(tmpdir(), "dfir-ku-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const pipeline = buildRuntimePipeline({ stateStore, store, imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }) });
  const app = createApp(store, { pipeline, stateStore, aiConfigured: false });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, stateStore };
}

describe("GET /cases/:id/known-unknowns (#9)", () => {
  it("returns structured uncovered-tactic items with collect directives for a serious case", async () => {
    const { app, stateStore } = await makeApp();
    const s = emptyState("c1");
    s.findings = [finding("f1", ["T1486"])]; // only Impact covered
    s.forensicTimeline = [
      { id: "e1", timestamp: "2026-05-20T08:00:00Z", description: "", severity: "High", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], asset: "WEB01" },
    ];
    await stateStore.save(s);

    const res = await request(app).get("/cases/c1/known-unknowns");
    expect(res.status).toBe(200);
    const items = res.body.items as Array<{ kind: string; tactic?: string; collect: unknown[] }>;
    expect(Array.isArray(items)).toBe(true);
    const uncovered = items.filter((i) => i.kind === "uncovered_tactic");
    expect(uncovered.length).toBeGreaterThan(0);
    expect(uncovered.some((i) => i.tactic === "Initial Access")).toBe(true);
    expect((uncovered[0].collect as unknown[]).length).toBeGreaterThan(0);
  });

  it("returns an empty item list for a fresh low-signal case", async () => {
    const { app } = await makeApp();
    const res = await request(app).get("/cases/c1/known-unknowns");
    expect(res.status).toBe(200);
    expect(res.body.items).toEqual([]);
  });
});
