import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import sharp from "sharp";
import { CaseStore } from "../src/storage/caseStore.js";
import { createApp } from "../src/server.js";
import { _resetDedupCache } from "../src/ingest/captureIngest.js";
import { AnalysisPipeline } from "../src/analysis/pipeline.js";
import { StateStore } from "../src/analysis/stateStore.js";
import { MockProvider } from "../src/providers/provider.js";
import { ReportWriter } from "../src/reports/reportWriter.js";

let app: ReturnType<typeof createApp>;

async function pngBase64(): Promise<string> {
  const buf = await sharp({
    create: { width: 16, height: 16, channels: 3, background: { r: 10, g: 20, b: 30 } },
  }).png().toBuffer();
  return buf.toString("base64");
}

beforeEach(async () => {
  _resetDedupCache();
  const root = await mkdtemp(join(tmpdir(), "dfir-server-"));
  app = createApp(new CaseStore(root));
});

describe("HTTP server", () => {
  it("answers CORS preflight so the browser extension can POST cross-origin", async () => {
    const res = await request(app)
      .options("/cases")
      .set("Origin", "chrome-extension://abc")
      .set("Access-Control-Request-Method", "POST")
      .set("Access-Control-Request-Headers", "content-type");
    expect(res.status).toBe(204);
    expect(res.headers["access-control-allow-origin"]).toBe("*");
    expect(res.headers["access-control-allow-headers"]).toContain("Content-Type");
  });

  it("POST /cases creates a case", async () => {
    const res = await request(app)
      .post("/cases")
      .send({ caseId: "c1", name: "Incident A", investigator: "yaniv", aiProvider: null });
    expect(res.status).toBe(201);
    expect(res.body.caseId).toBe("c1");
  });

  it("POST /captures ingests a capture and returns metadata", async () => {
    await request(app)
      .post("/cases")
      .send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });

    const res = await request(app).post("/captures").send({
      caseId: "c1",
      timestamp: "2026-05-28T10:00:00.000Z",
      url: "https://velociraptor.local/hunts",
      tabTitle: "Hunts",
      triggerType: "timer",
      imageBase64: await pngBase64(),
    });
    expect(res.status).toBe(201);
    expect(res.body.sequenceNumber).toBe(1);
    expect(res.body.screenshotFile).toMatch(/\.webp$/);
  });

  it("POST /captures returns 400 on invalid payload", async () => {
    const res = await request(app).post("/captures").send({ caseId: "c1" });
    expect(res.status).toBe(400);
  });
});

describe("server analysis wiring", () => {
  it("flushes a window on a navigation trigger and updates state", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-server-an-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    const pipeline = new AnalysisPipeline({
      provider: new MockProvider("mock", JSON.stringify({
        findings: [{ id: "f1", severity: "High", title: "Hit", description: "d",
          relatedIocs: [], mitreTechniques: [], status: "open" }],
        iocs: [], mitreTechniques: [], threadsOpened: [], threadsClosed: [],
        timelineNote: "n", summary: "s",
      })),
      stateStore,
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    });
    const app = createApp(store, { pipeline, windowSize: 10 });

    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
    await request(app).post("/captures").send({
      caseId: "c1", timestamp: "2026-05-28T10:00:00.000Z", url: "u", tabTitle: "t",
      triggerType: "navigation", imageBase64: await pngBase64(),
    });

    // analysis runs async after the response; poll the state briefly.
    let state = await stateStore.load("c1");
    for (let i = 0; i < 20 && state.findings.length === 0; i++) {
      await new Promise((r) => setTimeout(r, 25));
      state = await stateStore.load("c1");
    }
    expect(state.findings).toHaveLength(1);
  });
});

describe("state and report routes", () => {
  it("GET /cases/:id/state returns the current state", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-state-route-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    const app = createApp(store, { stateStore });
    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });

    const res = await request(app).get("/cases/c1/state");
    expect(res.status).toBe(200);
    expect(res.body.caseId).toBe("c1");
    expect(res.body.findings).toEqual([]);
  });

  it("POST /cases/:id/report writes reports and returns paths", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-report-route-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    const reportWriter = new ReportWriter(store, stateStore);
    const app = createApp(store, { stateStore, reportWriter });
    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });

    const res = await request(app).post("/cases/c1/report");
    expect(res.status).toBe(200);
    expect(res.body.markdown).toMatch(/report\.md$/);
  });
});
