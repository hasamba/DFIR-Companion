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

  it("GET /health returns 200 so the extension can detect the companion is online", async () => {
    const res = await request(app).get("/health");
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
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

  it("auto-synthesizes (debounced) after a capture window when enabled", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-server-autosynth-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    // Per-window extraction returns a forensic event but NO findings; synthesis
    // turns the event into a finding — so a finding only appears if auto-synth ran.
    const pipeline = new AnalysisPipeline({
      provider: new MockProvider("extract", JSON.stringify({
        findings: [], iocs: [], mitreTechniques: [], threadsOpened: [], threadsClosed: [],
        timelineNote: "reviewed", summary: "",
        forensicEvents: [{ id: "e1", timestamp: "2026-05-20T09:00:00Z", description: "phish opened",
          severity: "High", mitreTechniques: [], relatedFindingIds: [] }],
      })),
      synthesisProvider: new MockProvider("synth", JSON.stringify({
        findings: [{ id: "f1", severity: "High", title: "synth finding", description: "d",
          relatedIocs: [], mitreTechniques: [], status: "open" }],
        iocs: [], mitreTechniques: [], attackerPath: "path", summary: "s",
        forensicEvents: [], threadsOpened: [], threadsClosed: [], timelineNote: "",
      })),
      stateStore,
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    });
    const app = createApp(store, { pipeline, windowSize: 10, autoSynthesize: true, autoSynthesizeDebounceMs: 10 });

    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
    await request(app).post("/captures").send({
      caseId: "c1", timestamp: "2026-05-28T10:00:00.000Z", url: "u", tabTitle: "t",
      triggerType: "navigation", imageBase64: await pngBase64(),
    });

    let state = await stateStore.load("c1");
    for (let i = 0; i < 40 && state.findings.length === 0; i++) {
      await new Promise((r) => setTimeout(r, 25));
      state = await stateStore.load("c1");
    }
    expect(state.forensicTimeline.length).toBe(1);          // extraction ran
    expect(state.findings).toHaveLength(1);                  // auto-synthesis ran
    expect(state.findings[0].title).toBe("synth finding");
    expect(state.attackerPath).toBe("path");
  });

  it("emits AI status (analyzing then idle) around a window flush", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-server-ai-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    const pipeline = new AnalysisPipeline({
      provider: new MockProvider("mock", JSON.stringify({
        findings: [], iocs: [], mitreTechniques: [], threadsOpened: [], threadsClosed: [],
        timelineNote: "n", summary: "s",
      })),
      stateStore,
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    });
    const events: { status: string; phase?: string }[] = [];
    const app = createApp(store, {
      pipeline,
      windowSize: 10,
      onAiStatus: (_caseId, e) => events.push({ status: e.status, phase: e.phase }),
    });

    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
    await request(app).post("/captures").send({
      caseId: "c1", timestamp: "2026-05-28T10:00:00.000Z", url: "u", tabTitle: "t",
      triggerType: "navigation", imageBase64: await pngBase64(),
    });

    for (let i = 0; i < 20 && !events.some((e) => e.status === "idle"); i++) {
      await new Promise((r) => setTimeout(r, 25));
    }
    expect(events[0]).toEqual({ status: "analyzing", phase: "extracting" }); // processing screenshots
    expect(events.some((e) => e.status === "idle")).toBe(true);
  });

  it("GET /health reports aiEnabled false without a pipeline, true with one", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-ai-health-"));
    const store = new CaseStore(root);
    const noAi = await request(createApp(store)).get("/health");
    expect(noAi.body.aiEnabled).toBe(false);

    const withAi = await request(createApp(store, {
      pipeline: new AnalysisPipeline({
        provider: new MockProvider("mock", "{}"),
        stateStore: new StateStore(store),
        imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
      }),
    })).get("/health");
    expect(withAi.body.aiEnabled).toBe(true);
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

  it("POST /cases/:id/synthesize runs the pipeline's synthesis and returns counts", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-synth-route-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
    // Seed a forensic timeline so synthesize has something to work from.
    const seeded = (await import("../src/analysis/stateTypes.js")).emptyState("c1");
    seeded.forensicTimeline.push({ id: "e1", timestamp: "2026-05-20T09:00:00Z", description: "phish",
      severity: "High", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: ["s1.webp"] });
    await stateStore.save(seeded);

    const pipeline = new AnalysisPipeline({
      provider: new MockProvider("mock", JSON.stringify({
        findings: [{ id: "f1", severity: "High", title: "conclusion", description: "d",
          relatedIocs: [], mitreTechniques: ["T1566"], status: "open" }],
        iocs: [], mitreTechniques: [{ id: "T1566", name: "Phishing" }],
        attackerPath: "phish then run", summary: "s",
        forensicEvents: [], threadsOpened: [], threadsClosed: [], timelineNote: "",
      })),
      stateStore,
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    });
    const app = createApp(store, { pipeline, stateStore });

    const res = await request(app).post("/cases/c1/synthesize");
    expect(res.status).toBe(200);
    expect(res.body.findings).toBe(1);
    expect(res.body.attackerPath).toBe(true);
  });

  it("POST /cases/:id/synthesize returns 501 when no pipeline is configured", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-synth-noai-"));
    const app = createApp(new CaseStore(root), {});
    const res = await request(app).post("/cases/c1/synthesize");
    expect(res.status).toBe(501);
  });
});

describe("AI on/off control", () => {
  function findingPipeline(stateStore: StateStore) {
    return new AnalysisPipeline({
      provider: new MockProvider("mock", JSON.stringify({
        findings: [{ id: "f1", severity: "High", title: "Hit", description: "d",
          relatedIocs: [], mitreTechniques: [], status: "open" }],
        iocs: [], mitreTechniques: [], threadsOpened: [], threadsClosed: [],
        timelineNote: "n", summary: "s",
      })),
      stateStore,
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    });
  }

  it("does NOT analyze captures while AI is off, then backfills them when turned on", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-aioff-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    const app = createApp(store, { pipeline: findingPipeline(stateStore), stateStore, windowSize: 1 });

    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
    // turn AI OFF
    await request(app).post("/cases/c1/ai-control").send({ enabled: false });

    // capture two screenshots while off
    for (let i = 0; i < 2; i++) {
      await request(app).post("/captures").send({
        caseId: "c1", timestamp: `2026-05-28T10:0${i}:00.000Z`, url: "u", tabTitle: "t",
        triggerType: "navigation", imageBase64: await pngBase64(),
      });
    }
    // evidence stored, but nothing analyzed
    await new Promise((r) => setTimeout(r, 100));
    expect((await stateStore.load("c1")).findings).toHaveLength(0);

    // turn AI ON → backfill analyzes the two captured-while-off screenshots
    await request(app).post("/cases/c1/ai-control").send({ enabled: true });
    let state = await stateStore.load("c1");
    for (let i = 0; i < 40 && state.findings.length === 0; i++) {
      await new Promise((r) => setTimeout(r, 25));
      state = await stateStore.load("c1");
    }
    expect(state.findings).toHaveLength(1);
  });

  it("GET /cases/:id/ai-control reports the current state", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-aictl-route-"));
    const store = new CaseStore(root);
    const app = createApp(store, {});
    const res = await request(app).get("/cases/c1/ai-control");
    expect(res.status).toBe(200);
    expect(res.body.enabled).toBe(true);
  });
});
