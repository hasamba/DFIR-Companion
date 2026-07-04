import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import sharp from "sharp";
import { CaseStore } from "../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../src/server.js";
import { _resetDedupCache } from "../src/ingest/captureIngest.js";
import { AnalysisPipeline } from "../src/analysis/pipeline.js";
import { StateStore } from "../src/analysis/stateStore.js";
import { MockProvider } from "../src/providers/provider.js";
import { ReportWriter } from "../src/reports/reportWriter.js";
import { ReportMetaStore } from "../src/reports/reportMeta.js";
import { CommentsStore } from "../src/analysis/comments.js";
import { PlaybookStore } from "../src/analysis/playbookStore.js";
import { PlaybookControlStore } from "../src/analysis/playbookControl.js";
import { IocWhitelistStore } from "../src/analysis/iocWhitelistStore.js";
import { emptyState, type InvestigationState } from "../src/analysis/stateTypes.js";
import type { CustomerExposureProvider } from "../src/analysis/customerExposure.js";

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

  it("POST /cases returns 409 for a duplicate caseId", async () => {
    await request(app).post("/cases").send({ caseId: "c1", name: "A", investigator: "y", aiProvider: null });
    const res = await request(app).post("/cases").send({ caseId: "c1", name: "A again", investigator: "y", aiProvider: null });
    expect(res.status).toBe(409);
  });

  it("POST /cases rejects path-like case IDs before touching storage paths", async () => {
    const res = await request(app).post("/cases").send({ caseId: "..\\outside", name: "A", investigator: "y", aiProvider: null });
    expect(res.status).toBe(400);
  });

  it("GET /cases lists created cases", async () => {
    await request(app).post("/cases").send({ caseId: "c1", name: "Incident A", investigator: "y", aiProvider: null });
    await request(app).post("/cases").send({ caseId: "c2", name: "Incident B", investigator: "y", aiProvider: null });
    const res = await request(app).get("/cases");
    expect(res.status).toBe(200);
    expect(res.body.map((c: { caseId: string }) => c.caseId).sort()).toEqual(["c1", "c2"]);
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

  it("POST /captures returns 404 for a case that does not exist", async () => {
    const res = await request(app).post("/captures").send({
      caseId: "ghost", timestamp: "2026-05-28T10:00:00.000Z", url: "u", tabTitle: "t",
      triggerType: "timer", imageBase64: await pngBase64(),
    });
    expect(res.status).toBe(404);
  });

  it("stores customer exposure targets and checks only customer-domain emails", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-server-exposure-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    const calls: string[] = [];
    const provider: CustomerExposureProvider = {
      name: "MockExposure",
      lookupDomain: async (domain) => { calls.push(`domain:${domain}`); return []; },
      lookupEmail: async (email) => {
        calls.push(`email:${email}`);
        return [{ provider: "MockExposure", targetType: "email", target: email, email, breach: "Breach" }];
      },
    };
    const app = createApp(store, { stateStore, customerExposureProviders: [provider], customerExposureDelayMs: 0 });
    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    await stateStore.save({
      ...emptyState("c1"),
      forensicTimeline: [{
        id: "e1", timestamp: "2026-06-01T00:00:00Z",
        description: "alice@example.com received a phish from attacker@evil.test",
        severity: "Medium", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [],
      }],
      iocs: [{ id: "i1", type: "domain", value: "evil.test", firstSeen: "2026-06-01T00:00:00Z" }],
    });

    const saved = await request(app).put("/cases/c1/customer-exposure/targets").send({ domains: "example.com", emails: "" });
    expect(saved.status).toBe(200);
    expect(saved.body.targets).toEqual({ domains: ["example.com"], emails: [] });

    const checked = await request(app).post("/cases/c1/customer-exposure/check").send({});
    expect(checked.status).toBe(200);
    expect(calls).toEqual(["domain:example.com", "email:alice@example.com"]);
    expect(checked.body.targets).toEqual({ domains: ["example.com"], emails: ["alice@example.com"] });
    expect(checked.body.results).toHaveLength(1);
  });

  it("runs only the selected exposure providers (body override and persisted selection)", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-server-exposure-sel-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    const calls: string[] = [];
    const mk = (name: string): CustomerExposureProvider => ({
      name,
      lookupDomain: async (d) => { calls.push(`${name}:${d}`); return []; },
      lookupEmail: async () => [],
    });
    const app = createApp(store, { stateStore, customerExposureProviders: [mk("LeakCheck"), mk("Shodan")], customerExposureDelayMs: 0 });
    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    await stateStore.save(emptyState("c1"));
    await request(app).put("/cases/c1/customer-exposure/targets").send({ domains: "example.com", emails: "" });

    // Body override: run only Shodan this time.
    calls.length = 0;
    await request(app).post("/cases/c1/customer-exposure/check").send({ providers: ["Shodan"] });
    expect(calls).toEqual(["Shodan:example.com"]);

    // Persisted selection: save providers=[LeakCheck]; a check with no override uses it.
    await request(app).put("/cases/c1/customer-exposure/targets").send({ domains: "example.com", emails: "", providers: ["LeakCheck"] });
    calls.length = 0;
    await request(app).post("/cases/c1/customer-exposure/check").send({});
    expect(calls).toEqual(["LeakCheck:example.com"]);
  });

  it("returns 501 for customer exposure checks when no provider is configured", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-server-exposure-none-"));
    const store = new CaseStore(root);
    const app = createApp(store, { stateStore: new StateStore(store) });
    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });

    const res = await request(app).post("/cases/c1/customer-exposure/check").send({});

    expect(res.status).toBe(501);
    expect(res.body.error).toContain("no customer exposure providers configured");
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
    await request(app).post("/cases/c1/ai-control").send({ enabled: true }); // AI defaults off — turn it on
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

  it("periodic flush analyzes a lone buffered capture that never fills a window", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-server-flush-"));
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
    // windowSize 10 so a single capture never fills a window; a short flush interval is the
    // only thing that can drain it. `timer` is NOT a SIGNIFICANT trigger, so it stays buffered.
    const app = createApp(store, { pipeline, windowSize: 10, flushIntervalMs: 40 });

    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
    await request(app).post("/cases/c1/ai-control").send({ enabled: true }); // AI defaults off — turn it on
    await request(app).post("/captures").send({
      caseId: "c1", timestamp: "2026-05-28T10:00:00.000Z", url: "u", tabTitle: "t",
      triggerType: "timer", imageBase64: await pngBase64(),
    });

    // No navigation/tab_switch and the window is far from full, so analysis only happens once
    // the periodic sweep fires. Poll the state until the finding lands.
    let state = await stateStore.load("c1");
    for (let i = 0; i < 40 && state.findings.length === 0; i++) {
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
          relatedIocs: [], mitreTechniques: [], status: "open", relatedEventIds: ["e1"] }],
        iocs: [], mitreTechniques: [], attackerPath: "path", summary: "s",
        forensicEvents: [], threadsOpened: [], threadsClosed: [], timelineNote: "",
      })),
      stateStore,
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    });
    const app = createApp(store, { pipeline, windowSize: 10, autoSynthesize: true, autoSynthesizeDebounceMs: 10 });

    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
    await request(app).post("/cases/c1/ai-control").send({ enabled: true }); // AI defaults off — turn it on
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

  it("imports a CSV: persists it as evidence, extracts events, then synthesizes findings", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-server-csv-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    const pipeline = new AnalysisPipeline({
      // Extraction (per CSV batch) returns a forensic event but no findings…
      provider: new MockProvider("extract", JSON.stringify({
        findings: [], iocs: [], mitreTechniques: [], threadsOpened: [], threadsClosed: [],
        timelineNote: "read rows", summary: "",
        forensicEvents: [{ id: "e1", timestamp: "2026-05-20T09:00:00Z", description: "process from CSV row",
          severity: "Medium", mitreTechniques: [], relatedFindingIds: [] }], // Medium: isolates this test from the high-severity backfill
      })),
      // …synthesis turns the timeline into a finding.
      synthesisProvider: new MockProvider("synth", JSON.stringify({
        findings: [{ id: "f1", severity: "High", title: "finding from CSV", description: "d",
          relatedIocs: [], mitreTechniques: [], status: "open" }],
        iocs: [], mitreTechniques: [], attackerPath: "path", summary: "s",
        forensicEvents: [], threadsOpened: [], threadsClosed: [], timelineNote: "",
      })),
      stateStore,
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    });
    const csvApp = createApp(store, { pipeline, stateStore });

    await request(csvApp).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
    await request(csvApp).post("/cases/c1/ai-control").send({ enabled: true }); // AI defaults off — turn it on so synthesis runs
    const csv = "Timestamp,Process,PID\n2026-05-20T09:00:00Z,mimikatz.exe,1234\n2026-05-20T09:01:00Z,rubeus.exe,5678\n";
    const res = await request(csvApp).post("/cases/c1/import-csv").send({ filename: "results.csv", csv });

    expect(res.status).toBe(202);
    expect(res.body.rows).toBe(2);

    // Evidence-first: the raw CSV + an audit line are written before analysis.
    const auditLog = await readFile(store.importsLogPath("c1"), "utf8");
    expect(auditLog.trim().split("\n")).toHaveLength(1);
    const stored = await readFile(join(store.importsDir("c1"), res.body.file), "utf8");
    expect(stored).toBe(csv);

    // Background: extraction then synthesis populate the state.
    let state = await stateStore.load("c1");
    for (let i = 0; i < 60 && state.findings.length === 0; i++) {
      await new Promise((r) => setTimeout(r, 25));
      state = await stateStore.load("c1");
    }
    expect(state.forensicTimeline.length).toBeGreaterThanOrEqual(1); // extracted from rows
    expect(state.findings).toHaveLength(1);                          // synthesized
    expect(state.findings[0].title).toBe("finding from CSV");
  });

  it("serves screenshot + CSV evidence by filename and blocks traversal/invalid names", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-server-ev-"));
    const store = new CaseStore(root);
    const evApp = createApp(store);
    await request(evApp).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });

    // Screenshot evidence → served with an image content-type.
    const png = Buffer.from(await pngBase64(), "base64");
    await store.saveScreenshot("c1", "000001_x.png", png);
    const shot = await request(evApp).get("/cases/c1/evidence/000001_x.png");
    expect(shot.status).toBe(200);
    expect(shot.headers["content-type"]).toContain("image/png");

    // Imported CSV evidence → served as text so a click opens it in a tab.
    await store.saveImport("c1", "0001_results.csv", "a,b\n1,2\n");
    const csv = await request(evApp).get("/cases/c1/evidence/0001_results.csv");
    expect(csv.status).toBe(200);
    expect(csv.headers["content-type"]).toContain("text/plain");
    expect(csv.text).toContain("a,b");

    expect((await request(evApp).get("/cases/c1/evidence/missing.png")).status).toBe(404);
    expect((await request(evApp).get("/cases/c1/evidence/bad@name.png")).status).toBe(400); // bad charset
    expect((await request(evApp).get("/cases/c1/evidence/a..b.png")).status).toBe(400);     // traversal guard
  });

  it("imports a generic log file: persists as evidence, extracts events, then synthesizes findings", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-server-log-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    const pipeline = new AnalysisPipeline({
      provider: new MockProvider("extract", JSON.stringify({
        findings: [], iocs: [], mitreTechniques: [], threadsOpened: [], threadsClosed: [],
        timelineNote: "read lines", summary: "",
        forensicEvents: [{ id: "e1", timestamp: "2026-05-28T09:00:00Z", description: "event from log line",
          severity: "Medium", mitreTechniques: [], relatedFindingIds: [] }], // Medium: isolates this test from the high-severity backfill
      })),
      synthesisProvider: new MockProvider("synth", JSON.stringify({
        findings: [{ id: "f1", severity: "High", title: "finding from log", description: "d",
          relatedIocs: [], mitreTechniques: [], status: "open" }],
        iocs: [], mitreTechniques: [], attackerPath: "path", summary: "s",
        forensicEvents: [], threadsOpened: [], threadsClosed: [], timelineNote: "",
      })),
      stateStore,
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    });
    const logApp = createApp(store, { pipeline, stateStore });

    await request(logApp).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
    await request(logApp).post("/cases/c1/ai-control").send({ enabled: true }); // AI defaults off — turn it on so synthesis runs
    const log = "May 28 09:00:01 host sshd[1]: Failed password for root from 10.0.0.5\nMay 28 09:00:02 host sshd[2]: Accepted password for admin from 10.0.0.5\n";
    const res = await request(logApp).post("/cases/c1/import-log").send({ filename: "auth.log", text: log });

    expect(res.status).toBe(202);
    expect(res.body.lines).toBe(2);

    // Evidence-first: raw file + audit line written before analysis.
    const auditLog = await readFile(store.importsLogPath("c1"), "utf8");
    expect(auditLog.trim().split("\n")).toHaveLength(1);
    const stored = await readFile(join(store.importsDir("c1"), res.body.file), "utf8");
    expect(stored).toBe(log);

    let state = await stateStore.load("c1");
    for (let i = 0; i < 60 && state.findings.length === 0; i++) {
      await new Promise((r) => setTimeout(r, 25));
      state = await stateStore.load("c1");
    }
    expect(state.forensicTimeline.length).toBeGreaterThanOrEqual(1);
    expect(state.findings).toHaveLength(1);
    expect(state.findings[0].title).toBe("finding from log");
  });

  it("rejects a log import with empty text (no non-empty lines)", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-server-log-empty-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    const pipeline = new AnalysisPipeline({
      provider: new MockProvider("mock", "should not be called"),
      stateStore,
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    });
    const emptyApp = createApp(store, { pipeline, stateStore });
    await request(emptyApp).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });

    // text empty string → 400 from the early guard
    const res1 = await request(emptyApp).post("/cases/c1/import-log").send({ filename: "x.log", text: "" });
    expect(res1.status).toBe(400);

    // text non-empty but all-whitespace lines → 400 from the parser guard
    const res2 = await request(emptyApp).post("/cases/c1/import-log").send({ filename: "x.log", text: "   \n   \n" });
    expect(res2.status).toBe(400);
  });

  it("imports a THOR JSON report: drops info/lifecycle noise, maps findings to the timeline, then synthesizes", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-server-thor-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    const pipeline = new AnalysisPipeline({
      // No per-finding AI extraction (THOR mapping is deterministic); synthesis still runs.
      provider: new MockProvider("mock", JSON.stringify({
        findings: [{ id: "f1", severity: "Critical", title: "Mimikatz present", description: "d",
          relatedIocs: [], mitreTechniques: [], status: "open", relatedEventIds: [] }],
        iocs: [], mitreTechniques: [], attackerPath: "p", summary: "s",
        forensicEvents: [], threadsOpened: [], threadsClosed: [], timelineNote: "",
      })),
      stateStore,
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    });
    const thorApp = createApp(store, { pipeline, stateStore });
    await request(thorApp).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
    await request(thorApp).post("/cases/c1/ai-control").send({ enabled: true }); // AI defaults off — turn it on so synthesis runs

    const jsonl = [
      JSON.stringify({ time: "t", hostname: "WIN11", level: "Info", module: "Init", message: "startup noise" }),
      JSON.stringify({ time: "t", hostname: "WIN11", level: "Alert", module: "Filescan", message: "Malware file found",
        file: "C:\\Tools\\mimikatz.exe", modified: "2025-03-14T21:18:18Z", reason_1: "YARA Powerkatz",
        sha256: "4813e753f6f9bfa5c5de0edbb8dd3cc7f1fa51714097d3144d44e5e89dbd33ef" }),
    ].join("\n") + "\n";
    const res = await request(thorApp).post("/cases/c1/import-thor").send({ filename: "WIN11_thor.json", json: jsonl });

    expect(res.status).toBe(202);
    expect(res.body.findings).toBe(1);   // the Alert
    expect(res.body.dropped).toBe(1);    // the Init/Info line

    // Evidence-first: raw report + audit line written.
    const auditLog = await readFile(store.importsLogPath("c1"), "utf8");
    expect(auditLog.trim().split("\n")).toHaveLength(1);

    // Deterministic mapping populated the timeline; background synthesis adds findings.
    let state = await stateStore.load("c1");
    for (let i = 0; i < 60 && state.findings.length === 0; i++) {
      await new Promise((r) => setTimeout(r, 25));
      state = await stateStore.load("c1");
    }
    expect(state.forensicTimeline.length).toBe(1);
    expect(state.forensicTimeline[0].severity).toBe("Critical");
    expect(state.forensicTimeline[0].timestamp).toBe("2025-03-14T21:18:18Z"); // artifact time, not scan time
    expect(state.iocs.some((i) => i.value.includes("mimikatz.exe"))).toBe(true);
    expect(state.findings.length).toBeGreaterThanOrEqual(1);
  });

  it("rejects a THOR import that has only info/lifecycle rows (no findings)", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-server-thor-empty-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    const pipeline = new AnalysisPipeline({
      provider: new MockProvider("mock", "should not be called"),
      stateStore,
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    });
    const app2 = createApp(store, { pipeline, stateStore });
    await request(app2).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });

    const onlyNoise = [
      JSON.stringify({ time: "t", hostname: "H", level: "Info", module: "Init", message: "x" }),
      JSON.stringify({ time: "t", hostname: "H", level: "Info", module: "Startup", message: "y" }),
    ].join("\n");
    const res = await request(app2).post("/cases/c1/import-thor").send({ filename: "t.json", json: onlyNoise });
    expect(res.status).toBe(400);
  });

  it("unified /import applies the minimum-severity floor (THOR: keeps the Critical, drops the Medium Notice)", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-server-import-floor-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    const pipeline = new AnalysisPipeline({
      provider: new MockProvider("mock", "synthesis must not run (AI off)"),
      stateStore,
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    });
    const app = createApp(store, { pipeline, stateStore });
    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
    // AI defaults OFF → deterministic mapping only, no synthesis to confuse the count.

    const jsonl = [
      JSON.stringify({ time: "t", hostname: "WIN11", level: "Alert", module: "Filescan",
        message: "Malware file found", file: "C:\\Tools\\mimikatz.exe", modified: "2025-03-14T21:18:18Z" }),
      JSON.stringify({ time: "t", hostname: "WIN11", level: "Notice", module: "Filescan",
        message: "Minor finding", file: "C:\\Tools\\note.txt", modified: "2025-03-14T20:00:00Z" }),
    ].join("\n") + "\n";

    // The single Import button posts to /import with the chosen floor.
    const res = await request(app).post("/cases/c1/import")
      .send({ filename: "WIN11_thor.json", text: jsonl, minSeverity: "critical" });
    expect(res.status).toBe(202);
    expect(res.body.kind).toBe("thor");
    expect(res.body.minSeverity).toBe("Critical"); // normalized + echoed back

    let state = await stateStore.load("c1");
    for (let i = 0; i < 80 && state.forensicTimeline.length === 0; i++) {
      await new Promise((r) => setTimeout(r, 25));
      state = await stateStore.load("c1");
    }
    await new Promise((r) => setTimeout(r, 100)); // settle — the Medium Notice must never land
    state = await stateStore.load("c1");
    expect(state.forensicTimeline).toHaveLength(1);          // Alert(Critical) kept, Notice(Medium) dropped
    expect(state.forensicTimeline[0].severity).toBe("Critical");
  });

  it("unified /import keeps an ungraded (all-Info) import in full despite a high floor (the 'no severities → import everything' rule)", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-server-import-gate-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    const pipeline = new AnalysisPipeline({
      provider: new MockProvider("mock", "synthesis must not run (AI off)"),
      stateStore,
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    });
    const app = createApp(store, { pipeline, stateStore });
    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });

    // KAPE Prefetch (PECmd) CSV — every row maps to an Info evidence event (host triage, no grading).
    const kape = [
      "SourceFilename,ExecutableName,Hash,Size,RunCount,LastRun,PreviousRun0",
      "C:\\Windows\\Prefetch\\EVIL.EXE-1234.pf,EVIL.EXE,ABCD,10000,3,2023-04-01 10:00:00,2023-03-31 09:00:00",
      "C:\\Windows\\Prefetch\\CALC.EXE-5678.pf,CALC.EXE,EF01,9000,7,2023-04-02 11:00:00,2023-03-30 08:00:00",
    ].join("\n");

    const res = await request(app).post("/cases/c1/import")
      .send({ filename: "Prefetch.csv", text: kape, minSeverity: "high" });
    expect(res.status).toBe(202);
    expect(res.body.kind).toBe("kape");

    let state = await stateStore.load("c1");
    for (let i = 0; i < 80 && state.forensicTimeline.length === 0; i++) {
      await new Promise((r) => setTimeout(r, 25));
      state = await stateStore.load("c1");
    }
    await new Promise((r) => setTimeout(r, 100));
    state = await stateStore.load("c1");
    // The floor was "high" but this import grades nothing (all Info) → it is kept whole.
    expect(state.forensicTimeline).toHaveLength(2);
    expect(state.forensicTimeline.every((e) => e.severity === "Info")).toBe(true);
  });

  it("imports a SIEM/EDR JSON export (Elastic envelope): unwraps, maps Windows events, then synthesizes", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-server-siem-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    const pipeline = new AnalysisPipeline({
      // No per-event AI extraction (SIEM mapping is deterministic); synthesis still runs.
      provider: new MockProvider("mock", JSON.stringify({
        findings: [{ id: "f1", severity: "High", title: "Service install", description: "d",
          relatedIocs: [], mitreTechniques: [], status: "open", relatedEventIds: [] }],
        iocs: [], mitreTechniques: [], attackerPath: "p", summary: "s",
        forensicEvents: [], threadsOpened: [], threadsClosed: [], timelineNote: "",
      })),
      stateStore,
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    });
    const siemApp = createApp(store, { pipeline, stateStore });
    await request(siemApp).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
    await request(siemApp).post("/cases/c1/ai-control").send({ enabled: true }); // AI defaults off — turn it on so synthesis runs

    const elastic = JSON.stringify({ data: [
      { _source: { "@timestamp": "2017-03-20T06:33:40Z", log_name: "Security", computer_name: "DC1",
        event_id: 4624, event_data: { TargetUserName: "martin", TargetDomainName: "WINDMILL", LogonType: "3", IpAddress: "::ffff:10.10.200.11" } } },
      { _source: { "@timestamp": "2017-03-20T10:00:00Z", log_name: "System", computer_name: "DC1",
        event_id: 7045, event_data: { ServiceName: "EvilSvc", ServiceFileName: "C:\\Temp\\evil.exe" } } },
    ] });
    const res = await request(siemApp).post("/cases/c1/import-siem").send({ filename: "windmill_elastic.json", json: elastic });

    expect(res.status).toBe(202);
    expect(res.body.format).toBe("elastic-data");
    expect(res.body.records).toBe(2);
    expect(res.body.events).toBe(2);

    // Evidence-first: raw export + audit line written before analysis.
    const auditLog = await readFile(store.importsLogPath("c1"), "utf8");
    expect(auditLog.trim().split("\n")).toHaveLength(1);

    // Deterministic mapping populated the timeline; the ::ffff: IP was unwrapped.
    let state = await stateStore.load("c1");
    for (let i = 0; i < 60 && state.findings.length === 0; i++) {
      await new Promise((r) => setTimeout(r, 25));
      state = await stateStore.load("c1");
    }
    expect(state.forensicTimeline.length).toBe(2);
    expect(state.forensicTimeline.some((e) => e.severity === "High" && e.description.includes("7045"))).toBe(true);
    expect(state.iocs.some((i) => i.type === "ip" && i.value === "10.10.200.11")).toBe(true);
    expect(state.findings.length).toBeGreaterThanOrEqual(1);
  });

  it("import with AI OFF populates the timeline + IOCs deterministically but does NOT synthesize", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-server-import-aioff-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    const pipeline = new AnalysisPipeline({
      // Synthesis must never run while AI is off — if this provider is invoked, the response
      // is unparseable and the test would surface it (but the gate means it's never called).
      provider: new MockProvider("mock", "AI synthesis must not run when AI is off"),
      stateStore,
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    });
    const app = createApp(store, { pipeline, stateStore });
    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
    // AI defaults OFF for a fresh case — leave it off (this is the scenario under test).

    const jsonl = JSON.stringify({ time: "t", hostname: "WIN11", level: "Alert", module: "Filescan",
      message: "Malware file found", file: "C:\\Tools\\mimikatz.exe", modified: "2025-03-14T21:18:18Z",
      reason_1: "YARA Powerkatz", sha256: "4813e753f6f9bfa5c5de0edbb8dd3cc7f1fa51714097d3144d44e5e89dbd33ef" }) + "\n";
    const res = await request(app).post("/cases/c1/import-thor").send({ filename: "WIN11_thor.json", json: jsonl });
    expect(res.status).toBe(202);

    // Deterministic THOR mapping runs in the background; give it time, then confirm the
    // timeline + IOCs landed but synthesis never produced findings (AI is off).
    let state = await stateStore.load("c1");
    for (let i = 0; i < 60 && state.forensicTimeline.length === 0; i++) {
      await new Promise((r) => setTimeout(r, 25));
      state = await stateStore.load("c1");
    }
    // Settle: ensure no delayed synthesis sneaks a finding in afterwards.
    await new Promise((r) => setTimeout(r, 150));
    state = await stateStore.load("c1");
    expect(state.forensicTimeline.length).toBe(1);                       // deterministic mapping populated it
    expect(state.forensicTimeline[0].severity).toBe("Critical");
    expect(state.iocs.some((i) => i.value.includes("mimikatz.exe"))).toBe(true);
    expect(state.findings).toHaveLength(0);                              // synthesis was gated off — no findings
  });

  it("CSV/log import via /import is gated by the AI toggle — saved as evidence, NOT sent to the model, when AI is off", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-server-import-csv-aioff-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    const pipeline = new AnalysisPipeline({
      // CSV extraction IS an LLM call. If it runs while AI is off, this mock returns unparseable
      // output — but the gate means the provider must never be invoked, so the timeline stays empty.
      provider: new MockProvider("mock", "CSV extraction must not run when AI is off"),
      stateStore,
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    });
    const app = createApp(store, { pipeline, stateStore });
    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
    // AI defaults OFF for a fresh case — leave it off (the scenario under test).

    const csv = "Timestamp,Process,PID\n2026-05-20T09:00:00Z,mimikatz.exe,1234\n";
    const res = await request(app).post("/cases/c1/import").send({ filename: "results.csv", text: csv });
    expect(res.status).toBe(202);
    expect(res.body).toMatchObject({ accepted: true, kind: "csv", analyzed: false, reason: "ai-off" });

    // Evidence-first still holds: the raw CSV is persisted even though it wasn't analyzed.
    const saved = await readFile(join(store.importsDir("c1"), res.body.file), "utf8");
    expect(saved).toBe(csv);

    // Settle, then confirm the LLM never ran: no events, no IOCs, no findings.
    await new Promise((r) => setTimeout(r, 200));
    const state = await stateStore.load("c1");
    expect(state.forensicTimeline).toHaveLength(0);
    expect(state.iocs).toHaveLength(0);
    expect(state.findings).toHaveLength(0);
  });

  it("builds a deterministic-import pipeline even when no AI provider is configured", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-server-deterministic-no-ai-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    const pipeline = buildRuntimePipeline({
      provider: undefined,
      synthesisProvider: undefined,
      stateStore,
      store,
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    });
    const app = createApp(store, { pipeline, stateStore });
    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });

    const jsonl = JSON.stringify({ time: "t", hostname: "WIN11", level: "Alert", module: "Filescan",
      message: "Malware file found", file: "C:\\Tools\\mimikatz.exe", modified: "2025-03-14T21:18:18Z",
      reason_1: "YARA Powerkatz", sha256: "4813e753f6f9bfa5c5de0edbb8dd3cc7f1fa51714097d3144d44e5e89dbd33ef" }) + "\n";

    const res = await request(app).post("/cases/c1/import-thor").send({ filename: "WIN11_thor.json", json: jsonl });

    expect(res.status).toBe(202);
  });

  it("rejects a SIEM import with no parseable records", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-server-siem-empty-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    const pipeline = new AnalysisPipeline({
      provider: new MockProvider("mock", "should not be called"),
      stateStore,
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    });
    const app3 = createApp(store, { pipeline, stateStore });
    await request(app3).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });

    const res = await request(app3).post("/cases/c1/import-siem").send({ filename: "x.json", json: "garbage not json" });
    expect(res.status).toBe(400);
  });

  it("returns a friendly 413 (not raw HTML) when an upload exceeds the body limit", async () => {
    const prev = process.env.DFIR_MAX_BODY_MB;
    process.env.DFIR_MAX_BODY_MB = "1"; // 1 MB cap for the test
    try {
      const root = await mkdtemp(join(tmpdir(), "dfir-server-413-"));
      const store = new CaseStore(root);
      const stateStore = new StateStore(store);
      const pipeline = new AnalysisPipeline({
        provider: new MockProvider("mock", "should not be called"),
        stateStore,
        imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
      });
      const app4 = createApp(store, { pipeline, stateStore });

      // A ~1.5 MB JSON string field, over the 1 MB cap → rejected by the body parser.
      const res = await request(app4).post("/cases/c1/import-siem").send({ filename: "big.json", json: "x".repeat(1_500_000) });
      expect(res.status).toBe(413);
      expect(res.body.error).toMatch(/exceeds the 1 MB limit/);
      expect(res.body.error).toMatch(/DFIR_MAX_BODY_MB/);
    } finally {
      if (prev === undefined) delete process.env.DFIR_MAX_BODY_MB; else process.env.DFIR_MAX_BODY_MB = prev;
    }
  });

  it("marks a forensic event false-positive (kind=event), storing its label and re-synthesizing", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-server-legit-ev-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    const seeded = (await import("../src/analysis/stateTypes.js")).emptyState("c1");
    seeded.forensicTimeline.push(
      { id: "e1", timestamp: "2026-05-28T09:00:00Z", description: "client admin task", severity: "Medium",
        mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [] },
    );
    await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
    await stateStore.save(seeded);

    const pipeline = new AnalysisPipeline({
      provider: new MockProvider("mock", JSON.stringify({
        findings: [], iocs: [], mitreTechniques: [], threadsOpened: [], threadsClosed: [],
        timelineNote: "", summary: "", forensicEvents: [],
      })),
      stateStore,
      falsePositiveStore: new (await import("../src/analysis/falsePositive.js")).FalsePositiveStore(store),
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    });
    const legitApp = createApp(store, { pipeline, stateStore });

    const res = await request(legitApp).post("/cases/c1/false-positive")
      .send({ kind: "event", ref: "e1", reason: "authorized-test", note: "client's own admin", label: "client admin task" });
    expect(res.status).toBe(200);
    const stored = res.body.find((m: { kind: string }) => m.kind === "event");
    expect(stored).toMatchObject({ kind: "event", ref: "e1", label: "client admin task" });
    expect(stored.id).toBe("event:e1");
  });

  it("marks many events false-positive in one batch request (single write, fallback note, dedupe)", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-server-legit-batch-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    const seeded = (await import("../src/analysis/stateTypes.js")).emptyState("c1");
    seeded.forensicTimeline.push(
      { id: "e1", timestamp: "2026-05-28T09:00:00Z", description: "admin task 1", severity: "Medium",
        mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [] },
      { id: "e2", timestamp: "2026-05-28T09:05:00Z", description: "admin task 2", severity: "Medium",
        mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [] },
    );
    await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
    await stateStore.save(seeded);

    const pipeline = new AnalysisPipeline({
      provider: new MockProvider("mock", JSON.stringify({
        findings: [], iocs: [], mitreTechniques: [], threadsOpened: [], threadsClosed: [],
        timelineNote: "", summary: "", forensicEvents: [],
      })),
      stateStore,
      falsePositiveStore: new (await import("../src/analysis/falsePositive.js")).FalsePositiveStore(store),
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    });
    const legitApp = createApp(store, { pipeline, stateStore });

    const res = await request(legitApp).post("/cases/c1/false-positive/batch").send({
      reason: "authorized-test",
      note: "client's own admin",
      items: [
        { kind: "event", ref: "e1", label: "admin task 1" },
        { kind: "event", ref: "e2", label: "admin task 2", note: "specific reason" },
        { kind: "event", ref: "" }, // skipped: no ref
      ],
    });
    expect(res.status).toBe(200);
    const events = res.body.filter((m: { kind: string }) => m.kind === "event");
    expect(events).toHaveLength(2);
    expect(events.find((m: { ref: string }) => m.ref === "e1")).toMatchObject({ id: "event:e1", note: "client's own admin" });
    expect(events.find((m: { ref: string }) => m.ref === "e2")).toMatchObject({ id: "event:e2", note: "specific reason" });

    // Persisted (one write) — reload via GET reflects the same two markers.
    const after = await request(legitApp).get("/cases/c1/false-positive");
    expect(after.body.filter((m: { kind: string }) => m.kind === "event")).toHaveLength(2);

    // Empty/invalid batch is rejected.
    const bad = await request(legitApp).post("/cases/c1/false-positive/batch").send({ items: [] });
    expect(bad.status).toBe(400);
  });

  it("enriches IOCs via configured providers and annotates them in state", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-server-enrich-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    const seeded = (await import("../src/analysis/stateTypes.js")).emptyState("c1");
    seeded.iocs.push(
      { id: "i1", type: "hash", value: "deadbeefdeadbeef", firstSeen: "t0" },
      { id: "i2", type: "file", value: "C:\\evil.exe", firstSeen: "t0" }, // not enrichable
    );
    await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    await stateStore.save(seeded);

    const provider = {
      name: "VirusTotal",
      scope: "external" as const,
      supports: () => true,
      lookup: async () => ({ source: "VirusTotal", verdict: "malicious" as const, score: "60/72" }),
    };
    const app2 = createApp(store, { stateStore, enrichmentProviders: [provider], enrichDelayMs: 0 });

    // Enable VirusTotal for this case (external is opt-in), then enrich.
    await request(app2).post("/cases/c1/enrich-control").send({ providers: ["VirusTotal"] });
    const res = await request(app2).post("/cases/c1/enrich").send({});
    expect(res.status).toBe(202);
    expect(res.body.iocs).toBe(2);

    // Background enrichment annotates the hash (not the file) — poll until it lands.
    let state = await stateStore.load("c1");
    for (let i = 0; i < 40 && !state.iocs[0].enrichments; i++) {
      await new Promise((r) => setTimeout(r, 25));
      state = await stateStore.load("c1");
    }
    expect(state.iocs[0].enrichments).toEqual([{ source: "VirusTotal", verdict: "malicious", score: "60/72", fetchedAt: expect.any(String) }]);
    expect(state.iocs[1].enrichments).toBeUndefined(); // file path not enrichable
  });

  it("returns 501 for enrich when no providers are configured", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-server-noenrich-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const app2 = createApp(store, { stateStore });
    const res = await request(app2).post("/cases/c1/enrich").send({});
    expect(res.status).toBe(501);
  });

  it("enrichment toggle is OFF by default and enriches current IOCs when turned ON", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-server-enrichtoggle-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    const seeded = (await import("../src/analysis/stateTypes.js")).emptyState("c1");
    seeded.iocs.push({ id: "i1", type: "hash", value: "abc123", firstSeen: "t0" });
    await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    await stateStore.save(seeded);

    const provider = { name: "VirusTotal", scope: "external" as const, supports: () => true, lookup: async () => ({ source: "VirusTotal", verdict: "malicious" as const }) };
    const app2 = createApp(store, { stateStore, enrichmentProviders: [provider], enrichDelayMs: 0 });
    const vtState = async () => (await request(app2).get("/cases/c1/enrich-control")).body.providers.find((p: { name: string }) => p.name === "VirusTotal");

    // External provider is OFF by default (local-only default; VT is external).
    const get0 = await request(app2).get("/cases/c1/enrich-control");
    expect(get0.status).toBe(200);
    expect(get0.body.anyConfigured).toBe(true);
    expect(await vtState()).toMatchObject({ scope: "external", enabled: false });

    // Turn ON via the legacy { enabled } shape → enables all configured (just VirusTotal).
    const on = await request(app2).post("/cases/c1/enrich-control").send({ enabled: true });
    expect(on.status).toBe(200);
    expect(on.body.providers).toEqual(["VirusTotal"]);

    let state = await stateStore.load("c1");
    for (let i = 0; i < 40 && !state.iocs[0].enrichments; i++) {
      await new Promise((r) => setTimeout(r, 25));
      state = await stateStore.load("c1");
    }
    expect(state.iocs[0].enrichments?.[0]).toMatchObject({ source: "VirusTotal", verdict: "malicious" });

    // Persisted ON.
    expect((await vtState()).enabled).toBe(true);
  });

  it("rejects a log import when no AI pipeline is configured", async () => {
    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const res = await request(app).post("/cases/c1/import-log").send({ filename: "x.log", text: "line\n" });
    expect(res.status).toBe(501);
  });

  it("rejects a CSV import when no AI pipeline is configured", async () => {
    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const res = await request(app).post("/cases/c1/import-csv").send({ filename: "x.csv", csv: "a,b\n1,2\n" });
    expect(res.status).toBe(501);
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
    await request(app).post("/cases/c1/ai-control").send({ enabled: true }); // AI defaults off — turn it on
    await request(app).post("/captures").send({
      caseId: "c1", timestamp: "2026-05-28T10:00:00.000Z", url: "u", tabTitle: "t",
      triggerType: "navigation", imageBase64: await pngBase64(),
    });

    // AI is toggled on for the still-empty case first, which now ALSO emits a terminal idle
    // (backfill always reports a final status). So wait for the window flush's own analyzing→idle
    // pair — not just "any idle", which the backfill would satisfy before the flush even runs.
    const flushed = () => {
      const ai = events.findIndex((e) => e.status === "analyzing" && e.phase === "extracting");
      return ai >= 0 && events.slice(ai + 1).some((e) => e.status === "idle");
    };
    for (let i = 0; i < 40 && !flushed(); i++) {
      await new Promise((r) => setTimeout(r, 25));
    }
    expect(flushed()).toBe(true); // the window flush reported analyzing(extracting) → idle
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
    expect(res.body.html).toMatch(/report\.html$/);
  });

  it("serves the generated report for export as HTML or Markdown (with optional download)", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-report-file-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    const reportWriter = new ReportWriter(store, stateStore);
    const app = createApp(store, { stateStore, reportWriter });
    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });

    // Before generation the file doesn't exist yet.
    expect((await request(app).get("/cases/c1/report/report.html")).status).toBe(404);

    await request(app).post("/cases/c1/report");

    const html = await request(app).get("/cases/c1/report/report.html");
    expect(html.status).toBe(200);
    expect(html.headers["content-type"]).toContain("text/html");
    expect(html.text).toContain("<!doctype html>");
    expect(html.headers["content-disposition"]).toBeUndefined(); // inline view

    const dl = await request(app).get("/cases/c1/report/report.md?download=1");
    expect(dl.status).toBe(200);
    expect(dl.headers["content-type"]).toContain("text/markdown");
    expect(dl.headers["content-disposition"]).toContain('attachment; filename="report.md"');

    // PDF export: ?print=1 serves the same HTML with a print trigger injected (no auto-print
    // in the plain inline view), so the browser opens its "Save as PDF" dialog on load.
    const print = await request(app).get("/cases/c1/report/report.html?print=1");
    expect(print.status).toBe(200);
    expect(print.headers["content-type"]).toContain("text/html");
    expect(print.text).toContain("window.print()");
    expect(print.headers["content-disposition"]).toBeUndefined(); // viewed in a tab, not downloaded
    expect(html.text).not.toContain("window.print()");            // the plain view is untouched

    // Only known report files are served.
    expect((await request(app).get("/cases/c1/report/secrets.txt")).status).toBe(400);
  });

  it("enrich-control: per-provider selection with scope, local-only default", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-enrich-ctl-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    const mkP = (name: string, scope: "local" | "external") => ({ name, scope, supports: () => true, lookup: async () => null });
    const enrichmentProviders = [mkP("VirusTotal", "external"), mkP("MISP", "local"), mkP("YETI", "local")];
    const app = createApp(store, { stateStore, enrichmentProviders });
    await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });

    // Default: local sources ON, external OFF — with scope reported.
    const g1 = await request(app).get("/cases/c1/enrich-control");
    expect(g1.status).toBe(200);
    expect(g1.body.anyConfigured).toBe(true);
    const byName = Object.fromEntries(g1.body.providers.map((p: { name: string }) => [p.name, p]));
    expect(byName.MISP).toMatchObject({ scope: "local", enabled: true });
    expect(byName.YETI.enabled).toBe(true);
    expect(byName.VirusTotal).toMatchObject({ scope: "external", enabled: false });

    // Select VirusTotal + MISP (unknown name dropped).
    const post = await request(app).post("/cases/c1/enrich-control").send({ providers: ["VirusTotal", "MISP", "bogus"] });
    expect(post.status).toBe(200);
    expect([...post.body.providers].sort()).toEqual(["MISP", "VirusTotal"]);

    const g2 = await request(app).get("/cases/c1/enrich-control");
    const byName2 = Object.fromEntries(g2.body.providers.map((p: { name: string }) => [p.name, p]));
    expect(byName2.VirusTotal.enabled).toBe(true);
    expect(byName2.YETI.enabled).toBe(false);

    // Neither providers nor enabled → 400.
    expect((await request(app).post("/cases/c1/enrich-control").send({})).status).toBe(400);
  });

  it("enrich-health: probes each provider and reports up / down / no-probe", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-enrich-health-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    const base = (name: string, scope: "local" | "external") => ({ name, scope, supports: () => true, lookup: async () => null });
    const enrichmentProviders = [
      { ...base("MISP", "local"), probe: async () => { /* up */ } },
      { ...base("YETI", "local"), probe: async () => { throw new Error("YETI auth HTTP 405"); } },
      base("VirusTotal", "external"),   // no probe() → reported up, not probed
    ];
    const app = createApp(store, { stateStore, enrichmentProviders });

    const r = await request(app).get("/enrich-health");
    expect(r.status).toBe(200);
    const byName = Object.fromEntries(r.body.providers.map((p: { name: string }) => [p.name, p]));
    expect(byName.MISP).toMatchObject({ scope: "local", probed: true, ok: true });
    expect(byName.YETI).toMatchObject({ probed: true, ok: false, detail: "YETI auth HTTP 405" });
    expect(byName.VirusTotal).toMatchObject({ probed: false, ok: true });
  });

  it("comments: post/list/delete on a case entity, with validation + a live ping", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-comments-route-"));
    const store = new CaseStore(root);
    const commentsStore = new CommentsStore(store);
    let pinged = 0;
    const app = createApp(store, { commentsStore, onComments: () => { pinged++; } });
    await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });

    // text is required.
    expect((await request(app).post("/cases/c1/comments").send({ targetType: "ioc", targetId: "i1" })).status).toBe(400);

    const post = await request(app).post("/cases/c1/comments").send({ targetType: "ioc", targetId: "i1", author: "Alice", text: "Possible C2?" });
    expect(post.status).toBe(201);
    expect(post.body).toMatchObject({ targetType: "ioc", targetId: "i1", author: "Alice", text: "Possible C2?" });
    expect(pinged).toBe(1);

    const list = await request(app).get("/cases/c1/comments");
    expect(list.body).toHaveLength(1);

    const del = await request(app).delete(`/cases/c1/comments/${post.body.id}`);
    expect(del.status).toBe(204);
    expect(pinged).toBe(2);
    expect((await request(app).get("/cases/c1/comments")).body).toHaveLength(0);

    expect((await request(app).delete("/cases/c1/comments/nope")).status).toBe(404);
  });

  it("false-positive: onFalsePositive callback fires on add, batch add, and remove", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-legit-cb-"));
    const store = new CaseStore(root);
    await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    let pinged = 0;
    const app = createApp(store, { onFalsePositive: () => { pinged++; } });

    // Single add fires the callback.
    const add = await request(app).post("/cases/c1/false-positive")
      .send({ kind: "ioc", ref: "1.2.3.4", reason: "known-good-tool", note: "internal scanner" });
    expect(add.status).toBe(200);
    expect(pinged).toBe(1);

    // Batch add fires once (not per item).
    const batch = await request(app).post("/cases/c1/false-positive/batch")
      .send({ items: [{ kind: "finding", ref: "f1", reason: "detection-misfire", note: "fp" }, { kind: "finding", ref: "f2", reason: "detection-misfire" }] });
    expect(batch.status).toBe(200);
    expect(pinged).toBe(2);

    // Remove fires the callback.
    const markerId = add.body.find((m: { kind: string }) => m.kind === "ioc")?.id;
    const remove = await request(app).post("/cases/c1/false-positive/remove")
      .send({ id: markerId });
    expect(remove.status).toBe(200);
    expect(pinged).toBe(3);
  });

  it("promotes an IOC false-positive to the global whitelist when addToWhitelist is set", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-legit-whitelist-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    const iocWhitelistStore = new IocWhitelistStore(join(root, "ioc-whitelist.json"));
    await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const app = createApp(store, { stateStore, iocWhitelistStore });

    // seed an IOC on the case first
    await request(app).post("/cases/c1/iocs").send({ type: "ip", value: "10.0.0.5" });
    const res = await request(app).post("/cases/c1/false-positive").send({
      kind: "ioc", ref: "10.0.0.5", reason: "known-good-tool", addToWhitelist: true,
    });
    expect(res.status).toBe(200);
    const rules = await request(app).get("/ioc-whitelist");
    expect(rules.body.some((r: { pattern: string }) => r.pattern === "10.0.0.5")).toBe(true);
    expect(rules.body.find((r: { pattern: string }) => r.pattern === "10.0.0.5")).toMatchObject({ iocType: "ip" });
  });

  it("does NOT promote to the whitelist when addToWhitelist is absent, or when the marker kind is not 'ioc'", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-legit-no-whitelist-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    const iocWhitelistStore = new IocWhitelistStore(join(root, "ioc-whitelist.json"));
    await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const app = createApp(store, { stateStore, iocWhitelistStore });

    // IOC marker without addToWhitelist → no promotion.
    const noFlag = await request(app).post("/cases/c1/false-positive").send({
      kind: "ioc", ref: "10.0.0.6", reason: "known-good-tool",
    });
    expect(noFlag.status).toBe(200);

    // Finding marker WITH addToWhitelist → still no promotion (only "ioc" kind qualifies).
    const findingFlag = await request(app).post("/cases/c1/false-positive").send({
      kind: "finding", ref: "f1", reason: "detection-misfire", addToWhitelist: true,
    });
    expect(findingFlag.status).toBe(200);

    const rules = await request(app).get("/ioc-whitelist");
    expect(rules.body).toEqual([]);
  });

  it("false-positive: rejects an empty ref, and rejects reason 'other' with no note (single + batch)", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-legit-reason-"));
    const store = new CaseStore(root);
    await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const app = createApp(store, {});

    // No ref at all → 400.
    const noRef = await request(app).post("/cases/c1/false-positive")
      .send({ kind: "ioc", reason: "known-good-tool" });
    expect(noRef.status).toBe(400);

    // reason "other" with an empty note → 400.
    const otherNoNote = await request(app).post("/cases/c1/false-positive")
      .send({ kind: "ioc", ref: "9.9.9.9", reason: "other" });
    expect(otherNoNote.status).toBe(400);

    // reason "other" WITH a note → accepted.
    const otherWithNote = await request(app).post("/cases/c1/false-positive")
      .send({ kind: "ioc", ref: "9.9.9.9", reason: "other", note: "one-off manual exclusion" });
    expect(otherWithNote.status).toBe(200);
    expect(otherWithNote.body.find((m: { ref: string }) => m.ref === "9.9.9.9")).toMatchObject({ reason: "other" });

    // Batch: an item with reason "other" and no note is silently skipped, not the whole batch rejected —
    // unless it's the only item, in which case the batch itself has nothing valid to add → 400.
    const batchAllInvalid = await request(app).post("/cases/c1/false-positive/batch")
      .send({ items: [{ kind: "finding", ref: "f1", reason: "other" }] });
    expect(batchAllInvalid.status).toBe(400);

    const batchMixed = await request(app).post("/cases/c1/false-positive/batch")
      .send({ items: [
        { kind: "finding", ref: "f1", reason: "other" },                          // skipped: no note
        { kind: "finding", ref: "f2", reason: "detection-misfire" },              // accepted
      ] });
    expect(batchMixed.status).toBe(200);
    expect(batchMixed.body.some((m: { ref: string }) => m.ref === "f1")).toBe(false);
    expect(batchMixed.body.some((m: { ref: string }) => m.ref === "f2")).toBe(true);
  });

  it("scope: onScope callback fires with the new window when scope is saved", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-scope-cb-"));
    const store = new CaseStore(root);
    await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const received: Array<{ start: string | null; end: string | null }> = [];
    const app = createApp(store, { onScope: (_caseId, s) => { received.push(s); } });

    const res = await request(app).post("/cases/c1/scope")
      .send({ start: "2026-01-01T00:00:00Z", end: "2026-06-01T00:00:00Z" });
    expect(res.status).toBe(200);
    expect(received).toHaveLength(1);
    expect(received[0]).toMatchObject({ start: "2026-01-01T00:00:00.000Z", end: "2026-06-01T00:00:00.000Z" });

    // Clearing scope (empty body) also fires.
    const clear = await request(app).post("/cases/c1/scope").send({});
    expect(clear.status).toBe(200);
    expect(received).toHaveLength(2);
    expect(received[1]).toMatchObject({ start: null, end: null });
  });

  it("POST /cases/:id/ask answers a question, and /questions pins it to the case", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-ask-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    const pipeline = new AnalysisPipeline({
      provider: new MockProvider("mock", JSON.stringify({ answer: "No evidence of exfiltration.", status: "unknown", pointer: "Check egress proxy/firewall logs.", relatedEventIds: [] })),
      stateStore,
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    });
    const app = createApp(store, { pipeline, stateStore });
    await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
    const seeded = (await import("../src/analysis/stateTypes.js")).emptyState("c1");
    seeded.forensicTimeline.push({ id: "e1", timestamp: "", description: "evt", severity: "Low", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [] });
    await stateStore.save(seeded);

    const ask = await request(app).post("/cases/c1/ask").send({ question: "Was data exfiltrated?" });
    expect(ask.status).toBe(200);
    expect(ask.body.status).toBe("unknown");
    expect(ask.body.pointer).toContain("egress");

    expect((await request(app).post("/cases/c1/ask").send({ question: "" })).status).toBe(400); // empty question

    const add = await request(app).post("/cases/c1/questions")
      .send({ question: "Was data exfiltrated?", status: "unknown", pointer: ask.body.pointer });
    expect(add.status).toBe(201);
    expect(add.body.pinned).toBe(true);
    expect(add.body.id).toMatch(/^aq\d+$/);

    const state = await request(app).get("/cases/c1/state");
    expect(state.body.keyQuestions.some((q: { pinned?: boolean }) => q.pinned)).toBe(true);
  });

  it("derives the asset ↔ IoC graph on demand", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-asset-graph-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    const reportWriter = new ReportWriter(store, stateStore);
    const app = createApp(store, { stateStore, reportWriter });
    await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
    const seeded = (await import("../src/analysis/stateTypes.js")).emptyState("c1");
    seeded.iocs.push({ id: "i1", type: "ip", value: "10.0.0.5", firstSeen: "" });
    seeded.forensicTimeline.push({ id: "e1", timestamp: "", description: "beacon to 10.0.0.5", severity: "High",
      mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], asset: "WIN-01" });
    await stateStore.save(seeded);

    const res = await request(app).get("/cases/c1/asset-graph");
    expect(res.status).toBe(200);
    expect(res.body.assets.some((a: { name: string }) => a.name === "WIN-01")).toBe(true);
    expect(res.body.edges.length).toBeGreaterThan(0);
    expect(res.body.iocs.some((i: { value: string }) => i.value === "10.0.0.5")).toBe(true);
  });

  it("derives temporal attack phases on demand", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-phases-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    const reportWriter = new ReportWriter(store, stateStore);
    const app = createApp(store, { stateStore, reportWriter });
    await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
    const seeded = (await import("../src/analysis/stateTypes.js")).emptyState("c1");
    seeded.forensicTimeline.push(
      { id: "e1", timestamp: "2026-05-20T14:01:00Z", description: "phishing email opened", severity: "High",
        mitreTechniques: ["T1566"], relatedFindingIds: [], sourceScreenshots: [] },
      { id: "e2", timestamp: "2026-05-20T14:02:00Z", description: "powershell spawned", severity: "Medium",
        mitreTechniques: ["T1059"], relatedFindingIds: [], sourceScreenshots: [] },
      // > 5 min gap → a second phase
      { id: "e3", timestamp: "2026-05-20T16:30:00Z", description: "ransomware encryptor", severity: "Critical",
        mitreTechniques: ["T1486"], relatedFindingIds: [], sourceScreenshots: [] },
    );
    await stateStore.save(seeded);

    const res = await request(app).get("/cases/c1/phases");
    expect(res.status).toBe(200);
    expect(res.body).toHaveLength(2);
    expect(res.body[0].label).toBe("Initial Access");
    expect(res.body[0].eventIds).toEqual(["e1", "e2"]);
    expect(res.body[1].label).toBe("Impact");
    expect(res.body[1].maxSeverity).toBe("Critical");
  });

  it("derives per-IOC corroboration (tools that observed each indicator) on demand", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-iocsrc-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    const reportWriter = new ReportWriter(store, stateStore);
    const app = createApp(store, { stateStore, reportWriter });
    await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
    const seeded = (await import("../src/analysis/stateTypes.js")).emptyState("c1");
    seeded.iocs.push(
      { id: "i1", type: "hash", value: "ABCDEF123456", firstSeen: "2026-05-20T14:00:00Z" },
      { id: "i2", type: "domain", value: "lonely.example", firstSeen: "2026-05-20T14:00:00Z" },
    );
    seeded.forensicTimeline.push(
      { id: "e1", timestamp: "2026-05-20T14:01:00Z", description: "malware", severity: "High",
        mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], sha256: "abcdef123456", sources: ["THOR"] },
      { id: "e2", timestamp: "2026-05-20T14:02:00Z", description: "same file flagged", severity: "High",
        mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], sha256: "abcdef123456", sources: ["Velociraptor"] },
      { id: "e3", timestamp: "2026-05-20T14:03:00Z", description: "dns for lonely.example", severity: "Low",
        mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], sources: ["Zeek"] },
    );
    await stateStore.save(seeded);

    const res = await request(app).get("/cases/c1/ioc-sources");
    expect(res.status).toBe(200);
    expect(res.body.i1.sort()).toEqual(["THOR", "Velociraptor"]);   // corroborated by 2 tools
    expect(res.body.i2).toEqual(["Zeek"]);                            // single tool
  });

  it("ranks adversary group hints by technique overlap against the bundled MITRE dataset", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-advhints-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    const reportWriter = new ReportWriter(store, stateStore);
    const app = createApp(store, { stateStore, reportWriter });
    await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
    const seeded = (await import("../src/analysis/stateTypes.js")).emptyState("c1");
    // A broad set of very common techniques (incl. a sub-technique, to exercise base-rollup) so
    // multiple real groups clear the default 3-overlap threshold.
    seeded.findings.push(
      { id: "f1", severity: "High", title: "intrusion", description: "", relatedIocs: [], sourceScreenshots: [],
        mitreTechniques: ["T1566", "T1059.001", "T1078"], firstSeen: "2026-05-20T14:00:00Z", lastUpdated: "2026-05-20T14:00:00Z", status: "open" },
    );
    seeded.forensicTimeline.push(
      { id: "e1", timestamp: "2026-05-20T14:01:00Z", description: "cred dumping", severity: "High",
        mitreTechniques: ["T1003", "T1021", "T1053"], relatedFindingIds: [], sourceScreenshots: [] },
    );
    await stateStore.save(seeded);

    const res = await request(app).get("/cases/c1/adversary-hints");
    expect(res.status).toBe(200);
    expect(res.body.caveat).toMatch(/not attribution/i);
    expect(res.body.attackVersion).not.toBe("unknown");
    expect(res.body.caseTechniqueCount).toBe(6); // T1566,T1059.001,T1078,T1003,T1021,T1053 (sub-techniques kept)
    expect(Array.isArray(res.body.hints)).toBe(true);
    expect(res.body.hints.length).toBeGreaterThan(0);
    for (const h of res.body.hints) {
      expect(h.overlapCount).toBeGreaterThanOrEqual(3);          // meets the threshold (breadth)
      expect(h.overlapCount).toBeLessThanOrEqual(6);             // can't exceed the case set
      expect(h.overlapTechniques.length).toBe(h.overlapCount);
      expect(h.exactCount).toBeLessThanOrEqual(h.overlapCount);
      expect(h.exactTechniques.length).toBe(h.exactCount);
      expect(h.score).toBeCloseTo(h.exactCount + 0.5 * (h.overlapCount - h.exactCount)); // weighted
      expect(h.url).toMatch(/^https:\/\/attack\.mitre\.org\/groups\/G\d{4}\/$/);
    }
    // ranked by weighted score descending (exact agreement wins, not raw breadth)
    const scores = res.body.hints.map((h: { score: number }) => h.score);
    expect(scores).toEqual([...scores].sort((a: number, b: number) => b - a));
  });

  it("returns adversary hints below threshold as an empty list (still 200 with caveat)", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-advhints-empty-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    const reportWriter = new ReportWriter(store, stateStore);
    const app = createApp(store, { stateStore, reportWriter });
    await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
    const seeded = (await import("../src/analysis/stateTypes.js")).emptyState("c1");
    // Only two techniques → no group can overlap by the default minimum of 3.
    seeded.forensicTimeline.push(
      { id: "e1", timestamp: "2026-05-20T14:01:00Z", description: "x", severity: "Low",
        mitreTechniques: ["T1566", "T1059"], relatedFindingIds: [], sourceScreenshots: [] },
    );
    await stateStore.save(seeded);

    const res = await request(app).get("/cases/c1/adversary-hints");
    expect(res.status).toBe(200);
    expect(res.body.caseTechniqueCount).toBe(2);
    expect(res.body.hints).toEqual([]);
  });

  it("exports just the incident timeline as CSV on demand (no full report needed)", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-timeline-csv-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    const reportWriter = new ReportWriter(store, stateStore);
    const app = createApp(store, { stateStore, reportWriter });
    await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
    const seeded = (await import("../src/analysis/stateTypes.js")).emptyState("c1");
    seeded.forensicTimeline.push({ id: "e1", timestamp: "2026-05-20T09:00:00Z", description: "Phishing email opened",
      severity: "High", mitreTechniques: ["T1566"], relatedFindingIds: [], sourceScreenshots: ["s1.webp"] });
    await stateStore.save(seeded);

    const res = await request(app).get("/cases/c1/incident-timeline.csv");
    expect(res.status).toBe(200);
    expect(res.headers["content-type"]).toContain("text/csv");
    expect(res.headers["content-disposition"]).toContain('attachment; filename="incident-timeline.csv"');
    expect(res.text).toContain("timestamp,endTimestamp,count,severity,description");
    expect(res.text).toContain("Phishing email opened");
  });

  it("exports the report as a .docx attachment on demand (no full report needed)", async () => {
    const { default: JSZip } = await import("jszip");
    const root = await mkdtemp(join(tmpdir(), "dfir-report-docx-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    const reportWriter = new ReportWriter(store, stateStore);
    const app = createApp(store, { stateStore, reportWriter });
    await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
    const seeded = (await import("../src/analysis/stateTypes.js")).emptyState("c1");
    seeded.lastSummary = "Compromise summary.";
    await stateStore.save(seeded);

    const res = await request(app)
      .get("/cases/c1/report.docx")
      .buffer(true)
      .parse((res, callback) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk: Buffer) => chunks.push(chunk));
        res.on("end", () => callback(null, Buffer.concat(chunks)));
      });
    expect(res.status).toBe(200);
    expect(res.headers["content-type"]).toContain(
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    );
    expect(res.headers["content-disposition"]).toContain('attachment; filename="report-c1.docx"');
    const body = res.body as Buffer;
    expect(Buffer.isBuffer(body)).toBe(true);
    expect(body.length).toBeGreaterThan(1024);

    const zip = await JSZip.loadAsync(body);
    const xml = await zip.file("word/document.xml")!.async("text");
    expect(xml).toContain("Compromise summary.");
  });

  it("returns 501 when no reportWriter is configured", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-report-docx-501-"));
    const store = new CaseStore(root);
    const app = createApp(store, {}); // no reportWriter
    await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const res = await request(app).get("/cases/c1/report.docx");
    expect(res.status).toBe(501);
  });

  it("exports a STIX 2.1 bundle on demand, with the victim org from report metadata", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-stix-route-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    const reportMetaStore = new ReportMetaStore(store);
    const reportWriter = new ReportWriter(store, stateStore, undefined, undefined, reportMetaStore);
    const app = createApp(store, { stateStore, reportWriter });
    await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
    const seeded = (await import("../src/analysis/stateTypes.js")).emptyState("c1");
    seeded.iocs.push({ id: "i1", type: "domain", value: "c2.evil.com", firstSeen: "2026-05-20T09:00:00Z" });
    seeded.findings.push({ id: "f1", severity: "High", title: "C2 beacon", description: "d", relatedIocs: ["i1"],
      sourceScreenshots: [], mitreTechniques: ["T1071"], firstSeen: "t", lastUpdated: "t", status: "open" });
    seeded.mitreTechniques.push({ id: "T1071", name: "Application Layer Protocol", findingIds: ["f1"] });
    await stateStore.save(seeded);
    await reportMetaStore.save("c1", { organization: "Acme Corp" });

    const res = await request(app).get("/cases/c1/export/stix");
    expect(res.status).toBe(200);
    expect(res.headers["content-type"]).toContain("application/json");
    expect(res.headers["content-disposition"]).toContain('attachment; filename="stix-bundle-c1.json"');
    const bundle = JSON.parse(res.text);
    expect(bundle.type).toBe("bundle");
    const types = bundle.objects.map((o: { type: string }) => o.type);
    expect(types).toEqual(expect.arrayContaining(["identity", "report", "indicator", "attack-pattern", "relationship"]));
    expect(bundle.objects.filter((o: { type: string }) => o.type === "identity")
      .map((o: { name: string }) => o.name)).toContain("Acme Corp");
    expect(bundle.objects.find((o: { type: string }) => o.type === "indicator").pattern)
      .toBe("[domain-name:value = 'c2.evil.com']");
  });

  it("returns 501 for the STIX export when no reportWriter is configured", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-stix-501-"));
    const store = new CaseStore(root);
    const app = createApp(store, {}); // no reportWriter
    await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const res = await request(app).get("/cases/c1/export/stix");
    expect(res.status).toBe(501);
  });

  it("GET/PUT /cases/:id/report-meta round-trips and flows into the generated report", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-report-meta-route-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    const reportMetaStore = new ReportMetaStore(store);
    const reportWriter = new ReportWriter(store, stateStore, undefined, undefined, reportMetaStore);
    const app = createApp(store, { stateStore, reportWriter, reportMetaStore });
    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });

    // Defaults before anything is saved.
    const initial = await request(app).get("/cases/c1/report-meta");
    expect(initial.status).toBe(200);
    expect(initial.body.includeDisclaimer).toBe(true);
    expect(initial.body.organization).toBe("");

    // Save human-authored fields (unknown keys are dropped by normalization).
    const put = await request(app).put("/cases/c1/report-meta").send({
      organization: "ExampleCorp",
      executiveSummary: "Human-authored summary.",
      recommendations: ["Deploy EDR everywhere"],
      bogus: "dropped",
    });
    expect(put.status).toBe(200);
    expect(put.body.organization).toBe("ExampleCorp");
    expect(put.body).not.toHaveProperty("bogus");

    // Reload reflects the save.
    const reloaded = await request(app).get("/cases/c1/report-meta");
    expect(reloaded.body.executiveSummary).toBe("Human-authored summary.");

    // The generated report.md includes the human fields.
    const gen = await request(app).post("/cases/c1/report");
    expect(gen.status).toBe(200);
    const md = await readFile(gen.body.markdown, "utf8");
    expect(md).toContain("**Organization:** ExampleCorp");
    expect(md).toContain("Human-authored summary.");
    expect(md).toContain("Deploy EDR everywhere");
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
          relatedIocs: [], mitreTechniques: ["T1566"], status: "open", relatedEventIds: ["e1"] }],
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

  it("emits a terminal idle status when AI is turned on with nothing to catch up on", async () => {
    // Regression: the dashboard optimistically shows "AI on — catching up on un-analyzed
    // screenshots…" the moment you toggle. backfill used to `return` silently when there was
    // nothing pending, so no terminal event was ever sent and that message hung forever
    // ("this message is stuck, I don't know if it finished"). It must always report idle.
    const root = await mkdtemp(join(tmpdir(), "dfir-aibackfill-idle-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    const events: { status: string; detail?: string }[] = [];
    const app = createApp(store, {
      pipeline: findingPipeline(stateStore), stateStore, windowSize: 1,
      onAiStatus: (_c, e) => events.push({ status: e.status, detail: e.detail }),
    });
    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });

    // Fresh case, zero captures → toggling AI on has nothing to analyze, but must still emit idle.
    await request(app).post("/cases/c1/ai-control").send({ enabled: true });
    for (let i = 0; i < 40 && !events.some((e) => e.status === "idle"); i++) {
      await new Promise((r) => setTimeout(r, 25));
    }
    expect(events.some((e) => e.status === "idle")).toBe(true);
    // …and it must not have falsely claimed it was analyzing when there was nothing to do.
    expect(events.some((e) => e.status === "analyzing")).toBe(false);
  });

  it("synthesizes evidence imported while AI was off when AI is turned on (no screenshots)", async () => {
    // Bug: importing a Velociraptor table with AI off populates the timeline deterministically, but
    // turning AI on only "caught up" on screenshots — with none, backfill idled and never synthesized
    // the imported data (only a fresh import did). With autosynthesis on, AI-on must trigger synthesis.
    const root = await mkdtemp(join(tmpdir(), "dfir-aibackfill-import-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    const phases: string[] = [];
    const app = createApp(store, {
      pipeline: findingPipeline(stateStore), stateStore,
      autoSynthesize: true, autoSynthesizeDebounceMs: 10,
      onAiStatus: (_c, e) => { if (e.phase) phases.push(e.phase); },
    });
    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
    // No capture log at all (import-only case). Turning AI on must trigger synthesis, not idle.
    await request(app).post("/cases/c1/ai-control").send({ enabled: true });
    for (let i = 0; i < 80 && !phases.includes("synthesizing"); i++) await new Promise((r) => setTimeout(r, 25));
    expect(phases).toContain("synthesizing");
  });

  it("POST /import fires onImport(caseId) so dashboards can warn cross-case (parity with captures)", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-onimport-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    const imported: string[] = [];
    const app = createApp(store, { pipeline: findingPipeline(stateStore), stateStore, onImport: (c) => imported.push(c) });
    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
    const velo = JSON.stringify([{ _Source: "Windows.Detection.X", Detection: { Name: "Bad" }, EventTime: "2026-01-01T00:00:00Z", EntryPath: "c:\\x.exe" }]);
    const res = await request(app).post("/cases/c1/import").send({ json: velo, filename: "v.json" });
    expect(res.status).toBe(202);
    expect(imported).toContain("c1"); // → startServer broadcasts { type:"import_ingest", caseId } to all dashboards
  });

  it("GET /cases/:id/ai-control reports the current state", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-aictl-route-"));
    const store = new CaseStore(root);
    const app = createApp(store, {});
    const res = await request(app).get("/cases/c1/ai-control");
    expect(res.status).toBe(200);
    expect(res.body.enabled).toBe(false); // AI defaults OFF for a fresh case
  });
});

describe("manual entry (events / IOCs the AI didn't catch)", () => {
  async function freshApp() {
    const root = await mkdtemp(join(tmpdir(), "dfir-manual-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    const app = createApp(store, { stateStore });
    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    return { app, stateStore };
  }

  it("POST /cases/:id/events appends a manual forensic event (sorted, tagged manual)", async () => {
    const { app, stateStore } = await freshApp();
    const res = await request(app).post("/cases/c1/events").send({
      timestamp: "2026-06-04T10:00:00Z", description: "manual logon to DC01", severity: "High",
      asset: "DC01", mitreTechniques: "T1059.001",
    });
    expect(res.status).toBe(201);
    expect(res.body.id).toMatch(/^manual-/);
    expect(res.body.sources).toEqual(["manual"]);
    const state = await stateStore.load("c1");
    const e = state.forensicTimeline.find((x) => x.description === "manual logon to DC01");
    expect(e).toBeTruthy();
    expect(e!.mitreTechniques).toEqual(["T1059.001"]);
  });

  it("POST /cases/:id/events returns 400 on an invalid body (no description)", async () => {
    const { app } = await freshApp();
    const res = await request(app).post("/cases/c1/events").send({ timestamp: "2026-06-04T10:00:00Z" });
    expect(res.status).toBe(400);
  });

  it("POST /cases/:id/iocs appends a manual IOC and rejects a duplicate value", async () => {
    const { app, stateStore } = await freshApp();
    const r1 = await request(app).post("/cases/c1/iocs").send({ type: "ip", value: "8.8.8.8" });
    expect(r1.status).toBe(201);
    const r2 = await request(app).post("/cases/c1/iocs").send({ type: "ip", value: "8.8.8.8" });
    expect(r2.status).toBe(409);
    const state = await stateStore.load("c1");
    expect(state.iocs.filter((i) => i.value === "8.8.8.8")).toHaveLength(1);
  });
});

describe("playbook routes (issue #36)", () => {
  async function freshPlaybookApp(seed?: Partial<InvestigationState>) {
    const root = await mkdtemp(join(tmpdir(), "dfir-playbook-route-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    const playbookStore = new PlaybookStore(store);
    const playbookControlStore = new PlaybookControlStore(store);
    const events: string[] = [];
    const app = createApp(store, { stateStore, playbookStore, playbookControlStore, onPlaybook: () => events.push("changed") });
    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    if (seed) await stateStore.save({ ...emptyState("c1"), ...seed });
    return { app, stateStore, playbookStore, playbookControlStore, events };
  }

  const NEXT_STEP = { id: "ns1", priority: "high" as const, action: "Pull 4624/4672", rationale: "confirm logon", pointer: "ALClient07" };
  const CRIT_FINDING = {
    id: "f1", severity: "Critical" as const, title: "Ransomware staged", description: "lockbit.exe",
    relatedIocs: [], sourceScreenshots: [], mitreTechniques: [], firstSeen: "2026-06-10T00:00:00Z", lastUpdated: "2026-06-10T00:00:00Z", status: "open" as const,
  };

  it("GET auto-derives tasks from next steps + Critical/High findings and returns completion stats", async () => {
    const { app } = await freshPlaybookApp({ nextSteps: [NEXT_STEP], findings: [CRIT_FINDING] });
    const res = await request(app).get("/cases/c1/playbook");
    expect(res.status).toBe(200);
    expect(res.body.tasks.map((t: { id: string }) => t.id)).toEqual(["next_step:ns1", "finding:f1"]);
    expect(res.body.stats).toMatchObject({ total: 2, done: 0, completionPct: 0 });
  });

  it("PATCH updates status and the GET stats reflect completion (preserved across re-sync)", async () => {
    const { app } = await freshPlaybookApp({ nextSteps: [NEXT_STEP] });
    await request(app).get("/cases/c1/playbook");                       // materialize
    const patch = await request(app).patch("/cases/c1/playbook/next_step:ns1").send({ status: "done", assignee: "ana" });
    expect(patch.status).toBe(200);
    const res = await request(app).get("/cases/c1/playbook");           // re-syncs, must preserve status
    expect(res.body.tasks[0]).toMatchObject({ status: "done", assignee: "ana" });
    expect(res.body.stats).toMatchObject({ total: 1, done: 1, completionPct: 100 });
  });

  it("POST adds a custom task; POST /sync re-derives; PATCH /order reorders; DELETE removes", async () => {
    const { app, events } = await freshPlaybookApp({ nextSteps: [NEXT_STEP] });
    const add = await request(app).post("/cases/c1/playbook").send({ title: "Call client", priority: "high" });
    expect(add.status).toBe(201);
    const customId = add.body.id;
    expect(customId).toMatch(/^custom:/);

    const sync = await request(app).post("/cases/c1/playbook/sync");
    expect(sync.status).toBe(200);
    expect(sync.body.tasks).toHaveLength(2);                            // derived next step + custom

    const order = await request(app).patch("/cases/c1/playbook/order").send({ ids: [customId, "next_step:ns1"] });
    expect(order.status).toBe(200);
    expect(order.body.tasks.map((t: { id: string }) => t.id)).toEqual([customId, "next_step:ns1"]);

    const del = await request(app).delete(`/cases/c1/playbook/${customId}`);
    expect(del.status).toBe(204);
    const after = await request(app).get("/cases/c1/playbook");
    expect(after.body.tasks.map((t: { id: string }) => t.id)).toEqual(["next_step:ns1"]);
    expect(events.length).toBeGreaterThan(0);                          // WS broadcast fired
  });

  it("DELETE on an auto-derived task marks it skipped so it survives re-sync", async () => {
    const { app } = await freshPlaybookApp({ nextSteps: [NEXT_STEP] });
    await request(app).get("/cases/c1/playbook");                        // prime the derived task
    const del = await request(app).delete("/cases/c1/playbook/next_step:ns1");
    expect(del.status).toBe(204);
    const after = await request(app).get("/cases/c1/playbook");
    const task = after.body.tasks.find((t: { id: string }) => t.id === "next_step:ns1");
    expect(task).toBeDefined();
    expect(task.status).toBe("skipped");
  });

  it("rejects an empty title (400) and a missing task (404)", async () => {
    const { app } = await freshPlaybookApp({});
    expect((await request(app).post("/cases/c1/playbook").send({ title: "  " })).status).toBe(400);
    expect((await request(app).patch("/cases/c1/playbook/nope").send({ status: "done" })).status).toBe(404);
    expect((await request(app).delete("/cases/c1/playbook/nope")).status).toBe(404);
  });

  it("returns 501 when no playbook store is configured", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-playbook-off-"));
    const store = new CaseStore(root);
    const off = createApp(store, { stateStore: new StateStore(store) });
    await request(off).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    expect((await request(off).get("/cases/c1/playbook")).status).toBe(501);
  });

  it("PUT /playbook/control toggles IR templates, expanding a Critical finding into phase tasks", async () => {
    const { app } = await freshPlaybookApp({ findings: [CRIT_FINDING] });
    const before = await request(app).get("/cases/c1/playbook");
    expect(before.body.control).toEqual({ useTemplates: false });
    expect(before.body.tasks.map((t: { id: string }) => t.id)).toEqual(["finding:f1"]);   // single task by default

    const put = await request(app).put("/cases/c1/playbook/control").send({ useTemplates: true });
    expect(put.status).toBe(200);
    expect(put.body.control).toEqual({ useTemplates: true });
    expect(put.body.tasks.map((t: { id: string }) => t.id)).toEqual([
      "finding:f1:contain", "finding:f1:investigate", "finding:f1:eradicate", "finding:f1:recover",
    ]);

    // GET reflects the persisted setting and keeps the expanded tasks.
    const after = await request(app).get("/cases/c1/playbook");
    expect(after.body.control).toEqual({ useTemplates: true });
    expect(after.body.tasks).toHaveLength(4);
  });

  it("PUT /playbook/control rejects a non-boolean body (400)", async () => {
    const { app } = await freshPlaybookApp({});
    expect((await request(app).put("/cases/c1/playbook/control").send({ useTemplates: "yes" })).status).toBe(400);
  });
});
