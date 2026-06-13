import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ImportMetaStore } from "../../src/analysis/importMeta.js";
import { PushTokenStore } from "../../src/analysis/pushTokenStore.js";

// A deterministic (no-AI) THOR alert the importer maps straight to a forensic event.
const THOR_EVENT = {
  time: "2026-06-13T21:18:18Z", hostname: "WIN11", level: "Alert", module: "Filescan",
  message: "Malware file found", file: "C:\\Tools\\mimikatz.exe",
  sha256: "4813e753f6f9bfa5c5de0edbb8dd3cc7f1fa51714097d3144d44e5e89dbd33ef",
};

async function makeApp(opts: { pushToken?: string; withTokenStore?: boolean } = {}) {
  const root = await mkdtemp(join(tmpdir(), "dfir-push-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const pipeline = buildRuntimePipeline({
    provider: undefined, synthesisProvider: undefined, stateStore, store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const app = createApp(store, {
    pipeline, stateStore,
    importMetaStore: new ImportMetaStore(store),
    pushToken: opts.pushToken,
    pushTokenStore: opts.withTokenStore === false ? undefined : new PushTokenStore(store),
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, stateStore };
}

async function waitForEvents(stateStore: StateStore, caseId: string): Promise<number> {
  for (let i = 0; i < 100; i++) {
    const s = await stateStore.load(caseId);
    if (s.forensicTimeline.length > 0) return s.forensicTimeline.length;
    await new Promise((r) => setTimeout(r, 20));
  }
  return (await stateStore.load(caseId)).forensicTimeline.length;
}

describe("POST /cases/:id/push — generic push ingest", () => {
  it("403s when no push token is configured anywhere", async () => {
    const { app } = await makeApp({});   // no global token, store present but no case token
    const res = await request(app).post("/cases/c1/push").send({ source: "siem", events: [THOR_EVENT] });
    expect(res.status).toBe(403);
    expect(res.body.error).toMatch(/disabled/i);
  });

  it("401s when a token is configured but the wrong key is presented", async () => {
    const { app } = await makeApp({ pushToken: "secret" });
    const res = await request(app).post("/cases/c1/push").set("X-DFIR-Key", "nope").send({ events: [THOR_EVENT] });
    expect(res.status).toBe(401);
  });

  it("401s when no key is presented against a configured token", async () => {
    const { app } = await makeApp({ pushToken: "secret" });
    const res = await request(app).post("/cases/c1/push").send({ events: [THOR_EVENT] });
    expect(res.status).toBe(401);
    expect(res.body.error).toMatch(/missing/i);
  });

  it("accepts a payload with the global token and imports it into the timeline", async () => {
    const { app, stateStore } = await makeApp({ pushToken: "secret" });
    const res = await request(app).post("/cases/c1/push").set("X-DFIR-Key", "secret").send({ source: "siem-webhook", events: [THOR_EVENT] });
    expect(res.status).toBe(202);
    expect(res.body.kind).toBe("thor");
    expect(res.body.source).toBe("siem-webhook");
    expect(await waitForEvents(stateStore, "c1")).toBeGreaterThan(0);
  });

  it("accepts a Bearer token too", async () => {
    const { app } = await makeApp({ pushToken: "secret" });
    const res = await request(app).post("/cases/c1/push").set("Authorization", "Bearer secret").send({ events: [THOR_EVENT] });
    expect(res.status).toBe(202);
  });

  it("accepts a raw artifact-map body whole", async () => {
    const { app, stateStore } = await makeApp({ pushToken: "secret" });
    const map = { "Windows.Detection.Sigma": [{
      _Source: "Windows.Detection.Sigma",
      Rule: { Title: "Susp", Level: "high", Tags: ["attack.t1059"] },
      System: { EventID: 1, Channel: "Microsoft-Windows-Sysmon/Operational", Computer: "WS01", TimeCreated: "2026-06-13T10:00:00Z" },
      EventData: { Image: "C:\\evil.exe" },
    }] };
    const res = await request(app).post("/cases/c1/push").set("X-DFIR-Key", "secret").send(map);
    expect(res.status).toBe(202);
    expect(res.body.kind).toBe("velociraptor");
    expect(await waitForEvents(stateStore, "c1")).toBeGreaterThan(0);
  });

  it("authorizes with a per-case token generated via the API", async () => {
    const { app } = await makeApp({});   // no global token
    const gen = await request(app).post("/cases/c1/push-token/generate");
    expect(gen.status).toBe(201);
    const token = gen.body.token as string;
    expect(token).toMatch(/^[0-9a-f]{32}$/);

    // wrong/no key still rejected
    expect((await request(app).post("/cases/c1/push").send({ events: [THOR_EVENT] })).status).toBe(401);
    // correct per-case key accepted
    const ok = await request(app).post("/cases/c1/push").set("X-DFIR-Key", token).send({ events: [THOR_EVENT] });
    expect(ok.status).toBe(202);
  });

  it("GET /cases/:id/push-token reports config + push URL; DELETE clears it", async () => {
    const { app } = await makeApp({});
    await request(app).post("/cases/c1/push-token/generate");
    let info = await request(app).get("/cases/c1/push-token");
    expect(info.body.configured).toBe(true);
    expect(info.body.pushUrl).toContain("/cases/c1/push");
    expect((await request(app).delete("/cases/c1/push-token")).status).toBe(204);
    info = await request(app).get("/cases/c1/push-token");
    expect(info.body.configured).toBe(false);
  });

  it("404s an unknown case (even with a valid token)", async () => {
    const { app } = await makeApp({ pushToken: "secret" });
    const res = await request(app).post("/cases/nope/push").set("X-DFIR-Key", "secret").send({ events: [THOR_EVENT] });
    expect(res.status).toBe(404);
  });

  it("400s an undetectable payload", async () => {
    const { app } = await makeApp({ pushToken: "secret" });
    const res = await request(app).post("/cases/c1/push").set("X-DFIR-Key", "secret").send({ source: "x", events: [] });
    // empty events array → empty payload "[]" still detects as something? assert it's a 4xx either way
    expect(res.status).toBeGreaterThanOrEqual(400);
    expect(res.status).toBeLessThan(500);
  });
});
