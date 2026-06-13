import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ImportMetaStore } from "../../src/analysis/importMeta.js";
import { VeloMonitorStore } from "../../src/analysis/veloMonitorStore.js";
import { VelociraptorClient, type VqlRunner, type VelociraptorApiConfig } from "../../src/integrations/velociraptor/velociraptorApi.js";

const veloCfg: VelociraptorApiConfig = {
  apiConfigPath: "/x/api.yaml", binary: "velociraptor", timeoutMs: 5000, maxRows: 1000, maxOutputBytes: 1024 * 1024,
};

// A Sysmon EID 1 process-creation monitoring row the Velociraptor importer maps to an event.
const PROC_ROW = {
  System: { EventID: { Value: 1 }, Channel: "Microsoft-Windows-Sysmon/Operational", Computer: "WS01", TimeCreated: "2026-06-13T10:00:00Z" },
  EventData: { Image: "C:\\Windows\\System32\\cmd.exe", CommandLine: "cmd /c whoami", ParentImage: "C:\\evil.exe" },
  _ts: 1_780_000_100,
};

const runner: VqlRunner = async (statements) => {
  const p = statements[0];
  if (p.includes("artifact_definitions()") && p.includes("client_event")) {
    return { rows: [
      { name: "Windows.Events.ProcessCreation", description: "Process creation events", type: "CLIENT_EVENT" },
      { name: "Windows.Events.DNSQueries", description: "DNS queries", type: "CLIENT_EVENT" },
    ], raw: "" };
  }
  if (p.includes("GetClientMonitoringState()")) {
    return { rows: [{ artifact: "Windows.Events.ProcessCreation" }, { artifact: "Windows.Events.DNSQueries" }], raw: "" };
  }
  if (p.includes("source(") && p.includes("artifact=")) {
    return { rows: [PROC_ROW], raw: "" };
  }
  return { rows: [], raw: "" };
};

async function makeApp(runnerOverride: VqlRunner = runner) {
  const root = await mkdtemp(join(tmpdir(), "dfir-velomon-route-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const pipeline = buildRuntimePipeline({
    provider: undefined, synthesisProvider: undefined, stateStore, store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const app = createApp(store, {
    pipeline, stateStore,
    importMetaStore: new ImportMetaStore(store),
    velociraptorClient: new VelociraptorClient(veloCfg, runnerOverride),
    veloMonitorStore: new VeloMonitorStore(store),
    veloMonitorPollSeconds: 30,
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, stateStore };
}

describe("Velociraptor live monitors — routes", () => {
  it("lists CLIENT_EVENT artifacts for the picker", async () => {
    const { app } = await makeApp();
    const res = await request(app).get("/velociraptor/event-artifacts");
    expect(res.status).toBe(200);
    expect(res.body.artifacts.map((a: { name: string }) => a.name)).toContain("Windows.Events.ProcessCreation");
  });

  it("starts a monitor, lists it active, then stops + deletes it", async () => {
    const { app } = await makeApp();
    const start = await request(app).post("/cases/c1/velociraptor/monitors")
      .send({ clientId: "C.abc123", artifact: "Windows.Events.ProcessCreation", pollSeconds: 15, hostname: "WS01" });
    expect(start.status).toBe(202);
    expect(start.body.monitor.id).toBe("C.abc123__Windows.Events.ProcessCreation");
    expect(start.body.monitor.pollSeconds).toBe(15);
    expect(start.body.monitor.cursor).toBeGreaterThan(0);   // starts at "now", no history backfill

    const list = (await request(app).get("/cases/c1/velociraptor/monitors")).body;
    expect(list).toHaveLength(1);
    expect(list[0].status).toBe("active");

    const mid = start.body.monitor.id;
    expect((await request(app).post(`/cases/c1/velociraptor/monitors/${encodeURIComponent(mid)}/stop`)).status).toBe(200);
    expect((await request(app).get("/cases/c1/velociraptor/monitors")).body[0].status).toBe("stopped");

    expect((await request(app).delete(`/cases/c1/velociraptor/monitors/${encodeURIComponent(mid)}`)).status).toBe(204);
    expect((await request(app).get("/cases/c1/velociraptor/monitors")).body).toHaveLength(0);
  });

  it("validates clientId + artifact", async () => {
    const { app } = await makeApp();
    expect((await request(app).post("/cases/c1/velociraptor/monitors").send({ clientId: "bad", artifact: "Windows.Events.ProcessCreation" })).status).toBe(400);
    expect((await request(app).post("/cases/c1/velociraptor/monitors").send({ clientId: "C.abc", artifact: "bad name!" })).status).toBe(400);
  });

  it("starts an ALL-clients monitor (allClients:true, no specific endpoint) and ingests across the fleet", async () => {
    const { app, stateStore } = await makeApp();
    const start = await request(app).post("/cases/c1/velociraptor/monitors")
      .send({ allClients: true, artifact: "Windows.Events.ProcessCreation", pollSeconds: 30 });
    expect(start.status).toBe(202);
    expect(start.body.monitor.allClients).toBe(true);
    expect(start.body.monitor.clientId).toBe("*");
    expect(start.body.monitor.id).toBe("*__Windows.Events.ProcessCreation");
    expect(start.body.monitor.hostname).toBe("all clients");

    const poll = await request(app).post(`/cases/c1/velociraptor/monitors/${encodeURIComponent(start.body.monitor.id)}/poll`);
    expect(poll.body.monitor.addedEvents).toBeGreaterThan(0);
    expect((await stateStore.load("c1")).forensicTimeline.length).toBeGreaterThan(0);
  });

  it("auto-monitor starts an all-clients monitor for every configured client-event artifact", async () => {
    const { app } = await makeApp();
    const auto = await request(app).post("/cases/c1/velociraptor/monitors/auto").send({});
    expect(auto.status).toBe(202);
    expect(auto.body.discovered).toEqual(["Windows.Events.ProcessCreation", "Windows.Events.DNSQueries"]);
    expect(auto.body.started).toHaveLength(2);

    const list = (await request(app).get("/cases/c1/velociraptor/monitors")).body;
    expect(list.map((m: { id: string }) => m.id).sort()).toEqual(["*__Windows.Events.DNSQueries", "*__Windows.Events.ProcessCreation"]);
    expect(list.every((m: { allClients: boolean }) => m.allClients === true)).toBe(true);
  });

  it("auto-monitor 422s with guidance when nothing is configured", async () => {
    const emptyRunner: VqlRunner = async (statements) => {
      if (statements[0].includes("GetClientMonitoringState()")) return { rows: [], raw: "" };
      return { rows: [], raw: "" };
    };
    const { app } = await makeApp(emptyRunner);
    const auto = await request(app).post("/cases/c1/velociraptor/monitors/auto").send({});
    expect(auto.status).toBe(422);
    expect(auto.body.error).toMatch(/Client Monitoring/i);
  });

  it("poll-now ingests new monitoring rows into the timeline + advances stats", async () => {
    const { app, stateStore } = await makeApp();
    const start = await request(app).post("/cases/c1/velociraptor/monitors")
      .send({ clientId: "C.abc123", artifact: "Windows.Events.ProcessCreation", pollSeconds: 30, hostname: "WS01" });
    const mid = start.body.monitor.id;

    const poll = await request(app).post(`/cases/c1/velociraptor/monitors/${encodeURIComponent(mid)}/poll`);
    expect(poll.status).toBe(200);
    expect(poll.body.monitor.status).toBe("active");
    expect(poll.body.monitor.addedEvents).toBeGreaterThan(0);
    expect(poll.body.monitor.polls).toBe(1);

    const state = await stateStore.load("c1");
    expect(state.forensicTimeline.length).toBeGreaterThan(0);
  });

  it("a poll that errors marks the monitor errored without advancing its cursor", async () => {
    const failRunner: VqlRunner = async (statements) => {
      const p = statements[0];
      if (p.includes("source(")) throw new Error("velo unreachable");
      return { rows: [], raw: "" };
    };
    const { app } = await makeApp(failRunner);
    const start = await request(app).post("/cases/c1/velociraptor/monitors")
      .send({ clientId: "C.abc123", artifact: "Windows.Events.ProcessCreation" });
    const mid = start.body.monitor.id;
    const before = start.body.monitor.cursor;

    const poll = await request(app).post(`/cases/c1/velociraptor/monitors/${encodeURIComponent(mid)}/poll`);
    expect(poll.body.monitor.status).toBe("error");
    expect(poll.body.monitor.lastError).toMatch(/unreachable/);
    expect(poll.body.monitor.cursor).toBe(before);   // not advanced — retried next tick
  });

  it("monitors route returns [] and start is 501 when Velociraptor is not configured", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-velomon-noclient-"));
    const store = new CaseStore(root);
    const bare = createApp(store, {});
    expect((await request(bare).get("/cases/c1/velociraptor/monitors")).status).toBe(200);
    expect((await request(bare).post("/cases/c1/velociraptor/monitors").send({ clientId: "C.x", artifact: "A.B" })).status).toBe(501);
  });
});
