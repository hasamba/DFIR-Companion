import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";

const logs = vi.hoisted(() => ({ lines: [] as string[] }));
vi.mock("../../src/logging/serverLogger.js", async (orig) => {
  const real = await orig<typeof import("../../src/logging/serverLogger.js")>();
  return {
    ...real,
    logLine: (m: string) => logs.lines.push(m),
    warnLine: (m: string) => logs.lines.push(m),
  };
});

import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, getServerLogger } from "../../src/server.js";
import { resolveRequestPolicy } from "../../src/auth/policy.js";
import { ServerSetStore } from "../../src/integrations/serverSets/serverSetStore.js";
import { deriveServerSetKey } from "../../src/integrations/serverSets/secretBox.js";
import type { IrisSettings, ServerSetInput } from "../../src/integrations/serverSets/types.js";
import { createServerClients, type ServerClientBuilders } from "../../src/composition/serverSetClients.js";
import { createVeloHuntStatusTimers } from "../../src/composition/veloHuntStatusTimers.js";
import { IrisExportStore } from "../../src/integrations/iris/irisExportStore.js";
import { VeloHuntStore, type VeloHuntJob } from "../../src/analysis/veloHuntStore.js";
import { VeloMonitorStore, type VeloMonitor } from "../../src/analysis/veloMonitorStore.js";
import { ActivityLogStore } from "../../src/analysis/activityLog.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ReportWriter } from "../../src/reports/reportWriter.js";
import { buildRuntimePipeline } from "../../src/server.js";
import type { IrisClient } from "../../src/integrations/iris/irisClient.js";
import type { AppOptions } from "../../src/composition/appOptions.js";

const KEY = "iris-key-sentinel-alpha";
let dir: string;
let sets: ServerSetStore;
let cases: CaseStore;
let irisCreates: Array<{ url: string; name: string }>;
let irisExisting: Set<string>;
let monitorStore: VeloMonitorStore;

const builders: ServerClientBuilders = {
  iris: (s: IrisSettings) =>
    ({
      ping: async () => undefined,
      findCaseByName: async (name: string) =>
        irisExisting.has(`${s.url}|${name}`) ? { caseId: 1, caseName: name } : null,
      createCase: async (b: { case_name: string }) => {
        irisCreates.push({ url: s.url, name: b.case_name });
        irisExisting.add(`${s.url}|${b.case_name}`);
        return { caseId: 2, caseName: b.case_name };
      },
      setSummary: async () => undefined,
      iocTypeMap: async () => new Map(),
      assetTypeMap: async () => new Map(),
      eventCategoryMap: async () => new Map(),
      taskStatusMap: async () => new Map([["to do", 1]]),
      listAssets: async () => [],
      addAsset: async () => 1,
      listIocs: async () => [],
      addIoc: async () => 1,
      listEvents: async () => [],
      addEvent: async () => 1,
      listTasks: async () => [],
      addTask: async () => 1,
      listDirectories: async () => [],
      addDirectory: async () => 1,
      deleteDirectory: async () => undefined,
      addNote: async () => 1,
    }) as unknown as IrisClient,
  timesketch: () => {
    throw new Error("unused");
  },
  velociraptor: () => {
    throw new Error("unused");
  },
};

const set = (name: string, host: string): ServerSetInput => ({
  name,
  iris: { url: `https://${host}.example.com`, apiKey: KEY },
});

const monitor = (id: string): VeloMonitor => ({
  id,
  clientId: "C.1",
  artifact: "Windows.Events.ProcessCreation",
  pollSeconds: 60,
  cursor: 0,
  status: "stopped",
  createdAt: "2026-01-01T00:00:00.000Z",
});

const job = (huntId: string): VeloHuntJob => ({
  bundleId: "b",
  bundleName: "Bundle",
  artifacts: ["Windows.Sys.Pslist"],
  huntId,
  launchedAt: "2026-01-01T00:00:00.000Z",
  waitMinutes: 10,
  collectAt: "2026-01-01T00:10:00.000Z",
  status: "running",
});

let activity: ActivityLogStore;
let irisExport: IrisExportStore;
let huntStore: VeloHuntStore;
let setA: string;
let setB: string;

async function makeApp(over: Partial<AppOptions> = {}) {
  const stateStore = new StateStore(cases);
  const pipeline = buildRuntimePipeline({
    provider: undefined,
    synthesisProvider: undefined,
    stateStore,
    store: cases,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const app = createApp(cases, {
    pipeline,
    stateStore,
    reportWriter: new ReportWriter(cases, stateStore),
    serverClients: createServerClients(sets, {}, builders),
    serverSetStore: sets,
    irisExportStore: irisExport,
    veloHuntStore: huntStore,
    veloMonitorStore: monitorStore,
    activityLogStore: activity,
    ...over,
  });
  await request(app)
    .post("/cases")
    .send({ caseId: "c1", name: "Case c1", investigator: "i", aiProvider: null, serverSetId: setA });
  return app;
}

async function seedWork() {
  await irisExport.record("c1", "iris-case-one");
  await huntStore.upsert("c1", job("H.1"));
  await huntStore.upsert("c1", job("H.2"));
  await monitorStore.upsert("c1", monitor("m1"));
  await monitorStore.upsert("c1", monitor("m2"));
}

beforeEach(() => {
  logs.lines = [];
  irisCreates = [];
  irisExisting = new Set();
  dir = mkdtempSync(join(tmpdir(), "ss-change-"));
  sets = new ServerSetStore(join(dir, "server-sets"), deriveServerSetKey(Buffer.alloc(32, 7)));
  cases = new CaseStore(join(dir, "cases"));
  activity = new ActivityLogStore(cases);
  irisExport = new IrisExportStore(cases);
  huntStore = new VeloHuntStore(cases);
  monitorStore = new VeloMonitorStore(cases);
  setA = sets.create(set("Alpha", "alpha")).id;
  setB = sets.create(set("Bravo", "bravo")).id;
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

describe("POST /cases/:id/server-set policy", () => {
  it("needs a case administrator; the GET stays a read", () => {
    expect(resolveRequestPolicy("POST", "/cases/c1/server-set")).toEqual({
      kind: "case",
      permission: "admin",
      caseId: "c1",
    });
    expect(resolveRequestPolicy("GET", "/cases/c1/server-set")).toEqual({
      kind: "case",
      permission: "read",
      caseId: "c1",
    });
  });
});

describe("POST /cases/:id/server-set", () => {
  it("rejects a missing setId (400) and an unknown set (404)", async () => {
    const app = await makeApp();
    expect((await request(app).post("/cases/c1/server-set").send({})).status).toBe(400);
    expect((await request(app).post("/cases/c1/server-set").send({ setId: 5 })).status).toBe(400);
    const res = await request(app).post("/cases/c1/server-set").send({ setId: "nope" });
    expect(res.status).toBe(404);
    expect(res.body.error).toBe("Server set not found.");
  });

  it("answers changed:false for the set the case already uses", async () => {
    const app = await makeApp();
    const res = await request(app).post("/cases/c1/server-set").send({ setId: setA });
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ changed: false });
  });

  it("change with remote work and no confirm returns 409 and changes nothing", async () => {
    const app = await makeApp();
    await seedWork();
    const res = await request(app).post("/cases/c1/server-set").send({ setId: setB });
    expect(res.status).toBe(409);
    expect(res.body).toEqual({
      needsConfirm: true,
      work: { monitors: 2, irisCase: "iris-case-one", hunts: 2 },
    });
    expect(sets.caseSetId("c1")).toBe(setA);
    expect(await monitorStore.list("c1")).toHaveLength(2);
    expect((await irisExport.load("c1")).caseName).toBe("iris-case-one");
    expect(await huntStore.list("c1")).toHaveLength(2);
  });

  it("confirmed change stops monitors, forgets IRIS and hunts, relinks, and logs", async () => {
    const app = await makeApp();
    await seedWork();
    const res = await request(app).post("/cases/c1/server-set").send({ setId: setB, confirm: true });
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ changed: true, stopped: 2, hunts: 2, irisForgotten: true });
    expect(sets.caseSetId("c1")).toBe(setB);
    expect(await monitorStore.list("c1")).toEqual([]);
    expect((await irisExport.load("c1")).caseName).toBe("");
    expect(await huntStore.list("c1")).toEqual([]);
    const entries = await activity.load("c1");
    const text = entries.map((e) => e.detail).join("\n");
    expect(text).toContain(
      "Server set changed from 'Alpha' to 'Bravo': 2 monitors stopped, IRIS link 'iris-case-one' forgotten, 2 hunts forgotten",
    );
    expect(text).not.toContain("example.com");
    expect(JSON.stringify(res.body)).not.toContain(KEY);
  });

  it("change with no remote work needs no confirm", async () => {
    const app = await makeApp();
    const res = await request(app).post("/cases/c1/server-set").send({ setId: setB });
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ changed: true, stopped: 0, hunts: 0, irisForgotten: false });
    const detail = (await activity.load("c1")).map((e) => e.detail).join("\n");
    expect(detail).toContain("Server set changed from 'Alpha' to 'Bravo'");
  });

  it("change completes when the old server release throws", async () => {
    const failing = Object.create(monitorStore) as VeloMonitorStore;
    failing.remove = async () => {
      throw new Error("release failed");
    };
    const errorLog = vi.spyOn(getServerLogger(), "error").mockImplementation(() => undefined);
    const app = await makeApp({ veloMonitorStore: failing });
    await seedWork();
    const res = await request(app).post("/cases/c1/server-set").send({ setId: setB, confirm: true });
    expect(res.status).toBe(200);
    expect(sets.caseSetId("c1")).toBe(setB);
    expect(res.body.irisForgotten).toBe(true);
    const released = errorLog.mock.calls
      .map((c) => String(c[0]))
      .filter((l) => l.includes("could not be released"));
    errorLog.mockRestore();
    expect(released).toHaveLength(2); // one secret-free line per failed monitor
    expect(released.join("\n")).not.toContain("example.com");
  });

  it("evidence is untouched", async () => {
    const app = await makeApp();
    await seedWork();
    const files = ["events.jsonl", "iocs.json"].map((f) => join(cases.caseDir("c1"), f));
    for (const f of files) {
      try {
        writeFileSync(f, `sample ${f}`, { flag: "wx" });
      } catch {
        /* already present */
      }
    }
    const before = files.map((f) => readFileSync(f));
    await request(app).post("/cases/c1/server-set").send({ setId: setB, confirm: true });
    const after = files.map((f) => readFileSync(f));
    after.forEach((b, i) => expect(b.equals(before[i])).toBe(true));
  });

  it("next IRIS push after change creates a new IRIS case", async () => {
    const app = await makeApp();
    await request(app).post("/cases/c1/push/iris").send({});
    expect(irisCreates).toHaveLength(1);
    const again = await request(app).post("/cases/c1/push/iris").send({});
    expect(again.body.created).toBe(false); // same set: updated
    await request(app).post("/cases/c1/server-set").send({ setId: setB, confirm: true });
    const after = await request(app).post("/cases/c1/push/iris").send({});
    expect(after.status).toBe(200);
    expect(after.body.created).toBe(true);
    expect(irisCreates.at(-1)?.url).toBe("https://bravo.example.com");
  });
});

describe("hunt timers on a set change", () => {
  it("a pending status poll for the case does not fire after the change", async () => {
    vi.useFakeTimers();
    try {
      const get = vi.fn(async () => null);
      const timers = createVeloHuntStatusTimers({
        store: cases,
        options: { veloHuntStore: { get } } as unknown as AppOptions,
        startVeloHuntCollect: vi.fn(),
      });
      timers.scheduleVeloHuntStatusPoll("c1", "H.1");
      timers.scheduleVeloHuntStatusPoll("c2", "H.9");
      timers.stopVeloHuntStatusPollsForCase("c1");
      await vi.advanceTimersByTimeAsync(5 * 60_000);
      expect(get).toHaveBeenCalledTimes(1);
      expect(get).toHaveBeenCalledWith("c2", "H.9");
    } finally {
      vi.useRealTimers();
    }
  });
});
