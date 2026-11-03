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
import type {
  IrisSettings,
  ServerSetInput,
  VelociraptorSettings,
} from "../../src/integrations/serverSets/types.js";
import { createServerClients, type ServerClientBuilders } from "../../src/composition/serverSetClients.js";
import { createVeloHuntStatusTimers } from "../../src/composition/veloHuntStatusTimers.js";
import { IrisExportStore } from "../../src/integrations/iris/irisExportStore.js";
import { VeloHuntStore, type VeloHuntJob } from "../../src/analysis/veloHuntStore.js";
import { VeloMonitorStore, type VeloMonitor } from "../../src/analysis/veloMonitorStore.js";
import { ActivityLogStore } from "../../src/analysis/activityLog.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ReportWriter } from "../../src/reports/reportWriter.js";
import { buildRuntimePipeline } from "../../src/server.js";
import { VelociraptorClient, type VqlRunner } from "../../src/integrations/velociraptor/velociraptorApi.js";
import { ArtifactBundleStore } from "../../src/analysis/artifactBundleStore.js";
import { privateBundleDir } from "../helpers/bundleDir.js";
import type { IrisClient } from "../../src/integrations/iris/irisClient.js";
import type { AppOptions } from "../../src/composition/appOptions.js";

const KEY = "iris-key-sentinel-alpha";
let dir: string;
let sets: ServerSetStore;
let cases: CaseStore;
let irisCreates: Array<{ url: string; name: string }>;
let irisExisting: Set<string>;
let monitorStore: VeloMonitorStore;

const veloRunner: VqlRunner = async (statements) => {
  if (statements[0].includes("hunt(") && statements[0].includes("artifacts=["))
    return { rows: [{ Hunt: { HuntId: "H.TIMER1", state: "RUNNING" } }], raw: "" };
  return { rows: [], raw: "" };
};

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
  velociraptor: (s: VelociraptorSettings) =>
    new VelociraptorClient(
      {
        apiConfigPath: s.apiConfigPath,
        binary: "velociraptor",
        timeoutMs: 5000,
        maxRows: 1000,
        maxOutputBytes: 1024 * 1024,
      },
      veloRunner,
    ),
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

  it("change completes when the old set cannot release: records gone, one log line per monitor", async () => {
    const app = await makeApp();
    for (const id of ["m1", "m2"])
      await monitorStore.upsert("c1", { ...monitor(id), veloTableEntry: "added" });
    // Alpha has no Velociraptor tool, so the Client Monitoring entry cannot be released.
    const res = await request(app).post("/cases/c1/server-set").send({ setId: setB, confirm: true });
    expect(res.status).toBe(200);
    expect(res.body.stopped).toBe(2);
    expect(sets.caseSetId("c1")).toBe(setB);
    expect(await monitorStore.list("c1")).toEqual([]);
    const lines = logs.lines.filter((l) => l.includes("was not released"));
    expect(lines).toHaveLength(2);
    expect(lines.join("\n")).not.toMatch(/example\.com|api\.config|iris-key/);
  });

  it("a local failure removing a monitor record is retried, so no old monitor stays on the new set", async () => {
    const failedOnce = new Set<string>();
    const flaky = Object.create(monitorStore) as VeloMonitorStore;
    flaky.remove = async (caseId, id) => {
      if (!failedOnce.has(id)) {
        failedOnce.add(id);
        throw new Error("disk busy");
      }
      return monitorStore.remove(caseId, id);
    };
    const app = await makeApp({ veloMonitorStore: flaky });
    await seedWork();
    const res = await request(app).post("/cases/c1/server-set").send({ setId: setB, confirm: true });
    expect(res.status).toBe(200);
    expect(res.body.stopped).toBe(2);
    expect(await monitorStore.list("c1")).toEqual([]);
  });

  it("monitors are released while the OLD set is still linked", async () => {
    const seen: Array<string | undefined> = [];
    const spy = Object.create(monitorStore) as VeloMonitorStore;
    spy.remove = async (caseId, id) => {
      seen.push(sets.caseSetId(caseId));
      return monitorStore.remove(caseId, id);
    };
    const app = await makeApp({ veloMonitorStore: spy });
    await seedWork();
    await request(app).post("/cases/c1/server-set").send({ setId: setB, confirm: true });
    expect(seen).toEqual([setA, setA]);
  });

  it("two concurrent confirmed changes are serialized and audited in order", async () => {
    const app = await makeApp();
    await seedWork();
    const setC = sets.create(set("Charlie", "charlie")).id;
    const [r1, r2] = await Promise.all([
      request(app).post("/cases/c1/server-set").send({ setId: setB, confirm: true }),
      request(app).post("/cases/c1/server-set").send({ setId: setC, confirm: true }),
    ]);
    expect([r1.status, r2.status]).toEqual([200, 200]);
    const details = (await activity.load("c1"))
      .map((e) => e.detail)
      .filter((d) => d.startsWith("Server set changed"));
    expect(details).toHaveLength(2);
    const first = details.find((d) => d.includes("from 'Alpha'"))!;
    expect(first).toContain("2 monitors stopped");
    const firstTarget = /to '(\w+)'/.exec(first)![1];
    const second = details.find((d) => d !== first)!;
    expect(second).toContain(`from '${firstTarget}'`);
    expect(second).not.toContain("monitors stopped");
    const last = /to '(\w+)'/.exec(second)![1];
    expect(sets.get(sets.caseSetId("c1")!)?.name).toBe(last);
  });

  it("a failure after monitors stopped answers 500 with a clear message and logs the partial result", async () => {
    const broken = Object.create(irisExport) as IrisExportStore;
    broken.clear = async () => {
      throw new Error("ENOENT /secret/path");
    };
    const errorLog = vi.spyOn(getServerLogger(), "error").mockImplementation(() => undefined);
    const app = await makeApp({ irisExportStore: broken });
    await seedWork();
    const res = await request(app).post("/cases/c1/server-set").send({ setId: setB, confirm: true });
    const lines = errorLog.mock.calls.map((c) => String(c[0]));
    errorLog.mockRestore();
    expect(res.status).toBe(500);
    expect(res.body.error).toBe("The server set change did not finish. Check the server log and try again.");
    expect(sets.caseSetId("c1")).toBe(setA);
    const partial = lines.find((l) => l.includes("did not finish"));
    expect(partial).toContain("2 monitors stopped");
    expect(partial).not.toContain("/secret/path");
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

describe("hunt timers on a set change (real route)", () => {
  it("a pending collect timer and status poll of the case do not fire after a confirmed change", async () => {
    const velo = (name: string): ServerSetInput => ({
      name,
      velociraptor: { apiConfigPath: `/srv/${name}/api.config.yaml` },
    });
    const v1 = sets.create(velo("VeloOne")).id;
    const v2 = sets.create(velo("VeloTwo")).id;
    const get = vi.spyOn(huntStore, "get");
    const app = await makeApp({
      artifactBundleStore: new ArtifactBundleStore(privateBundleDir(dir)),
    });
    sets.linkCase("c1", v1);
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] }); // before launch: the route arms the timers
    const launched = await request(app)
      .post("/cases/c1/velociraptor/run-bundle")
      .send({ bundleId: "super-timeline-triage", waitMinutes: 1 });
    expect(launched.status).toBe(202);
    get.mockClear();
    try {
      const res = await request(app).post("/cases/c1/server-set").send({ setId: v2, confirm: true });
      expect(res.status).toBe(200);
      expect(res.body.hunts).toBe(1);
      await vi.advanceTimersByTimeAsync(10 * 60_000);
      expect(get).not.toHaveBeenCalled();
    } finally {
      vi.useRealTimers();
    }
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
