import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
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
import { createApp } from "../../src/server.js";
import { ServerSetStore } from "../../src/integrations/serverSets/serverSetStore.js";
import { deriveServerSetKey } from "../../src/integrations/serverSets/secretBox.js";
import type { VelociraptorSettings } from "../../src/integrations/serverSets/types.js";
import { createServerClients } from "../../src/composition/serverSetClients.js";
import { createVeloMonitors } from "../../src/composition/veloMonitors.js";
import { createVeloHunts } from "../../src/composition/veloHunts.js";
import { VeloHuntStore } from "../../src/analysis/veloHuntStore.js";
import { startPostListenTasks } from "../../src/composition/maintenanceTasks.js";
import { seedServerSets } from "../../src/composition/serverSetMigration.js";
import { VeloMonitorStore, type VeloMonitor } from "../../src/analysis/veloMonitorStore.js";
import { VelociraptorClientStore } from "../../src/analysis/velociraptorClientStore.js";
import { UpdateCheckStore } from "../../src/analysis/updateCheckStore.js";
import {
  VelociraptorClient,
  type VqlRunner,
  type VelociraptorApiConfig,
} from "../../src/integrations/velociraptor/velociraptorApi.js";
import type { AppOptions } from "../../src/composition/appOptions.js";
import { ArtifactBundleStore } from "../../src/analysis/artifactBundleStore.js";
import { privateBundleDir } from "../helpers/bundleDir.js";
import { POLL_TIMEOUT_MS } from "../helpers/poll.js";

const cfg = (apiConfigPath: string): VelociraptorApiConfig => ({
  apiConfigPath,
  binary: "velociraptor",
  timeoutMs: 5000,
  maxRows: 1000,
  maxOutputBytes: 1024 * 1024,
});

let dir: string;
let sets: ServerSetStore;
let cases: CaseStore;
// One fake runner per API config path: the path is what tells the sets apart.
let runners: Record<string, ReturnType<typeof vi.fn<VqlRunner>>>;

const runnerFor = (path: string) => {
  runners[path] ??= vi.fn<VqlRunner>(async (statements) => {
    if (statements[0].includes("FROM clients()")) {
      return {
        rows: [{ client_id: `C.${path.replace(/\W/g, "")}`, os_info: { hostname: "ws01" } }],
        raw: "",
      };
    }
    return { rows: [], raw: "" };
  });
  return runners[path];
};
const velo = (path: string): VelociraptorSettings => ({ apiConfigPath: path });
const clients = () =>
  createServerClients(
    sets,
    {},
    { velociraptor: (s) => new VelociraptorClient(cfg(s.apiConfigPath), runnerFor(s.apiConfigPath)) },
  );

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "ss-velo-"));
  sets = new ServerSetStore(join(dir, "server-sets"), deriveServerSetKey(Buffer.alloc(32, 7)));
  mkdirSync(join(dir, "cases"));
  cases = new CaseStore(join(dir, "cases"));
  runners = {};
  logs.lines.length = 0;
});
afterEach(() => {
  vi.useRealTimers();
  rmSync(dir, { recursive: true, force: true });
});

describe("Velociraptor per server set", () => {
  it("case VQL run uses the case's Velociraptor set", async () => {
    const a = sets.create({ name: "A", velociraptor: velo("/a/api.yaml") });
    const b = sets.create({ name: "B", velociraptor: velo("/b/api.yaml") });
    sets.setDefault(a.id);
    const app = createApp(cases, { serverClients: clients() });
    await request(app).post("/cases").send({ caseId: "c2", name: "n", investigator: "i", aiProvider: null });
    sets.linkCase("c2", b.id);
    const res = await request(app)
      .post("/velociraptor/run")
      .send({ vql: "SELECT 1 FROM info()", caseId: "c2" });
    expect(res.status).toBe(200);
    expect(runnerFor("/b/api.yaml")).toHaveBeenCalled();
    expect(runnerFor("/a/api.yaml")).not.toHaveBeenCalled();
  });

  it("monitor tick after set edit uses the new client", async () => {
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const s = sets.create({ name: "A", velociraptor: velo("/old/api.yaml") });
    sets.linkCase("c1", s.id);
    const monStore = new VeloMonitorStore(cases);
    const monitor: VeloMonitor = {
      id: "C.1__Windows.Events.ProcessCreation",
      clientId: "C.1",
      artifact: "Windows.Events.ProcessCreation",
      pollSeconds: 30,
      cursor: 1,
      status: "active",
      createdAt: new Date().toISOString(),
    };
    await monStore.upsert("c1", monitor);
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    const options = { veloMonitorStore: monStore, serverClients: clients() } as AppOptions;
    const m = createVeloMonitors({ store: cases, options, ingestStreamed: vi.fn() });
    m.scheduleVeloMonitor("c1", monitor);
    sets.update(s.id, { name: "A", velociraptor: velo("/new/api.yaml") });
    await vi.advanceTimersByTimeAsync(30_000);
    // The tick reads the monitor from disk first: wait for that real I/O, not for another tick.
    await vi.waitFor(() => expect(runnerFor("/new/api.yaml")).toHaveBeenCalled());
    expect(runnerFor("/old/api.yaml")).not.toHaveBeenCalled();
    m.stopVeloMonitorTimer("c1", monitor.id);
  });

  it("monitor tick for a case whose set was deleted skips and logs once", async () => {
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const gone = sets.create({ name: "Gone", velociraptor: velo("/gone/api.yaml") });
    sets.linkCase("c1", gone.id);
    const p = join(dir, "server-sets", "sets.json");
    writeFileSync(
      p,
      JSON.stringify(
        (JSON.parse(readFileSync(p, "utf8")) as { id: string }[]).filter((x) => x.id !== gone.id),
      ),
    );
    const monStore = new VeloMonitorStore(cases);
    const monitor: VeloMonitor = {
      id: "C.1__Windows.Events.ProcessCreation",
      clientId: "C.1",
      artifact: "Windows.Events.ProcessCreation",
      pollSeconds: 30,
      cursor: 1,
      status: "active",
      createdAt: new Date().toISOString(),
    };
    await monStore.upsert("c1", monitor);
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    const serverClients = clients();
    const resolves = vi.spyOn(serverClients, "forCase");
    const options = { veloMonitorStore: monStore, serverClients } as AppOptions;
    const m = createVeloMonitors({ store: cases, options, ingestStreamed: vi.fn() });
    m.scheduleVeloMonitor("c1", monitor);
    // Two ticks. Each reads the monitor from disk before it resolves the set: wait for that I/O.
    await vi.advanceTimersByTimeAsync(30_000);
    await vi.waitFor(() => expect(resolves).toHaveBeenCalledTimes(1));
    await vi.advanceTimersByTimeAsync(30_000);
    await vi.waitFor(() => expect(resolves).toHaveBeenCalledTimes(2));
    expect(runnerFor("/gone/api.yaml")).not.toHaveBeenCalled();
    expect(logs.lines.filter((l) => l.includes("server set was deleted"))).toHaveLength(1);
    m.stopVeloMonitorTimer("c1", monitor.id);
  });

  it("fleet refresh runs once per Velociraptor set", async () => {
    const a = sets.create({ name: "A", velociraptor: velo("/a/api.yaml") });
    const b = sets.create({ name: "B", velociraptor: velo("/b/api.yaml") });
    sets.create({ name: "None" });
    const inventoryDir = join(dir, "velociraptor");
    startPostListenTasks({
      store: cases,
      demoMode: false,
      serverSets: sets,
      serverClients: clients(),
      clientInventoryFor: (id) => new VelociraptorClientStore(join(inventoryDir, `clients-${id}.json`)),
      updateCheckStore: new UpdateCheckStore(join(dir, "update-check.json")),
      updateRepo: "",
    });
    await vi.waitFor(() => {
      expect(existsSync(join(inventoryDir, `clients-${a.id}.json`))).toBe(true);
      expect(existsSync(join(inventoryDir, `clients-${b.id}.json`))).toBe(true);
    });
    expect(runnerFor("/a/api.yaml")).toHaveBeenCalledTimes(1);
    expect(runnerFor("/b/api.yaml")).toHaveBeenCalledTimes(1);
    const inv = JSON.parse(readFileSync(join(inventoryDir, `clients-${b.id}.json`), "utf8"));
    expect(inv.clients[0].clientId).toBe("C.bapiyaml");
  });

  it("migration renames clients.json to the Default set's file", () => {
    const inventoryDir = join(dir, "velociraptor");
    mkdirSync(inventoryDir);
    const content = JSON.stringify({ updatedAt: "2026-01-01T00:00:00Z", clients: [{ clientId: "C.1" }] });
    writeFileSync(join(inventoryDir, "clients.json"), content);
    seedServerSets(sets, { DFIR_VELOCIRAPTOR_API_CONFIG: "/x/api.yaml" }, [], { inventoryDir });
    const testingId = sets.defaultId()!;
    expect(existsSync(join(inventoryDir, "clients.json"))).toBe(false);
    expect(readFileSync(join(inventoryDir, `clients-${testingId}.json`), "utf8")).toBe(content);
  });

  it("case-launched hunt and collection results come from the case's set, not the default", async () => {
    const a = sets.create({ name: "A", velociraptor: velo("/a/api.yaml") });
    const b = sets.create({ name: "B", velociraptor: velo("/b/api.yaml") });
    sets.setDefault(a.id);
    sets.linkCase("c2", b.id);
    const app = createApp(cases, { serverClients: clients() });
    const hunt = await request(app)
      .post("/velociraptor/hunt-results")
      .send({ huntId: "H.1", artifact: "Windows.System.Pslist", caseId: "c2" });
    expect(hunt.status).toBe(200);
    const flow = await request(app)
      .post("/velociraptor/collect-results")
      .send({ clientId: "C.1", flowId: "F.1", artifact: "Windows.System.Pslist", caseId: "c2" });
    expect(flow.status).toBe(200);
    expect(runnerFor("/b/api.yaml")).toHaveBeenCalled();
    expect(runnerFor("/a/api.yaml")).not.toHaveBeenCalled();
  });

  it("a named case that does not resolve is refused, never answered from the default set", async () => {
    const a = sets.create({ name: "A", velociraptor: velo("/a/api.yaml") });
    sets.setDefault(a.id);
    const app = createApp(cases, { serverClients: clients() });
    const res = await request(app)
      .post("/velociraptor/hunt-results")
      .send({ huntId: "H.1", artifact: "Windows.System.Pslist", caseId: "unlinked" });
    expect(res.status).toBe(409);
    const art = await request(app).get("/velociraptor/artifacts?caseId=unlinked");
    expect(art.status).toBe(409);
    expect(runnerFor("/a/api.yaml")).not.toHaveBeenCalled();
  });

  it("a hunt collect whose set does not resolve stays armed and runs once the set is fixed", async () => {
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const s = sets.create({ name: "A", velociraptor: velo("/a/api.yaml") });
    sets.linkCase("c1", s.id);
    const huntStore = new VeloHuntStore(cases);
    const now = new Date().toISOString();
    await huntStore.upsert("c1", {
      bundleId: "b1",
      bundleName: "Bundle",
      artifacts: ["Windows.System.Pslist"],
      huntId: "H.1",
      launchedAt: now,
      waitMinutes: 1,
      collectAt: now,
      status: "running",
    });
    const p = join(dir, "server-sets", "sets.json");
    const saved = readFileSync(p, "utf8");
    writeFileSync(p, "[]"); // the case's set is gone
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    const options = {
      veloHuntStore: huntStore,
      pipeline: {},
      serverClients: clients(),
    } as unknown as AppOptions;
    const hunts = createVeloHunts({ store: cases, options } as unknown as Parameters<
      typeof createVeloHunts
    >[0]);
    hunts.startVeloHuntCollect("c1", "H.1");
    await vi.waitFor(() => expect(hunts.veloHuntTimers.has("c1", "H.1")).toBe(true));
    expect(logs.lines.filter((l) => l.includes("server set was deleted"))).toHaveLength(1);
    writeFileSync(p, saved); // the set is back
    await vi.advanceTimersByTimeAsync(30_000);
    await vi.waitFor(() => expect(runnerFor("/a/api.yaml")).toHaveBeenCalled());
    hunts.stopVeloHuntStatusPoll("c1", "H.1");
  });
});

describe("an in-flight hunt collect across a set change", () => {
  it("a collect whose download resolves after a confirmed change never re-creates the forgotten hunt", async () => {
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const a = sets.create({ name: "A", velociraptor: velo("/a/api.yaml") });
    const b = sets.create({ name: "B", velociraptor: velo("/b/api.yaml") });
    sets.linkCase("c1", a.id);
    const huntStore = new VeloHuntStore(cases);
    const now = new Date().toISOString();
    await huntStore.upsert("c1", {
      bundleId: "b1",
      bundleName: "Bundle",
      artifacts: ["Windows.System.Pslist"],
      huntId: "H.1",
      launchedAt: now,
      waitMinutes: 1,
      collectAt: now,
      status: "running",
    });
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    let downloading = false;
    runners["/a/api.yaml"] = vi.fn<VqlRunner>(async (statements) => {
      if (statements.join("\n").includes("hunt_results(")) {
        downloading = true;
        await gate; // the download is in flight while the analyst changes the set
        return { rows: [{ Pid: 1, Name: "x.exe" }], raw: "" };
      }
      return { rows: [], raw: "" };
    });
    const upsert = vi.spyOn(huntStore, "upsert");
    const options = {
      veloHuntStore: huntStore,
      pipeline: {},
      serverClients: clients(),
    } as unknown as AppOptions;
    const persistEvidence = vi.fn(async () => ({ storedName: "e.json", importedAt: now, seq: 1 }));
    const hunts = createVeloHunts({
      store: cases,
      options,
      persistEvidence,
      resolveImportKind: () => "velociraptor",
      getControl: async () => ({ enabled: false }),
      importLock: { acquire: async () => () => undefined },
    } as unknown as Parameters<typeof createVeloHunts>[0]);
    hunts.startVeloHuntCollect("c1", "H.1");
    await vi.waitFor(() => expect(downloading).toBe(true));
    // The confirmed change: hunts forgotten, timers cancelled, case relinked.
    await huntStore.clear("c1");
    hunts.cancelVeloHuntTimersForCase("c1");
    sets.linkCase("c1", b.id);
    upsert.mockClear();
    release();
    await vi.waitFor(async () =>
      expect((await hunts.listVeloHuntJobViews("c1")).every((j) => !j.collectActive)).toBe(true),
    );
    await new Promise((r) => setTimeout(r, 50));
    expect(upsert).not.toHaveBeenCalled();
    expect(await huntStore.get("c1", "H.1")).toBeNull();
    expect(hunts.veloHuntTimers.has("c1", "H.1")).toBe(false);
    expect(runnerFor("/b/api.yaml")).not.toHaveBeenCalled();
    expect(persistEvidence).not.toHaveBeenCalled(); // nothing from the old server lands in the case
  });
  it("a relink alone (hunt still stored) stops the in-flight collect from writing back", async () => {
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const a = sets.create({ name: "A", velociraptor: velo("/a/api.yaml") });
    const b = sets.create({ name: "B", velociraptor: velo("/b/api.yaml") });
    sets.linkCase("c1", a.id);
    const huntStore = new VeloHuntStore(cases);
    const now = new Date().toISOString();
    await huntStore.upsert("c1", {
      bundleId: "b1",
      bundleName: "Bundle",
      artifacts: ["Windows.System.Pslist"],
      huntId: "H.1",
      launchedAt: now,
      waitMinutes: 1,
      collectAt: now,
      status: "running",
    });
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    let downloading = false;
    runners["/a/api.yaml"] = vi.fn<VqlRunner>(async (statements) => {
      if (statements.join("\n").includes("hunt_results(")) {
        downloading = true;
        await gate; // the download is in flight while the analyst changes the set
        return { rows: [{ Pid: 1, Name: "x.exe" }], raw: "" };
      }
      return { rows: [], raw: "" };
    });
    const upsert = vi.spyOn(huntStore, "upsert");
    const options = {
      veloHuntStore: huntStore,
      pipeline: {},
      serverClients: clients(),
    } as unknown as AppOptions;
    const persistEvidence = vi.fn(async () => ({ storedName: "e.json", importedAt: now, seq: 1 }));
    const hunts = createVeloHunts({
      store: cases,
      options,
      persistEvidence,
      resolveImportKind: () => "velociraptor",
      getControl: async () => ({ enabled: false }),
      importLock: { acquire: async () => () => undefined },
    } as unknown as Parameters<typeof createVeloHunts>[0]);
    hunts.startVeloHuntCollect("c1", "H.1");
    await vi.waitFor(() => expect(downloading).toBe(true));
    // Only the link moves; the hunt record stays, so only the set-id guard can stop the write-back.
    sets.linkCase("c1", b.id);
    upsert.mockClear();
    release();
    await vi.waitFor(async () =>
      expect((await hunts.listVeloHuntJobViews("c1")).every((j) => !j.collectActive)).toBe(true),
    );
    await new Promise((r) => setTimeout(r, 50));
    expect(upsert).not.toHaveBeenCalled();
    expect(hunts.veloHuntTimers.has("c1", "H.1")).toBe(false);
    expect(runnerFor("/b/api.yaml")).not.toHaveBeenCalled();
    expect(persistEvidence).not.toHaveBeenCalled(); // nothing from the old server lands in the case
  });
});

describe("the case-less client list and time-scope preview follow the open case", () => {
  async function twoSetApp() {
    const a = sets.create({ name: "A", velociraptor: velo("/a/api.yaml") });
    const b = sets.create({ name: "B", velociraptor: velo("/b/api.yaml") });
    sets.setDefault(a.id);
    sets.linkCase("c2", b.id);
    const inventoryDir = join(dir, "velociraptor");
    const app = createApp(cases, {
      serverClients: clients(),
      clientInventoryFor: (id) => new VelociraptorClientStore(join(inventoryDir, `clients-${id}.json`)),
      artifactBundleStore: new ArtifactBundleStore(privateBundleDir(dir)),
    });
    return { app, a, b };
  }

  it("refresh and read of the client list with a caseId use that case's set and inventory", async () => {
    const { app } = await twoSetApp();
    const refreshed = await request(app).post("/velociraptor/clients/refresh").send({ caseId: "c2" });
    expect(refreshed.status).toBe(200);
    expect(refreshed.body.clients[0].clientId).toBe("C.bapiyaml");
    expect(refreshed.body.setName).toBe("B");
    expect(runnerFor("/a/api.yaml")).not.toHaveBeenCalled();
    const read = await request(app).get("/velociraptor/clients?caseId=c2");
    expect(read.status).toBe(200);
    expect(read.body.clients[0].clientId).toBe("C.bapiyaml");
    expect(read.body.setName).toBe("B");
    const def = await request(app).get("/velociraptor/clients");
    expect(def.body.clients).toEqual([]); // the default set's inventory was never refreshed
  });

  it("time-scope preview with a caseId asks that case's server", async () => {
    const { app } = await twoSetApp();
    const res = await request(app)
      .post("/velociraptor/bundles/super-timeline-triage/time-scope-preview")
      .send({ preset: "7d", caseId: "c2" });
    expect(res.status).toBe(200);
    expect(runnerFor("/b/api.yaml")).toHaveBeenCalled();
    expect(runnerFor("/a/api.yaml")).not.toHaveBeenCalled();
  });

  it("a named case without a set is refused on the two actions, never answered from the default set", async () => {
    const { app } = await twoSetApp();
    const r2 = await request(app).post("/velociraptor/clients/refresh").send({ caseId: "unlinked" });
    const r3 = await request(app)
      .post("/velociraptor/bundles/super-timeline-triage/time-scope-preview")
      .send({ preset: "7d", caseId: "unlinked" });
    expect([r2.status, r3.status]).toEqual([409, 409]);
    expect(runnerFor("/a/api.yaml")).not.toHaveBeenCalled();
  });

  // Settings reads the client list on open (#2462). "This case has no usable Velociraptor" is an
  // ordinary state there, so the read answers an empty list with 200 instead of a console-logged
  // 409/501, and it is still never answered from the default set's inventory.
  it("reading the client list for an unlinked case is an empty 200, never the default set's", async () => {
    const { app } = await twoSetApp();
    const filled = await request(app).post("/velociraptor/clients/refresh").send({});
    expect(filled.body.clients.length).toBeGreaterThan(0); // the default set's inventory is not empty
    const r1 = await request(app).get("/velociraptor/clients?caseId=unlinked");
    expect(r1.status).toBe(200);
    expect(r1.body).toEqual({ updatedAt: "", clients: [] });
  });

  it("reading the client list for a case whose set has no Velociraptor is an empty 200", async () => {
    const { app } = await twoSetApp();
    const noVelo = sets.create({ name: "No Velo", iris: { url: "https://iris.example.test", apiKey: "k" } });
    sets.linkCase("c3", noVelo.id);
    const r = await request(app).get("/velociraptor/clients?caseId=c3");
    expect(r.status).toBe(200);
    expect(r.body).toEqual({ updatedAt: "", clients: [] });
  });

  it("reading the client list keeps the 400 for a malformed caseId", async () => {
    const { app } = await twoSetApp();
    const r = await request(app).get("/velociraptor/clients?caseId=bad%20id%2F..");
    expect(r.status).toBe(400);
  });
});

describe("startup fleet inventory retries", () => {
  const start = () =>
    startPostListenTasks({
      store: cases,
      demoMode: false,
      serverSets: sets,
      serverClients: clients(),
      clientInventoryFor: (id) =>
        new VelociraptorClientStore(join(dir, "velociraptor", `clients-${id}.json`)),
      updateCheckStore: new UpdateCheckStore(join(dir, "update-check.json")),
      updateRepo: "",
    });
  const failing = (path: string) =>
    (runners[path] = vi.fn<VqlRunner>(async () => {
      throw new Error("server down");
    }));

  /** Wait, in real time, until the startup refresh has logged `text` (#2289). */
  const loggedLine = (text: string) =>
    vi.waitFor(() => expect(logs.lines.some((l) => l.includes(text))).toBe(true), {
      timeout: POLL_TIMEOUT_MS,
    });

  // Two waits on POLL_TIMEOUT_MS, plus room for the test's own work.
  it(
    "a retry uses the set's current Velociraptor, not the client from the first attempt",
    { timeout: POLL_TIMEOUT_MS * 3 },
    async () => {
      vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
      const s = sets.create({ name: "A", velociraptor: velo("/old/api.yaml") });
      const old = failing("/old/api.yaml");
      start();
      // The retry log is written right before the retry's setTimeout, so once it is there the
      // timer exists and the clock advance below is guaranteed to fire it.
      await loggedLine("server set 'A' startup inventory refresh failed (server down) — retrying in 30s");
      expect(old).toHaveBeenCalledTimes(1);
      sets.update(s.id, { name: "A", velociraptor: velo("/new/api.yaml") });
      await vi.advanceTimersByTimeAsync(30_000);
      // Wait for the END of the chain, not the runner call at its start. The inventory file is
      // written after the runner answers; returning earlier let afterEach's rmSync race that write
      // and fail the test with ENOTEMPTY on a busy CI runner (#2289).
      await loggedLine("server set 'A' inventory: 1 enrolled client(s)");
      expect(runnerFor("/new/api.yaml")).toHaveBeenCalled();
      expect(old).toHaveBeenCalledTimes(1);
    },
  );

  it("retries stop once the set is deleted or loses its Velociraptor", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    const gone = sets.create({ name: "Gone", velociraptor: velo("/gone/api.yaml") });
    const off = sets.create({ name: "Off", velociraptor: velo("/off/api.yaml") });
    const g = failing("/gone/api.yaml");
    const o = failing("/off/api.yaml");
    start();
    await vi.waitFor(() => expect(g).toHaveBeenCalledTimes(1));
    await vi.waitFor(() => expect(o).toHaveBeenCalledTimes(1));
    sets.remove(gone.id);
    sets.update(off.id, { name: "Off" });
    await vi.advanceTimersByTimeAsync(20 * 60_000);
    expect(g).toHaveBeenCalledTimes(1);
    expect(o).toHaveBeenCalledTimes(1);
  });
});
