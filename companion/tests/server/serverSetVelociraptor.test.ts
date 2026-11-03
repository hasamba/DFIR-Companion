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

  it("migration renames clients.json to the Testing set's file", () => {
    const inventoryDir = join(dir, "velociraptor");
    mkdirSync(inventoryDir);
    const content = JSON.stringify({ updatedAt: "2026-01-01T00:00:00Z", clients: [{ clientId: "C.1" }] });
    writeFileSync(join(inventoryDir, "clients.json"), content);
    seedServerSets(sets, { DFIR_VELOCIRAPTOR_API_CONFIG: "/x/api.yaml" }, [], { inventoryDir });
    const testingId = sets.defaultId()!;
    expect(existsSync(join(inventoryDir, "clients.json"))).toBe(false);
    expect(readFileSync(join(inventoryDir, `clients-${testingId}.json`), "utf8")).toBe(content);
  });
});
