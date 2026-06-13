import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { VelociraptorClientStore } from "../../src/analysis/velociraptorClientStore.js";
import { VelociraptorClient, type VqlRunner, type VelociraptorApiConfig } from "../../src/integrations/velociraptor/velociraptorApi.js";

const cfg: VelociraptorApiConfig = {
  apiConfigPath: "/x/api.yaml", binary: "velociraptor", timeoutMs: 5000, maxRows: 1000, maxOutputBytes: 1024 * 1024,
};

// A runner that returns one enrolled client for clients(), or throws (server down).
const upRunner: VqlRunner = async (statements) => {
  if (statements[0].includes("clients()")) return { rows: [{ client_id: "C.111", os_info: { hostname: "WS1", fqdn: "ws1.lab" } }], raw: "" };
  return { rows: [], raw: "" };
};
const downRunner: VqlRunner = async () => { throw new Error("connection refused"); };

async function makeApp(rebuild: () => VelociraptorClient | undefined) {
  const root = await mkdtemp(join(tmpdir(), "dfir-veloreconnect-"));
  const store = new CaseStore(root);
  const velociraptorClientStore = new VelociraptorClientStore(join(dirname(root), "velociraptor", "clients.json"));
  const app = createApp(store, {
    velociraptorClient: undefined,            // not configured / down at boot
    velociraptorClientStore,
    rebuildVelociraptorClient: rebuild,
  });
  return { app, velociraptorClientStore };
}

describe("POST /velociraptor/reconnect", () => {
  it("rebuilds the client + refreshes the inventory when the server is up", async () => {
    const { app } = await makeApp(() => new VelociraptorClient(cfg, upRunner));

    // Before reconnect: not configured.
    expect((await request(app).get("/health")).body.velociraptorEnabled).toBe(false);

    const res = await request(app).post("/velociraptor/reconnect");
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ configured: true, ok: true, clients: 1 });

    // The live client is now set — health + inventory reflect it without a restart.
    expect((await request(app).get("/health")).body.velociraptorEnabled).toBe(true);
    const inv = (await request(app).get("/velociraptor/clients")).body;
    expect(inv.clients.map((c: { clientId: string }) => c.clientId)).toContain("C.111");
  });

  it("reports configured-but-unreachable when the rebuilt client can't reach the server", async () => {
    const { app } = await makeApp(() => new VelociraptorClient(cfg, downRunner));
    const res = await request(app).post("/velociraptor/reconnect");
    expect(res.status).toBe(200);
    expect(res.body.configured).toBe(true);
    expect(res.body.ok).toBe(false);
    expect(res.body.error).toMatch(/connection refused/);
  });

  it("reports not-configured when no API config is present", async () => {
    const { app } = await makeApp(() => undefined);
    const res = await request(app).post("/velociraptor/reconnect");
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ configured: false, ok: false });
    expect((await request(app).get("/health")).body.velociraptorEnabled).toBe(false);
  });

  it("GET /velociraptor/status reports configured + inventory freshness", async () => {
    const { app } = await makeApp(() => new VelociraptorClient(cfg, upRunner));
    let status = (await request(app).get("/velociraptor/status")).body;
    expect(status.configured).toBe(false);
    await request(app).post("/velociraptor/reconnect");
    status = (await request(app).get("/velociraptor/status")).body;
    expect(status.configured).toBe(true);
    expect(status.clients).toBe(1);
  });
});
