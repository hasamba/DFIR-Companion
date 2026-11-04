import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { setInventories } from "../../src/analysis/velociraptorClientStore.js";
import { ServerSetStore } from "../../src/integrations/serverSets/serverSetStore.js";
import { deriveServerSetKey } from "../../src/integrations/serverSets/secretBox.js";
import { createServerClients } from "../../src/composition/serverSetClients.js";
import {
  VelociraptorClient,
  type VqlRunner,
  type VelociraptorApiConfig,
} from "../../src/integrations/velociraptor/velociraptorApi.js";

const cfg: VelociraptorApiConfig = {
  apiConfigPath: "/x/api.yaml",
  binary: "velociraptor",
  timeoutMs: 5000,
  maxRows: 1000,
  maxOutputBytes: 1024 * 1024,
};

// A runner that returns one enrolled client for clients(), or throws (server down).
const upRunner: VqlRunner = async (statements) => {
  if (statements[0].includes("clients()"))
    return { rows: [{ client_id: "C.111", os_info: { hostname: "WS1", fqdn: "ws1.lab" } }], raw: "" };
  return { rows: [], raw: "" };
};
const downRunner: VqlRunner = async () => {
  throw new Error("connection refused");
};

// The default server set names a Velociraptor API config. `armed` stands for "the server came up /
// the config was saved": until then the set's client builds as undefined (not configured at boot).
// Reconnect drops the cached set clients, so the next lookup builds again — with whatever `rebuild`
// returns now.
async function makeApp(rebuild: () => VelociraptorClient | undefined) {
  const root = await mkdtemp(join(tmpdir(), "dfir-veloreconnect-"));
  const store = new CaseStore(root);
  const sets = new ServerSetStore(join(root, "server-sets"), deriveServerSetKey(Buffer.alloc(32, 7)));
  sets.setDefault(sets.create({ name: "Testing", velociraptor: { apiConfigPath: "/x/api.yaml" } }).id);
  const state = { armed: false };
  const serverClients = createServerClients(
    sets,
    {},
    {
      velociraptor: () => (state.armed ? rebuild() : undefined),
    },
  );
  const app = createApp(store, {
    serverClients,
    clientInventoryFor: setInventories(join(dirname(root), "velociraptor")),
  });
  // The reconnect itself is what must make the new client live — arming alone changes nothing cached.
  const reconnect = () => {
    state.armed = true;
    return request(app).post("/velociraptor/reconnect");
  };
  return { app, reconnect };
}

describe("POST /velociraptor/reconnect", () => {
  it("rebuilds the set clients + refreshes the default set inventory when the server is up", async () => {
    const { app, reconnect } = await makeApp(() => new VelociraptorClient(cfg, upRunner));

    // Before reconnect: not configured.
    expect((await request(app).get("/health")).body.velociraptorEnabled).toBe(false);

    const res = await reconnect();
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ configured: true, ok: true, clients: 1 });

    // The live client is now set — health + inventory reflect it without a restart.
    expect((await request(app).get("/health")).body.velociraptorEnabled).toBe(true);
    const inv = (await request(app).get("/velociraptor/clients")).body;
    expect(inv.clients.map((c: { clientId: string }) => c.clientId)).toContain("C.111");
  });

  it("reports configured-but-unreachable when the rebuilt client can't reach the server", async () => {
    const { reconnect } = await makeApp(() => new VelociraptorClient(cfg, downRunner));
    const res = await reconnect();
    expect(res.status).toBe(200);
    expect(res.body.configured).toBe(true);
    expect(res.body.ok).toBe(false);
    expect(res.body.error).toMatch(/connection refused/);
  });

  it("reports not-configured when no API config is present", async () => {
    const { app, reconnect } = await makeApp(() => undefined);
    const res = await reconnect();
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ configured: false, ok: false });
    expect((await request(app).get("/health")).body.velociraptorEnabled).toBe(false);
  });

  it("GET /velociraptor/status reports configured + inventory freshness", async () => {
    const { app, reconnect } = await makeApp(() => new VelociraptorClient(cfg, upRunner));
    let status = (await request(app).get("/velociraptor/status")).body;
    expect(status.configured).toBe(false);
    await reconnect();
    status = (await request(app).get("/velociraptor/status")).body;
    expect(status.configured).toBe(true);
    expect(status.clients).toBe(1);
  });
});
