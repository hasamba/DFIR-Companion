import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ReportWriter } from "../../src/reports/reportWriter.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { createServerClients } from "../../src/composition/serverSetClients.js";
import { ServerSetStore } from "../../src/integrations/serverSets/serverSetStore.js";
import { deriveServerSetKey } from "../../src/integrations/serverSets/secretBox.js";

// Two fake IRIS servers. Each records the Authorization header of every request it receives and
// answers "no matching case" / an empty list, so a push gets as far as proving who it talked to.
interface FakeIris {
  server: Server;
  url: string;
  auths: string[];
}
async function fakeIris(): Promise<FakeIris> {
  const auths: string[] = [];
  const server = createServer((req, res) => {
    auths.push(String(req.headers.authorization ?? ""));
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify({ status: "success", data: { cases: [] } }));
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return { server, url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, auths };
}

// Calls one push makes against the fake IRIS below before it stops.
const IRIS_CALLS_PER_PUSH = 7;

let dir: string;
let sets: ServerSetStore;
let a: FakeIris;
let b: FakeIris;
let app: ReturnType<typeof createApp>;

beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), "ss-routing-"));
  a = await fakeIris();
  b = await fakeIris();
  sets = new ServerSetStore(join(dir, "server-sets"), deriveServerSetKey(Buffer.alloc(32, 9)));
  const store = new CaseStore(join(dir, "cases"));
  const stateStore = new StateStore(store);
  const pipeline = buildRuntimePipeline({
    provider: undefined,
    synthesisProvider: undefined,
    stateStore,
    store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  app = createApp(store, {
    pipeline,
    stateStore,
    reportWriter: new ReportWriter(store, stateStore),
    serverClients: createServerClients(sets, {}),
  });
  for (const id of ["c1", "c2", "c3"]) {
    await request(app).post("/cases").send({ caseId: id, name: id, investigator: "i", aiProvider: null });
  }
});
afterEach(async () => {
  await Promise.all([a, b].map((f) => new Promise((r) => f.server.close(r))));
  rmSync(dir, { recursive: true, force: true });
});

describe("IRIS and Timesketch routes use the case's own server set", () => {
  it("two cases on two sets push to their own IRIS", async () => {
    const sa = sets.create({ name: "A", iris: { url: a.url, apiKey: "iris-key-sentinel-alpha" } });
    const sb = sets.create({ name: "B", iris: { url: b.url, apiKey: "iris-key-sentinel-bravo" } });
    sets.linkCase("c1", sa.id);
    sets.linkCase("c2", sb.id);
    await Promise.all([
      request(app).post("/cases/c1/push/iris").send({}),
      request(app).post("/cases/c2/push/iris").send({}),
    ]);
    // One push makes exactly 7 IRIS calls against this fake (the legacy-name lookup, case
    // create/lookup and the type maps) before the fake's empty answers stop it with a 502. Each
    // server must see exactly its own push's calls, all carrying its own key.
    expect(a.auths).toHaveLength(IRIS_CALLS_PER_PUSH);
    expect(b.auths).toHaveLength(IRIS_CALLS_PER_PUSH);
    expect(new Set(a.auths)).toEqual(new Set(["Bearer iris-key-sentinel-alpha"]));
    expect(new Set(b.auths)).toEqual(new Set(["Bearer iris-key-sentinel-bravo"]));
  });

  it("push for an unlinked case returns 409 with the no-link message", async () => {
    const res = await request(app).post("/cases/c3/push/iris").send({});
    expect(res.status).toBe(409);
    expect(res.body.error).toBe("This case has no server set. Choose one in the case header.");
    expect(a.auths).toHaveLength(0);
  });

  it("a set without Timesketch answers 501 on the Timesketch push", async () => {
    const sa = sets.create({ name: "A", iris: { url: a.url, apiKey: "iris-key-sentinel-alpha" } });
    sets.linkCase("c1", sa.id);
    const res = await request(app).post("/cases/c1/push/timesketch").send({});
    expect(res.status).toBe(501);
  });

  it("/iris/status and /iris/cases use the default set", async () => {
    const sa = sets.create({ name: "A", iris: { url: a.url, apiKey: "iris-key-sentinel-alpha" } });
    const sb = sets.create({ name: "B", iris: { url: b.url, apiKey: "iris-key-sentinel-bravo" } });
    sets.setDefault(sb.id);
    sets.linkCase("c1", sa.id);
    const status = await request(app).get("/iris/status");
    expect(status.body).toEqual({ configured: true, baseUrl: b.url });
    const cases = await request(app).get("/iris/cases");
    expect(cases.status).toBe(200);
    expect(a.auths).toHaveLength(0);
    expect(new Set(b.auths)).toEqual(new Set(["Bearer iris-key-sentinel-bravo"]));
    const health = await request(app).get("/health");
    expect(health.body.irisEnabled).toBe(true);
    expect(health.body.timesketchEnabled).toBe(false);
  });

  it("with no default set /iris/status reports not configured", async () => {
    const res = await request(app).get("/iris/status");
    expect(res.body.configured).toBe(false);
  });

  it("editing a set's key changes the next push without a restart", async () => {
    const sa = sets.create({ name: "A", iris: { url: a.url, apiKey: "iris-key-sentinel-alpha" } });
    sets.linkCase("c1", sa.id);
    await request(app).post("/cases/c1/push/iris").send({});
    // The push answers when its first parallel lookup fails; the other lookup may still be in
    // flight. Wait for all of this push's calls before clearing, so none lands after the edit.
    await vi.waitFor(() => expect(a.auths).toHaveLength(IRIS_CALLS_PER_PUSH));
    expect(new Set(a.auths)).toEqual(new Set(["Bearer iris-key-sentinel-alpha"]));
    a.auths.length = 0;
    sets.update(sa.id, { name: "A", iris: { url: a.url, apiKey: "iris-key-sentinel-charlie" } });
    await request(app).post("/cases/c1/push/iris").send({});
    await vi.waitFor(() => expect(a.auths).toHaveLength(IRIS_CALLS_PER_PUSH));
    expect(new Set(a.auths)).toEqual(new Set(["Bearer iris-key-sentinel-charlie"]));
  });
});
