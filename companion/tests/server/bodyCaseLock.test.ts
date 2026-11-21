import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { ActivityLogStore } from "../../src/analysis/activityLog.js";
import { hashCasePassword } from "../../src/analysis/casePassword.js";
import { resetLimiters } from "../../src/http/rateLimiter.js";
import {
  VelociraptorClient,
  type VqlRunner,
  type VelociraptorApiConfig,
} from "../../src/integrations/velociraptor/velociraptorApi.js";
import { veloServerClients } from "../helpers/serverClientsStub.js";

// Routes that name their case in the request body (or ?caseId=) sit outside the /cases/:id
// case-lock gate. Each one must still refuse a password-protected case until the caller has
// unlocked it, with the same unlock cookie the gate accepts — and keep working for an unlocked
// case and for a case with no password.

const veloCfg: VelociraptorApiConfig = {
  apiConfigPath: "/x/api.yaml",
  binary: "velociraptor",
  timeoutMs: 5000,
  maxRows: 1000,
  maxOutputBytes: 1024 * 1024,
};

const runner: VqlRunner = async (statements) => {
  if (statements[0].includes("hunt(")) {
    return { rows: [{ Hunt: { HuntId: "H.TEST1", state: "RUNNING" } }], raw: "" };
  }
  return { rows: [{ a: 1 }], raw: "" };
};

let app: ReturnType<typeof createApp>;
let store: CaseStore;
let activityLogStore: ActivityLogStore;

beforeEach(async () => {
  resetLimiters();
  const root = await mkdtemp(join(tmpdir(), "dfir-bodycaselock-"));
  store = new CaseStore(root);
  activityLogStore = new ActivityLogStore(store);
  app = createApp(store, {
    activityLogStore,
    serverClients: veloServerClients(new VelociraptorClient(veloCfg, runner)),
  });
  await store.createCase({ caseId: "locked", name: "n", investigator: "i", aiProvider: null });
  await store.createCase({ caseId: "open1", name: "n", investigator: "i", aiProvider: null });
  await store.updateCaseMeta("locked", { password: await hashCasePassword("secret123") });
});

async function unlockCookie(): Promise<string> {
  const login = await request(app).post("/cases/locked/unlock").send({ password: "secret123" });
  expect(login.status).toBe(200);
  const cookie = login.headers["set-cookie"]?.[0];
  expect(cookie).toBeTruthy();
  return cookie;
}

type Call = { name: string; send: (caseId: string, cookie?: string) => request.Test };

const withCookie = (t: request.Test, cookie?: string) => (cookie ? t.set("Cookie", cookie) : t);

const CALLS: Call[] = [
  {
    name: "POST /velociraptor/run",
    send: (caseId, cookie) =>
      withCookie(request(app).post("/velociraptor/run"), cookie).send({
        vql: "SELECT 1 FROM info()",
        caseId,
      }),
  },
  {
    name: "POST /velociraptor/hunt",
    send: (caseId, cookie) =>
      withCookie(request(app).post("/velociraptor/hunt"), cookie).send({
        vql: "SELECT 1 FROM info()",
        description: "d",
        caseId,
      }),
  },
  {
    name: "POST /velociraptor/hunt-results",
    send: (caseId, cookie) =>
      withCookie(request(app).post("/velociraptor/hunt-results"), cookie).send({
        huntId: "H.1",
        artifact: "A",
        caseId,
      }),
  },
  {
    name: "POST /velociraptor/collect-results",
    send: (caseId, cookie) =>
      withCookie(request(app).post("/velociraptor/collect-results"), cookie).send({
        clientId: "C.1",
        flowId: "F.1",
        artifact: "A",
        caseId,
      }),
  },
  {
    name: "POST /velociraptor/clients/refresh",
    send: (caseId, cookie) =>
      withCookie(request(app).post("/velociraptor/clients/refresh"), cookie).send({ caseId }),
  },
  {
    name: "POST /velociraptor/reconnect",
    send: (caseId, cookie) =>
      withCookie(request(app).post("/velociraptor/reconnect"), cookie).send({ caseId }),
  },
  {
    name: "POST /velociraptor/bundles/:id/time-scope-preview",
    send: (caseId, cookie) =>
      withCookie(request(app).post("/velociraptor/bundles/b1/time-scope-preview"), cookie).send({
        preset: "24h",
        caseId,
      }),
  },
  {
    name: "GET /velociraptor/clients?caseId=",
    send: (caseId, cookie) => withCookie(request(app).get(`/velociraptor/clients?caseId=${caseId}`), cookie),
  },
  {
    name: "GET /velociraptor/artifacts?caseId=",
    send: (caseId, cookie) =>
      withCookie(request(app).get(`/velociraptor/artifacts?caseId=${caseId}`), cookie),
  },
  {
    name: "GET /velociraptor/event-artifacts?caseId=",
    send: (caseId, cookie) =>
      withCookie(request(app).get(`/velociraptor/event-artifacts?caseId=${caseId}`), cookie),
  },
  {
    name: "POST /cases/seed-demo",
    send: (caseId, cookie) =>
      withCookie(request(app).post("/cases/seed-demo"), cookie).send({ caseId, force: true }),
  },
];

describe("body-caseId routes respect the case password", () => {
  for (const call of CALLS) {
    it(`${call.name} refuses a locked case without the unlock cookie`, async () => {
      const res = await call.send("locked");
      expect(res.status).toBe(401);
      expect(res.body.error).toBe("locked");
    });

    it(`${call.name} lets an unlocked caller through`, async () => {
      const res = await call.send("locked", await unlockCookie());
      expect(res.status).not.toBe(401);
    });

    it(`${call.name} lets a case with no password through`, async () => {
      const res = await call.send("open1");
      expect(res.status).not.toBe(401);
    });
  }

  it("a refused run leaves no line in the locked case's activity log", async () => {
    await CALLS[0].send("locked");
    await CALLS[1].send("locked");
    expect(await activityLogStore.load("locked", { category: "hunt" })).toHaveLength(0);
  });

  it("an unlocked run is still recorded in the case's activity log", async () => {
    const res = await CALLS[0].send("locked", await unlockCookie());
    expect(res.status).toBe(200);
    expect(await activityLogStore.load("locked", { category: "hunt" })).toHaveLength(1);
  });

  it("a cookie for a different case does not unlock this one", async () => {
    await store.updateCaseMeta("open1", { password: await hashCasePassword("other456") });
    const login = await request(app).post("/cases/open1/unlock").send({ password: "other456" });
    const res = await CALLS[0].send("locked", login.headers["set-cookie"]?.[0]);
    expect(res.status).toBe(401);
  });

  it("a malformed caseId is still a 400, not a lock refusal", async () => {
    const res = await request(app)
      .post("/velociraptor/run")
      .send({ vql: "SELECT 1 FROM info()", caseId: "../x" });
    expect(res.status).toBe(400);
  });
});

// The seed route seeds `caseId ?? "demo"`, and demo mode discards the caller's id. The lock check
// must run on the case actually reseeded, not on whatever the body happened to name.
describe("POST /cases/seed-demo checks the lock of the case it actually seeds", () => {
  async function lockDemoCase(): Promise<void> {
    await store.createCase({ caseId: "demo", name: "n", investigator: "i", aiProvider: null });
    await store.updateCaseMeta("demo", { status: "closed", password: await hashCasePassword("demo1234") });
  }

  it("refuses a force reseed of a locked default demo case when no caseId is named", async () => {
    await lockDemoCase();
    const res = await request(app).post("/cases/seed-demo").send({ force: true });
    expect(res.status).toBe(401);
    expect(res.body).toMatchObject({ error: "locked", caseId: "demo" });
  });

  it("reseeds the locked default demo case once it is unlocked", async () => {
    await lockDemoCase();
    const login = await request(app).post("/cases/demo/unlock").send({ password: "demo1234" });
    expect(login.status).toBe(200);
    const res = await request(app)
      .post("/cases/seed-demo")
      .set("Cookie", login.headers["set-cookie"]?.[0])
      .send({ force: true });
    expect(res.status).toBe(201);
  });

  it("in demo mode, naming a different locked case does not refuse the default reseed", async () => {
    const demoApp = createApp(store, { activityLogStore, demoMode: true });
    const res = await request(demoApp).post("/cases/seed-demo").send({ caseId: "locked" });
    expect(res.status).toBe(201);
    expect(res.body.caseId).toBe("demo");
  });

  it("in demo mode, a locked default demo case is refused whatever id the body names", async () => {
    await lockDemoCase();
    const demoApp = createApp(store, { activityLogStore, demoMode: true });
    const res = await request(demoApp).post("/cases/seed-demo").send({ caseId: "open1", force: true });
    expect(res.status).toBe(401);
    expect(res.body.caseId).toBe("demo");
  });
});
