import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { readFile } from "node:fs/promises";
import { StateStore } from "../../src/analysis/stateStore.js";
import { resetLimiters } from "../../src/http/rateLimiter.js";
import { AuthStore } from "../../src/auth/authStore.js";
import { TeamAuth } from "../../src/auth/teamAuth.js";
import { resolveRequestPolicy } from "../../src/auth/policy.js";
import { ServerSetStore } from "../../src/integrations/serverSets/serverSetStore.js";
import { deriveServerSetKey } from "../../src/integrations/serverSets/secretBox.js";
import {
  MASKED_SECRET,
  type IrisSettings,
  type ServerClients,
  type ServerSetInput,
  type TimesketchSettings,
  type VelociraptorSettings,
} from "../../src/integrations/serverSets/types.js";
import { createServerClients, type ServerClientBuilders } from "../../src/composition/serverSetClients.js";
import type { IrisClient } from "../../src/integrations/iris/irisClient.js";
import type { TimesketchClient } from "../../src/integrations/timesketch/timesketchClient.js";
import type { VelociraptorClient } from "../../src/integrations/velociraptor/velociraptorApi.js";

const IRIS_KEY = "iris-key-sentinel-alpha";
const TS_PASSWORD = "timesketch-password-sentinel-bravo";
const BOOTSTRAP_TOKEN = "test-bootstrap-token-with-enough-entropy";
const USER_PASSWORD = "a different sufficiently long password";

let dir: string;
let sets: ServerSetStore;
let cases: CaseStore;
// What each probe was handed: the settings tell the sets apart.
let probed: string[];

const builders: ServerClientBuilders = {
  iris: (s: IrisSettings) =>
    ({
      ping: async () => {
        probed.push(`iris:${s.url}`);
        if (s.url.includes("down")) throw new Error("IRIS request failed: connect ECONNREFUSED");
      },
    }) as unknown as IrisClient,
  timesketch: (s: TimesketchSettings) =>
    ({
      login: async () => {
        probed.push(`timesketch:${s.url}`);
        throw new Error(`Timesketch request to https://${s.user}:${s.password}@ts.example.com failed`);
      },
    }) as unknown as TimesketchClient,
  velociraptor: (s: VelociraptorSettings) =>
    ({
      listClients: async () => {
        probed.push(`velociraptor:${s.apiConfigPath}`);
        return [];
      },
    }) as unknown as VelociraptorClient,
};

const fullSet = (name: string, irisUrl = "https://iris.example.com"): ServerSetInput => ({
  name,
  iris: { url: irisUrl, apiKey: IRIS_KEY },
  timesketch: { url: "https://ts.example.com", user: "analyst", password: TS_PASSWORD },
  velociraptor: { apiConfigPath: `/srv/${name}/api.config.yaml` },
});

function spyClients(): ServerClients & { invalidated: Array<string | undefined> } {
  const real = createServerClients(sets, {}, builders);
  const invalidated: Array<string | undefined> = [];
  return {
    ...real,
    invalidated,
    invalidate: (id?: string) => {
      invalidated.push(id);
      real.invalidate(id);
    },
  };
}

function singleUserApp(serverClients: ServerClients = spyClients()) {
  return createApp(cases, { serverClients, serverSetStore: sets });
}

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "ss-route-"));
  sets = new ServerSetStore(join(dir, "server-sets"), deriveServerSetKey(Buffer.alloc(32, 7)));
  cases = new CaseStore(join(dir, "cases"));
  probed = [];
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

async function teamApp() {
  await cases.createCase({ caseId: "c1", name: "Case c1", investigator: "i", aiProvider: null });
  const app = createApp(cases, {
    serverClients: spyClients(),
    serverSetStore: sets,
    teamAuth: new TeamAuth({
      store: new AuthStore(join(dir, "auth.sqlite")),
      bootstrapToken: BOOTSTRAP_TOKEN,
      cookieSecure: false,
      sessionTtlMs: 60 * 60_000,
    }),
  });
  const admin = request.agent(app);
  const boot = await admin.post("/auth/bootstrap").send({
    bootstrapToken: BOOTSTRAP_TOKEN,
    username: "admin",
    password: "correct horse battery staple",
    displayName: "Primary Admin",
  });
  expect(boot.status).toBe(201);
  const adminCsrf = (await admin.get("/auth/me")).body.csrfToken as string;
  const created = await admin.post("/auth/users").set("X-DFIR-CSRF", adminCsrf).send({
    username: "member",
    password: USER_PASSWORD,
    displayName: "Member",
  });
  expect(created.status).toBe(201);
  const grant = await admin
    .put(`/auth/cases/c1/roles/${encodeURIComponent(created.body.id as string)}`)
    .set("X-DFIR-CSRF", adminCsrf)
    .send({ role: "investigator" });
  expect(grant.status).toBe(200);
  const member = request.agent(app);
  const login = await member.post("/auth/local/login").send({ username: "member", password: USER_PASSWORD });
  expect(login.status).toBe(200);
  const memberCsrf = (await member.get("/auth/me")).body.csrfToken as string;
  return { admin, adminCsrf, member, memberCsrf };
}

describe("server set policy", () => {
  it("GET /server-sets is open to any signed-in user; every other /server-sets route is global admin", () => {
    expect(resolveRequestPolicy("GET", "/server-sets")).toEqual({ kind: "authenticated" });
    for (const [m, p] of [
      ["POST", "/server-sets"],
      ["PUT", "/server-sets/s1"],
      ["DELETE", "/server-sets/s1"],
      ["POST", "/server-sets/s1/default"],
      ["POST", "/server-sets/s1/test"],
      ["GET", "/server-sets/s1"],
    ]) {
      expect(resolveRequestPolicy(m, p), `${m} ${p}`).toEqual({ kind: "global", permission: "admin" });
    }
    expect(resolveRequestPolicy("GET", "/cases/c1/server-set")).toEqual({
      kind: "case",
      permission: "read",
      caseId: "c1",
    });
  });
});

describe("GET /server-sets", () => {
  it("masks secrets for admins", async () => {
    const s = sets.create(fullSet("Lab"));
    sets.setDefault(s.id);
    const res = await request(singleUserApp()).get("/server-sets");
    expect(res.status).toBe(200);
    expect(res.text).not.toContain(IRIS_KEY);
    expect(res.text).not.toContain(TS_PASSWORD);
    expect(res.body.defaultId).toBe(s.id);
    expect(res.body.sets[0]).toMatchObject({ id: s.id, name: "Lab", usedBy: 0 });
    expect(res.body.sets[0].iris.apiKey).toBe(MASKED_SECRET);
    expect(res.body.sets[0].timesketch.password).toBe(MASKED_SECRET);
  });

  it("returns names only for members", async () => {
    const s = sets.create(fullSet("Lab"));
    sets.setDefault(s.id);
    const { member } = await teamApp();
    const res = await member.get("/server-sets");
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ defaultId: s.id, sets: [{ id: s.id, name: "Lab" }] });
  });
});

describe("member cannot change sets", () => {
  it("member cannot create, edit, delete or set default", async () => {
    const s = sets.create(fullSet("Lab"));
    const { member, memberCsrf } = await teamApp();
    const tries = [
      () => member.post("/server-sets").set("X-DFIR-CSRF", memberCsrf).send({ name: "Mine" }),
      () => member.put(`/server-sets/${s.id}`).set("X-DFIR-CSRF", memberCsrf).send({ name: "Renamed" }),
      () => member.delete(`/server-sets/${s.id}`).set("X-DFIR-CSRF", memberCsrf),
      () => member.post(`/server-sets/${s.id}/default`).set("X-DFIR-CSRF", memberCsrf),
      () => member.post(`/server-sets/${s.id}/test`).set("X-DFIR-CSRF", memberCsrf),
    ];
    for (const t of tries) expect((await t()).status).toBe(403);
    expect(sets.list().map((x) => x.name)).toEqual(["Lab"]);
    expect(sets.defaultId()).toBeUndefined();
  });

  it("an admin can create a set in team mode", async () => {
    const { admin, adminCsrf } = await teamApp();
    const res = await admin.post("/server-sets").set("X-DFIR-CSRF", adminCsrf).send(fullSet("Team"));
    expect(res.status).toBe(201);
    expect(res.text).not.toContain(IRIS_KEY);
  });
});

describe("POST / PUT / DELETE / default", () => {
  it("creates a set and answers with the masked set", async () => {
    const res = await request(singleUserApp()).post("/server-sets").send(fullSet("Lab"));
    expect(res.status).toBe(201);
    expect(res.text).not.toContain(IRIS_KEY);
    expect(res.text).not.toContain(TS_PASSWORD);
    expect(res.body.iris.apiKey).toBe(MASKED_SECRET);
    expect(sets.get(res.body.id)?.iris?.apiKey).toBe(IRIS_KEY);
  });

  it("drops unknown fields and rejects a bad name or url with 400", async () => {
    const app = singleUserApp();
    const ok = await request(app)
      .post("/server-sets")
      .send({ name: "Lab", extra: "x", iris: { url: "https://iris.example.com", apiKey: "k", evil: 1 } });
    expect(ok.status).toBe(201);
    expect(ok.body.extra).toBeUndefined();
    expect(ok.body.iris.evil).toBeUndefined();
    expect((await request(app).post("/server-sets").send({ name: "" })).status).toBe(400);
    expect((await request(app).post("/server-sets").send({ name: "Lab" })).status).toBe(400); // duplicate
    const badUrl = await request(app)
      .post("/server-sets")
      .send({ name: "B", iris: { url: "ftp://iris.example.com", apiKey: "k" } });
    expect(badUrl.status).toBe(400);
  });

  it("PUT with masked key keeps the key and invalidates the cache", async () => {
    const s = sets.create(fullSet("Lab"));
    const clients = spyClients();
    const res = await request(singleUserApp(clients))
      .put(`/server-sets/${s.id}`)
      .send({
        name: "Lab 2",
        iris: { url: "https://iris2.example.com", apiKey: MASKED_SECRET },
        timesketch: { url: "https://ts.example.com", user: "analyst", password: MASKED_SECRET },
      });
    expect(res.status).toBe(200);
    expect(res.text).not.toContain(IRIS_KEY);
    expect(res.body.name).toBe("Lab 2");
    const stored = sets.get(s.id);
    expect(stored?.iris?.apiKey).toBe(IRIS_KEY);
    expect(stored?.iris?.url).toBe("https://iris2.example.com");
    expect(stored?.timesketch?.password).toBe(TS_PASSWORD);
    expect(clients.invalidated).toContain(s.id);
  });

  it("PUT on an unknown set is 404", async () => {
    const res = await request(singleUserApp()).put("/server-sets/nope").send({ name: "x" });
    expect(res.status).toBe(404);
  });

  it("DELETE in-use set returns 409 with case names", async () => {
    const def = sets.create({ name: "Default" });
    sets.setDefault(def.id);
    const s = sets.create(fullSet("Lab"));
    await cases.createCase({
      caseId: "c7",
      name: "Ransom <b>probe</b>",
      investigator: "i",
      aiProvider: null,
    });
    sets.linkCase("c7", s.id);
    const res = await request(singleUserApp()).delete(`/server-sets/${s.id}`);
    expect(res.status).toBe(409);
    expect(res.body).toEqual({
      error: "Server set is in use",
      usedBy: [{ id: "c7", name: "Ransom <b>probe</b>" }],
    });
    expect(res.headers["content-type"]).toMatch(/json/);
    expect(sets.get(s.id)).toBeDefined();
  });

  it("DELETE of an unused set is 204 and invalidates it; the default set is refused", async () => {
    const def = sets.create({ name: "Default" });
    sets.setDefault(def.id);
    const s = sets.create(fullSet("Lab"));
    const clients = spyClients();
    const app = singleUserApp(clients);
    expect((await request(app).delete(`/server-sets/${s.id}`)).status).toBe(204);
    expect(sets.get(s.id)).toBeUndefined();
    expect(clients.invalidated).toContain(s.id);
    expect((await request(app).delete(`/server-sets/${def.id}`)).status).toBe(409);
    expect((await request(app).delete("/server-sets/nope")).status).toBe(404);
  });

  it("POST /:setId/default makes it the default and refreshes clients", async () => {
    const s = sets.create(fullSet("Lab"));
    const clients = spyClients();
    const app = singleUserApp(clients);
    expect((await request(app).post(`/server-sets/${s.id}/default`)).status).toBe(204);
    expect(sets.defaultId()).toBe(s.id);
    expect(clients.invalidated).toContain(undefined);
    expect((await request(app).post("/server-sets/nope/default")).status).toBe(404);
  });

  it("reports usedBy as a count", async () => {
    const s = sets.create(fullSet("Lab"));
    sets.linkCase("a", s.id);
    sets.linkCase("b", s.id);
    const res = await request(singleUserApp()).get("/server-sets");
    expect(res.body.sets[0].usedBy).toBe(2);
  });
});

describe("POST /cases links the new case", () => {
  it("POST /cases with serverSetId links the case", async () => {
    const def = sets.create({ name: "Default" });
    sets.setDefault(def.id);
    const s = sets.create(fullSet("Lab"));
    const res = await request(singleUserApp())
      .post("/cases")
      .send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null, serverSetId: s.id });
    expect(res.status).toBe(201);
    expect(sets.caseSetId("c1")).toBe(s.id);
  });

  it("POST /cases without it links the default", async () => {
    const def = sets.create({ name: "Default" });
    sets.setDefault(def.id);
    const res = await request(singleUserApp())
      .post("/cases")
      .send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    expect(res.status).toBe(201);
    expect(sets.caseSetId("c1")).toBe(def.id);
  });

  it("POST /cases with no default set still creates the case, unlinked", async () => {
    const res = await request(singleUserApp())
      .post("/cases")
      .send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    expect(res.status).toBe(201);
    expect(sets.caseSetId("c1")).toBeUndefined();
  });

  it("POST /cases with unknown id → 400", async () => {
    const res = await request(singleUserApp())
      .post("/cases")
      .send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null, serverSetId: "nope" });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("unknown server set");
    expect(await cases.caseExists("c1")).toBe(false);
  });

  it("the demo seeder links a new demo case to the default set", async () => {
    const def = sets.create({ name: "Default" });
    sets.setDefault(def.id);
    const res = await request(singleUserApp()).post("/cases/seed-demo").send({ caseId: "demo-x" });
    expect(res.status).toBe(201);
    expect(sets.caseSetId("demo-x")).toBe(def.id);
  });

  it("a whole-case ZIP import links the new case to the default set, not the source case's", async () => {
    resetLimiters();
    const other = sets.create({ name: "Other" });
    const def = sets.create({ name: "Default" });
    sets.setDefault(def.id);
    const app = createApp(cases, {
      serverClients: spyClients(),
      serverSetStore: sets,
      stateStore: new StateStore(cases),
    });
    await request(app)
      .post("/cases")
      .send({ caseId: "INC-1", name: "One", investigator: "i", aiProvider: null, serverSetId: other.id });
    const archived = await request(app).post("/cases/INC-1/archive").send({});
    expect(archived.status, archived.text).toBe(200);
    const zip = await readFile(archived.body.archivePath as string);
    const res = await request(app)
      .post("/cases/import/zip")
      .send({ data: zip.toString("base64"), targetCaseId: "INC-2" });
    expect(res.status, res.text).toBe(201);
    expect(sets.caseSetId("INC-2")).toBe(def.id);
    expect(sets.caseSetId("INC-1")).toBe(other.id); // archived, not deleted: the link stays
  });

  it("a hard delete removes the case's link", async () => {
    const def = sets.create({ name: "Default" });
    sets.setDefault(def.id);
    const app = singleUserApp();
    await request(app).post("/cases").send({ caseId: "c9", name: "n", investigator: "i", aiProvider: null });
    expect(sets.caseSetId("c9")).toBe(def.id);
    const closed = await request(app).patch("/cases/c9/status").send({ status: "closed" });
    expect(closed.status, closed.text).toBe(200);
    const del = await request(app).post("/cases/c9/delete").send({ archiveFirst: "none" });
    expect(del.status, del.text).toBe(200);
    expect(del.body.deleted).toBe(true);
    expect(sets.caseSetId("c9")).toBeUndefined();
  });
});

describe("POST /server-sets/:setId/test", () => {
  it("test endpoint reports per-tool results for that set, not the default", async () => {
    const def = sets.create(fullSet("Default", "https://iris-default.example.com"));
    sets.setDefault(def.id);
    const s = sets.create(fullSet("Lab", "https://iris-down.example.com"));
    const res = await request(singleUserApp()).post(`/server-sets/${s.id}/test`);
    expect(res.status).toBe(200);
    expect(probed).toEqual([
      "iris:https://iris-down.example.com",
      "timesketch:https://ts.example.com",
      "velociraptor:/srv/Lab/api.config.yaml",
    ]);
    expect(res.body.iris).toEqual({ ok: false, error: "IRIS request failed: connect ECONNREFUSED" });
    expect(res.body.velociraptor).toEqual({ ok: true });
    expect(res.body.timesketch.ok).toBe(false);
    expect(res.text).not.toContain(TS_PASSWORD);
    expect(res.text).not.toContain("analyst:");
  });

  it("leaves out a tool the set does not use, and 404s an unknown set", async () => {
    const s = sets.create({ name: "Only Velo", velociraptor: { apiConfigPath: "/srv/v/api.yaml" } });
    const app = singleUserApp();
    const res = await request(app).post(`/server-sets/${s.id}/test`);
    expect(res.body).toEqual({ velociraptor: { ok: true } });
    const missing = await request(app).post("/server-sets/nope/test");
    expect(missing.status).toBe(404);
    expect(missing.body.error).toBe("Server set not found.");
  });
});

describe("GET /cases/:id/server-set", () => {
  it("names the case's set and the tools it uses", async () => {
    const s = sets.create({ name: "Only Velo", velociraptor: { apiConfigPath: "/srv/v/api.yaml" } });
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    sets.linkCase("c1", s.id);
    const res = await request(singleUserApp()).get("/cases/c1/server-set");
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ setId: s.id, name: "Only Velo", tools: ["velociraptor"] });
  });

  it("409s with the resolver message for an unlinked case", async () => {
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const res = await request(singleUserApp()).get("/cases/c1/server-set");
    expect(res.status).toBe(409);
    expect(res.body.error).toBe("This case has no server set. Choose one in the case header.");
  });
});

describe("probeError", () => {
  it("keeps one line, strips URL credentials and cuts the text an IRIS server sent back", async () => {
    const { probeError } = await import("../../src/routes/serverSetBody.js");
    expect(probeError(new Error("failed https://bob:hunter-word@ts.example.com/x\nstack"))).toBe(
      "failed https://ts.example.com/x",
    );
    expect(probeError(new Error("IRIS error on /api/ping: <html>remote body</html>"))).toBe(
      "IRIS error on /api/ping",
    );
  });
});
