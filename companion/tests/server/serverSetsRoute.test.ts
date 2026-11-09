import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, getServerLogger } from "../../src/server.js";
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
// The secret each IRIS / Timesketch client was built with, to prove a mask is never sent on.
let secretsSeen: string[];

const builders: ServerClientBuilders = {
  iris: (s: IrisSettings) => {
    secretsSeen.push(`iris:${s.apiKey}`);
    return {
      ping: async () => {
        probed.push(`iris:${s.url}`);
        if (s.url.includes("down")) throw new Error("IRIS request failed: connect ECONNREFUSED");
      },
    } as unknown as IrisClient;
  },
  timesketch: (s: TimesketchSettings) => {
    secretsSeen.push(`timesketch:${s.password}`);
    return {
      login: async () => {
        probed.push(`timesketch:${s.url}`);
        throw new Error(`Timesketch request to https://${s.user}:${s.password}@ts.example.com failed`);
      },
    } as unknown as TimesketchClient;
  },
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
  secretsSeen = [];
});
// Windows cannot unlink an open SQLite file, so close every auth store before removing the dir.
const authStores: AuthStore[] = [];
afterEach(() => {
  for (const store of authStores.splice(0)) store.close();
  rmSync(dir, { recursive: true, force: true });
});

function trackAuthStore(store: AuthStore): AuthStore {
  authStores.push(store);
  return store;
}

async function teamApp() {
  await cases.createCase({ caseId: "c1", name: "Case c1", investigator: "i", aiProvider: null });
  const app = createApp(cases, {
    serverClients: spyClients(),
    serverSetStore: sets,
    teamAuth: new TeamAuth({
      store: trackAuthStore(new AuthStore(join(dir, "auth.sqlite"))),
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
      ["POST", "/server-sets/test"],
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
      () => member.post("/server-sets/test").set("X-DFIR-CSRF", memberCsrf).send(fullSet("Typed")),
      () =>
        member
          .post(`/server-sets/${s.id}/test`)
          .set("X-DFIR-CSRF", memberCsrf)
          .send({ ...fullSet("Lab"), tools: ["iris"] }),
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

  it("DELETE and POST default work on a set whose secret cannot be decrypted", async () => {
    const def = sets.create({ name: "Default" });
    sets.setDefault(def.id);
    const broken = sets.create(fullSet("Broken"));
    const other = sets.create(fullSet("Other"));
    // Corrupt both sealed IRIS keys on disk: the sets still exist, but no secret opens.
    const path = join(dir, "server-sets", "sets.json");
    const raw = JSON.parse(await readFile(path, "utf8")) as Array<{ iris?: { apiKey: string } }>;
    for (const s of raw) if (s.iris) s.iris.apiKey = "v1:AAAA:AAAA:AAAA";
    writeFileSync(path, JSON.stringify(raw));
    const app = singleUserApp();
    expect((await request(app).post(`/server-sets/${other.id}/default`)).status).toBe(204);
    expect(sets.defaultId()).toBe(other.id);
    expect((await request(app).delete(`/server-sets/${broken.id}`)).status).toBe(204);
    expect(sets.has(broken.id)).toBe(false);
  });

  it("a corrupt sets.json answers 500 and the log names the error, never the file text", async () => {
    sets.create(fullSet("Lab"));
    writeFileSync(join(dir, "server-sets", "sets.json"), "[x iris-key-sentinel-snippet");
    const app = singleUserApp();
    const logged: string[] = [];
    const error = vi.spyOn(getServerLogger(), "error").mockImplementation((m: string) => void logged.push(m));
    const res = await request(app).get("/server-sets");
    error.mockRestore();
    expect(res.status).toBe(500);
    expect(logged.join("\n")).toContain("SyntaxError");
    expect(logged.join("\n")).not.toContain("iris-key");
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

describe("POST /server-sets/test (typed values, nothing saved)", () => {
  it("tests the typed IRIS values and saves nothing", async () => {
    const res = await request(singleUserApp())
      .post("/server-sets/test")
      .send({ name: "", iris: { url: "https://iris-typed.example.com", apiKey: "typed-key-word" } });
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ iris: { ok: true } });
    expect(probed).toEqual(["iris:https://iris-typed.example.com"]);
    expect(secretsSeen).toEqual(["iris:typed-key-word"]);
    expect(sets.list()).toEqual([]);
    expect(res.text).not.toContain("typed-key-word");
  });

  it("runs only the tools named in `tools`", async () => {
    const res = await request(singleUserApp())
      .post("/server-sets/test")
      .send({ ...fullSet("Typed"), tools: ["velociraptor"] });
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ velociraptor: { ok: true } });
    expect(probed).toEqual(["velociraptor:/srv/Typed/api.config.yaml"]);
  });

  it("refuses a masked secret: there is no stored secret to use", async () => {
    const res = await request(singleUserApp())
      .post("/server-sets/test")
      .send({ name: "New", iris: { url: "https://iris.example.com", apiKey: MASKED_SECRET } });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("secret required");
    expect(probed).toEqual([]);
  });

  it("reports an incomplete tool and still tests the others", async () => {
    const res = await request(singleUserApp())
      .post("/server-sets/test")
      .send({
        name: "Half",
        iris: { url: "https://iris.example.com" },
        velociraptor: { apiConfigPath: "/srv/half/api.yaml" },
      });
    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      iris: { ok: false, error: "IRIS is incomplete" },
      velociraptor: { ok: true },
    });
  });

  it("answers 400 for a bad tools list or a non-http(s) URL", async () => {
    const app = singleUserApp();
    const badTools = await request(app)
      .post("/server-sets/test")
      .send({ ...fullSet("T"), tools: "iris" });
    expect(badTools.status).toBe(400);
    const badUrl = await request(app)
      .post("/server-sets/test")
      .send({ name: "T", iris: { url: "file:///etc/passwd", apiKey: "word-key" } });
    expect(badUrl.status).toBe(400);
    expect(badUrl.body.error).toBe("iris url must be http(s)");
    expect(probed).toEqual([]);
  });

  it("never returns the key or the password", async () => {
    const res = await request(singleUserApp()).post("/server-sets/test").send(fullSet("Typed"));
    expect(res.status).toBe(200);
    expect(res.body.timesketch.ok).toBe(false);
    expect(res.text).not.toContain(IRIS_KEY);
    expect(res.text).not.toContain(TS_PASSWORD);
  });
});

describe("POST /server-sets/:setId/test with typed values", () => {
  it("a masked key uses the stored key; a new URL is used as typed", async () => {
    const s = sets.create(fullSet("Lab"));
    const res = await request(singleUserApp())
      .post(`/server-sets/${s.id}/test`)
      .send({
        name: "Lab",
        iris: { url: "https://iris-new.example.com", apiKey: MASKED_SECRET },
        timesketch: { url: "https://ts.example.com", user: "analyst", password: MASKED_SECRET },
        tools: ["iris", "timesketch"],
      });
    expect(res.status).toBe(200);
    expect(probed).toEqual(["iris:https://iris-new.example.com", "timesketch:https://ts.example.com"]);
    expect(secretsSeen).toEqual([`iris:${IRIS_KEY}`, `timesketch:${TS_PASSWORD}`]);
    expect(res.body.iris).toEqual({ ok: true });
    expect(res.text).not.toContain(IRIS_KEY);
    expect(res.text).not.toContain(TS_PASSWORD);
    expect(sets.get(s.id)?.iris?.url).toBe("https://iris.example.com"); // nothing saved
  });

  it("an emptied secret tests with no secret", async () => {
    const s = sets.create(fullSet("Lab"));
    const res = await request(singleUserApp())
      .post(`/server-sets/${s.id}/test`)
      .send({ name: "Lab", iris: { url: "https://iris.example.com", apiKey: "" }, tools: ["iris"] });
    expect(res.body).toEqual({ iris: { ok: false, error: "IRIS is incomplete" } });
    expect(secretsSeen).toEqual([]);
  });

  it("404s an unknown set even with a body", async () => {
    const res = await request(singleUserApp()).post("/server-sets/nope/test").send(fullSet("X"));
    expect(res.status).toBe(404);
    expect(res.body.error).toBe("Server set not found.");
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

  // An unlinked case is an ordinary state on every case load, so the read answers 200 and carries the
  // resolver's message as `problem` instead of a console-logged 409 (#2462).
  it("answers 200 with the resolver message as the problem for an unlinked case", async () => {
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const res = await request(singleUserApp()).get("/cases/c1/server-set");
    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      setId: "",
      name: "",
      tools: [],
      problem: "This case has no server set. Choose one in the case header.",
    });
  });
});

// The case list carries each case's set id and name, so the dashboard's case dropdown can show it
// under the case without one request per case. Names and ids only: never a URL or a secret.
describe("GET /cases names each case's server set", () => {
  it("gives a linked case its set and an unlinked case null, with no secret or URL", async () => {
    const s = sets.create(fullSet("Client A"));
    await cases.createCase({ caseId: "CASE-A", name: "A", investigator: "i", aiProvider: null });
    await cases.createCase({ caseId: "CASE-B", name: "B", investigator: "i", aiProvider: null });
    sets.linkCase("CASE-A", s.id);
    const res = await request(singleUserApp()).get("/cases");
    expect(res.status).toBe(200);
    const byId = Object.fromEntries(
      (res.body as Array<{ caseId: string; serverSet: unknown }>).map((c) => [c.caseId, c.serverSet]),
    );
    expect(byId).toEqual({ "CASE-A": { id: s.id, name: "Client A" }, "CASE-B": null });
    const text = JSON.stringify(res.body);
    expect(text).not.toContain(IRIS_KEY);
    expect(text).not.toContain(TS_PASSWORD);
    expect(text).not.toContain("example.com");
    expect(text).not.toContain("api.config.yaml");
  });

  it("a link to a set that no longer exists reads as null", async () => {
    await cases.createCase({ caseId: "CASE-A", name: "A", investigator: "i", aiProvider: null });
    writeFileSync(join(dir, "server-sets", "links.json"), JSON.stringify({ cases: { "CASE-A": "gone" } }));
    const res = await request(singleUserApp()).get("/cases");
    expect(res.body[0].serverSet).toBeNull();
  });

  it("a member sees only their own cases, each with its set", async () => {
    const s = sets.create({ name: "Lab" });
    const { member } = await teamApp();
    await cases.createCase({ caseId: "c2", name: "Hidden", investigator: "i", aiProvider: null });
    sets.linkCase("c1", s.id);
    sets.linkCase("c2", s.id);
    const res = await member.get("/cases");
    expect(res.status).toBe(200);
    expect(res.body.map((c: { caseId: string }) => c.caseId)).toEqual(["c1"]);
    expect(res.body[0].serverSet).toEqual({ id: s.id, name: "Lab" });
  });

  it("an unreadable store still lists the cases, every set null, and logs once", async () => {
    sets.create(fullSet("Lab"));
    await cases.createCase({ caseId: "CASE-A", name: "A", investigator: "i", aiProvider: null });
    writeFileSync(join(dir, "server-sets", "sets.json"), "[x iris-key-sentinel-snippet");
    const app = singleUserApp();
    const logged: string[] = [];
    const error = vi.spyOn(getServerLogger(), "error").mockImplementation((m: string) => void logged.push(m));
    const first = await request(app).get("/cases");
    const second = await request(app).get("/cases");
    error.mockRestore();
    expect(first.status).toBe(200);
    expect(first.body.map((c: { serverSet: unknown }) => c.serverSet)).toEqual([null]);
    expect(second.body[0].serverSet).toBeNull();
    const lines = logged.filter((l) => l.includes("[server-sets]"));
    expect(lines).toHaveLength(1);
    expect(lines[0]).toContain("SyntaxError");
    expect(logged.join("\n")).not.toContain("iris-key");
  });
});

describe("probeError", () => {
  it("keeps one line, strips URL credentials and cuts the text an IRIS server sent back", async () => {
    const { probeError } = await import("../../src/routes/serverSetBody.js");
    // trufflehog:ignore — a made-up credential, the input the scrubber must strip
    const withCreds = "failed https://bob:hunter-word@ts.example.com/x\nstack"; // trufflehog:ignore
    expect(probeError(new Error(withCreds))).toBe("failed https://ts.example.com/x");
    expect(probeError(new Error("IRIS error on /api/ping: <html>remote body</html>"))).toBe(
      "IRIS error on /api/ping",
    );
  });

  it("keeps the server-set certificate hint inside the 200-character cut", async () => {
    const { probeError } = await import("../../src/routes/serverSetBody.js");
    const { IrisClient } = await import("../../src/integrations/iris/irisClient.js");
    const { TimesketchClient } = await import("../../src/integrations/timesketch/timesketchClient.js");
    const cause = Object.assign(
      new Error(
        "self-signed certificate; if the root CA is installed locally, try running Node.js with --use-system-ca",
      ),
      { code: "DEPTH_ZERO_SELF_SIGNED_CERT" },
    );
    const fetchFn = async (): Promise<Response> => {
      throw new TypeError("fetch failed", { cause });
    };
    const iris = new IrisClient({ baseUrl: "https://iris.example.org", apiKey: "word-key", fetchFn });
    const ts = new TimesketchClient({
      baseUrl: "https://ts.example.org",
      username: "u",
      password: "p",
      fetchFn,
    });
    const irisMsg = probeError(await iris.ping().catch((e: unknown) => e));
    const tsMsg = probeError(await ts.login().catch((e: unknown) => e));
    expect(irisMsg).toContain("DEPTH_ZERO_SELF_SIGNED_CERT");
    expect(irisMsg).toContain("Set the CA bundle for IRIS in this server set (Settings → Server sets)");
    expect(tsMsg).toContain("Set the CA bundle for Timesketch in this server set (Settings → Server sets)");
    expect(irisMsg).not.toContain("--use-system-ca");
  });
});
