import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { AuthStore } from "../../src/auth/authStore.js";
import { TeamAuth } from "../../src/auth/teamAuth.js";
import { createApp } from "../../src/server.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import type { IOC } from "../../src/analysis/stateTypes.js";

// GET /global/iocs and GET /cases/:id/related (#679). The ranking itself is unit-tested in
// tests/analysis/crossCaseIndex.test.ts; what matters here is the WIRING — above all the
// visibility gate, because both routes read cases OTHER than the one in the URL and neither the
// case-lock gate nor the per-case team policy covers those.

const BOOTSTRAP_TOKEN = "test-bootstrap-token-with-enough-entropy";

afterEach(() => {
  delete process.env.DFIR_CROSS_CASE;
});

function ioc(id: string, type: IOC["type"], value: string, flagged = false): IOC {
  return {
    id,
    type,
    value,
    firstSeen: "2026-01-01T00:00:00Z",
    ...(flagged
      ? {
          enrichments: [
            { source: "VirusTotal", verdict: "malicious" as const, fetchedAt: "2026-01-02T00:00:00Z" },
          ],
        }
      : {}),
  };
}

async function seed(store: CaseStore, stateStore: StateStore, caseId: string, iocs: IOC[]) {
  await store.createCase({ caseId, name: `Case ${caseId}`, investigator: "i", aiProvider: null });
  await stateStore.save({ ...emptyState(caseId), iocs });
}

describe("cross-case pivot — single-user mode", () => {
  let app: ReturnType<typeof createApp>;
  let store: CaseStore;
  let stateStore: StateStore;

  beforeEach(async () => {
    process.env.DFIR_CROSS_CASE = "on"; // the pivot is off by default (#723)
    const root = await mkdtemp(join(tmpdir(), "dfir-crosscase-"));
    store = new CaseStore(root);
    stateStore = new StateStore(store);
    await seed(store, stateStore, "c1", [ioc("i1", "domain", "evil.com", true), ioc("i2", "ip", "10.0.0.5")]);
    await seed(store, stateStore, "c2", [ioc("i9", "domain", "EVIL.com")]);
    await seed(store, stateStore, "c3", [ioc("i7", "domain", "unrelated.test")]);
    app = createApp(store, { stateStore });
  });

  it("finds every case holding an indicator", async () => {
    const res = await request(app).get("/global/iocs?q=evil.com");
    expect(res.status).toBe(200);
    expect(res.body.entries[0].value).toBe("evil.com");
    expect(res.body.entries[0].caseIds).toEqual(["c1", "c2"]);
    expect(res.body.scannedCases).toBe(3);
  });

  it("requires a query rather than dumping the index", async () => {
    expect((await request(app).get("/global/iocs")).status).toBe(400);
    expect((await request(app).get("/global/iocs?q=%20%20")).status).toBe(400);
  });

  it("narrows the search by type and by how many cases hold the value", async () => {
    expect((await request(app).get("/global/iocs?q=evil.com&type=ip")).body.entries).toEqual([]);
    const two = await request(app).get("/global/iocs?q=evil&minCases=2");
    expect(two.body.entries.map((e: { value: string }) => e.value)).toEqual(["evil.com"]);
  });

  it("refuses a type the index does not carry rather than ignoring the filter", async () => {
    // Dropping the unrecognised value would answer ?type=process with every domain and address in
    // the estate — the opposite of what was asked for.
    const res = await request(app).get("/global/iocs?q=evil.com&type=process");
    expect(res.status).toBe(400);
    expect(res.body.error).toContain("domain");
  });

  it("lists the related case and what it shares", async () => {
    const res = await request(app).get("/cases/c1/related");
    expect(res.status).toBe(200);
    expect(res.body.related).toHaveLength(1);
    expect(res.body.related[0]).toMatchObject({ caseId: "c2", sharedCount: 1, maliciousCount: 1 });
    expect(res.body.related[0].shared[0].value).toBe("evil.com");
  });

  it("404s an unknown case instead of answering with an empty list", async () => {
    // StateStore.load answers an unknown case with emptyState, so without the caseExists check
    // this would 200 for any id at all.
    expect((await request(app).get("/cases/nope/related")).status).toBe(404);
  });

  it("sees an indicator imported after the first answer was cached", async () => {
    expect((await request(app).get("/cases/c3/related")).body.related).toEqual([]);
    await stateStore.save({ ...emptyState("c3"), iocs: [ioc("i7", "domain", "evil.com")] });
    const again = await request(app).get("/cases/c3/related");
    expect(again.body.related.map((r: { caseId: string }) => r.caseId)).toEqual(["c1", "c2"]);
  });

  it("repaints a renamed or archived case without waiting for its evidence to change", async () => {
    // The name and the lifecycle status live in case.json, not in the state database, so a cache
    // keyed on the database alone would keep serving the old label until the next import.
    expect((await request(app).get("/cases/c1/related")).body.related[0].name).toBe("Case c2");
    await store.updateCaseMeta("c2", { name: "Phishing wave" });
    expect((await request(app).get("/cases/c1/related")).body.related[0].name).toBe("Phishing wave");
    const closed = await request(app).patch("/cases/c2/status").send({ status: "closed" });
    expect(closed.status).toBe(200);
    expect((await request(app).get("/cases/c1/related")).body.related[0].status).toBe("closed");
  });

  it("keeps a suspicious-only verdict flagged after the cache trims the IOC", async () => {
    // The cache stores a slimmed IOC — the full provider records are megabytes the index never
    // reads. The trim must not lose the one bit it does read, on either flagging verdict.
    await stateStore.save({
      ...emptyState("c3"),
      iocs: [
        {
          id: "i7",
          type: "domain",
          value: "evil.com",
          firstSeen: "2026-01-01T00:00:00Z",
          enrichments: [
            { source: "AbuseIPDB", verdict: "harmless", fetchedAt: "2026-01-02T00:00:00Z" },
            { source: "MISP", verdict: "suspicious", fetchedAt: "2026-01-02T00:00:00Z" },
          ],
        },
      ],
    });
    const res = await request(app).get("/cases/c3/related");
    expect(res.body.related[0].shared[0].malicious).toBe(true);
  });

  it("501s when no state store is configured", async () => {
    const bare = createApp(store);
    expect((await request(bare).get("/global/iocs?q=evil.com")).status).toBe(501);
    expect((await request(bare).get("/cases/c1/related")).status).toBe(501);
  });
});

describe("cross-case pivot — a password-protected case stays out", () => {
  let app: ReturnType<typeof createApp>;

  beforeEach(async () => {
    process.env.DFIR_CROSS_CASE = "on"; // the pivot is off by default (#723)
    const root = await mkdtemp(join(tmpdir(), "dfir-crosscase-pw-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    await seed(store, stateStore, "open", [ioc("i1", "domain", "evil.com")]);
    await seed(store, stateStore, "secret", [ioc("i9", "domain", "evil.com")]);
    app = createApp(store, { stateStore });
    await request(app).post("/cases/secret/password").send({ newPassword: "correct horse" });
  });

  // The case-lock gate is mounted on /cases/:id, so it does not cover /global/* at all and on
  // /cases/:id/related it only guards the SUBJECT case. Without the second half of the gate in
  // routes/crossCase.ts, a locked case's indicators would be readable through its correlation
  // with an unlocked one.
  it("omits the locked case from a global search", async () => {
    const res = await request(app).get("/global/iocs?q=evil.com");
    expect(res.body.entries[0].caseIds).toEqual(["open"]);
    expect(res.body.scannedCases).toBe(1);
  });

  it("omits the locked case from another case's related list", async () => {
    expect((await request(app).get("/cases/open/related")).body.related).toEqual([]);
  });

  it("includes it again once this client has unlocked it", async () => {
    const agent = request.agent(app);
    const unlock = await agent.post("/cases/secret/unlock").send({ password: "correct horse" });
    expect(unlock.status).toBe(200);
    const res = await agent.get("/cases/open/related");
    expect(res.body.related.map((r: { caseId: string }) => r.caseId)).toEqual(["secret"]);
  });
});

describe("cross-case pivot — team mode respects case roles", () => {
  let app: ReturnType<typeof createApp>;
  let admin: { agent: ReturnType<typeof request.agent>; csrf: string };

  async function login(username: string) {
    const agent = request.agent(app);
    const res = await agent
      .post("/auth/local/login")
      .send({ username, password: "a different sufficiently long password" });
    expect(res.status).toBe(200);
    return agent;
  }

  beforeEach(async () => {
    process.env.DFIR_CROSS_CASE = "on"; // the pivot is off by default (#723)
    const root = await mkdtemp(join(tmpdir(), "dfir-crosscase-team-"));
    const store = new CaseStore(join(root, "cases"));
    const stateStore = new StateStore(store);
    await seed(store, stateStore, "c1", [ioc("i1", "domain", "evil.com")]);
    await seed(store, stateStore, "c2", [ioc("i9", "domain", "evil.com")]);
    app = createApp(store, {
      stateStore,
      teamAuth: new TeamAuth({
        store: new AuthStore(join(root, "auth.sqlite")),
        bootstrapToken: BOOTSTRAP_TOKEN,
        cookieSecure: false,
        sessionTtlMs: 60 * 60_000,
      }),
    });
    const agent = request.agent(app);
    const boot = await agent.post("/auth/bootstrap").send({
      bootstrapToken: BOOTSTRAP_TOKEN,
      username: "admin",
      password: "correct horse battery staple",
      displayName: "Primary Admin",
    });
    expect(boot.status).toBe(201);
    const me = await agent.get("/auth/me");
    admin = { agent, csrf: me.body.csrfToken as string };
    const created = await admin.agent.post("/auth/users").set("X-DFIR-CSRF", admin.csrf).send({
      username: "reader",
      password: "a different sufficiently long password",
      displayName: "READER",
    });
    expect(created.status).toBe(201);
    const grant = await admin.agent
      .put(`/auth/cases/c1/roles/${encodeURIComponent(created.body.id as string)}`)
      .set("X-DFIR-CSRF", admin.csrf)
      .send({ role: "reader" });
    expect(grant.status).toBe(200);
  });

  it("turns away an unauthenticated caller", async () => {
    expect((await request(app).get("/global/iocs?q=evil.com")).status).toBe(401);
  });

  it("lets a reader search, and answers only with the case they hold a role on", async () => {
    const reader = await login("reader");
    const res = await reader.get("/global/iocs?q=evil.com");
    // The route must not be global-admin-only: an investigator pivoting across their own cases is
    // the whole point of the feature.
    expect(res.status).toBe(200);
    expect(res.body.entries[0].caseIds).toEqual(["c1"]);
  });

  it("hides a case the reader holds no role on from the related list", async () => {
    const reader = await login("reader");
    const res = await reader.get("/cases/c1/related");
    expect(res.status).toBe(200);
    expect(res.body.related).toEqual([]);
  });

  it("shows a global administrator both cases", async () => {
    const res = await admin.agent.get("/cases/c1/related");
    expect(res.body.related.map((r: { caseId: string }) => r.caseId)).toEqual(["c2"]);
  });
});

// The pivot names cases OTHER than the one the analyst is looking at, and each answered request
// pins a slimmed copy of every visible case's IOCs for the life of the process. It stays off until
// a deployment asks for it (#723).
describe("cross-case pivot — off by default", () => {
  let app: ReturnType<typeof createApp>;

  beforeEach(async () => {
    delete process.env.DFIR_CROSS_CASE;
    const root = await mkdtemp(join(tmpdir(), "dfir-crosscase-off-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    await seed(store, stateStore, "c1", [ioc("i1", "domain", "evil.com")]);
    await seed(store, stateStore, "c2", [ioc("i9", "domain", "evil.com")]);
    app = createApp(store, { stateStore });
  });

  it("refuses the estate-wide search, and says why", async () => {
    const res = await request(app).get("/global/iocs?q=evil.com");
    expect(res.status).toBe(404);
    expect(res.body.error).toMatch(/DFIR_CROSS_CASE/);
  });

  it("refuses the related-cases lookup for a case that really exists", async () => {
    // Not a 404 about a missing case — c1 is there. The 404 is the feature being off.
    const res = await request(app).get("/cases/c1/related");
    expect(res.status).toBe(404);
    expect(res.body.error).toMatch(/DFIR_CROSS_CASE/);
  });

  it.each([["off"], [""], ["  "], ["true"], ["1"], ["yes"]])(
    'stays off for DFIR_CROSS_CASE=%j — only an explicit "on" enables it',
    async (value) => {
      process.env.DFIR_CROSS_CASE = value;
      const root = await mkdtemp(join(tmpdir(), "dfir-crosscase-val-"));
      const store = new CaseStore(root);
      const stateStore = new StateStore(store);
      await seed(store, stateStore, "c1", [ioc("i1", "domain", "evil.com")]);
      const scoped = createApp(store, { stateStore });
      expect((await request(scoped).get("/global/iocs?q=evil.com")).status).toBe(404);
    },
  );

  it("enables on an explicit ON, whatever the case and spacing", async () => {
    process.env.DFIR_CROSS_CASE = "  ON  ";
    const root = await mkdtemp(join(tmpdir(), "dfir-crosscase-on-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    await seed(store, stateStore, "c1", [ioc("i1", "domain", "evil.com")]);
    await seed(store, stateStore, "c2", [ioc("i9", "domain", "evil.com")]);
    const scoped = createApp(store, { stateStore });
    const res = await request(scoped).get("/global/iocs?q=evil.com");
    expect(res.status).toBe(200);
    expect(res.body.entries[0].caseIds).toEqual(["c1", "c2"]);
  });
});
