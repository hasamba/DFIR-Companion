import { describe, it, expect } from "vitest";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { AuthStore } from "../../src/auth/authStore.js";
import { TeamAuth } from "../../src/auth/teamAuth.js";
import { resolveRequestPolicy } from "../../src/auth/policy.js";
import { createApp } from "../../src/server.js";
import { loadToolConfig, type ToolConfig, type ToolId } from "../../src/integrations/tools/toolConfig.js";
import type { ToolRunner } from "../../src/integrations/tools/toolRunner.js";

// Settings → Tools "Update rules" with no case connected (#2259). The command updates the TOOL's
// rules — nothing case-scoped — so the dashboard calls a global route. That route spawns a process,
// which is exactly what the #211 hardening exists to keep away from strangers, so every test below
// that expects a refusal also asserts that nothing was spawned.

const BOOTSTRAP_TOKEN = "test-bootstrap-token-with-enough-entropy";
const USER_PASSWORD = "a different sufficiently long password";

function recordingRunner(): { runner: ToolRunner; spawned: string[] } {
  const spawned: string[] = [];
  const runner: ToolRunner = async (binary, args) => {
    spawned.push([binary, ...args].join(" "));
    return { stdout: "42 rules updated", stderr: "", code: 0 };
  };
  return { runner, spawned };
}

function suricataConfigs(): Map<ToolId, ToolConfig> {
  const suricata = loadToolConfig("suricata", {
    DFIR_TOOL_SURICATA_BINARY: "suricata",
    DFIR_TOOL_SURICATA_UPDATE_CMD: "suricata-update",
  })!;
  return new Map<ToolId, ToolConfig>([["suricata", suricata]]);
}

async function singleUserApp(opts: { withRunner?: boolean } = {}) {
  const root = await mkdtemp(join(tmpdir(), "dfir-upd-global-"));
  const store = new CaseStore(root);
  const { runner, spawned } = recordingRunner();
  const app = createApp(store, {
    stateStore: new StateStore(store),
    toolRunner: opts.withRunner === false ? undefined : runner,
    loadToolConfigs: suricataConfigs,
  });
  return { app, spawned };
}

describe("POST /tools/:toolId/update-rules — single-user mode (#2259)", () => {
  it("runs the update command with no case in existence", async () => {
    const { app, spawned } = await singleUserApp();
    const r = await request(app).post("/tools/suricata/update-rules").send({});
    expect(r.status).toBe(200);
    expect(r.body).toMatchObject({ ok: true, tool: "suricata" });
    expect(r.body.output).toMatch(/updated/);
    expect(spawned).toHaveLength(1);
  });

  it("refuses an untrusted browser origin before spawning (#211)", async () => {
    const { app, spawned } = await singleUserApp();
    const r = await request(app)
      .post("/tools/suricata/update-rules")
      .set("Origin", "https://evil.example")
      .send({});
    expect(r.status).toBe(403);
    expect(spawned).toEqual([]);
  });

  it("400s an unknown or unconfigured tool without spawning", async () => {
    const { app, spawned } = await singleUserApp();
    expect((await request(app).post("/tools/no-such-tool/update-rules").send({})).status).toBe(400);
    expect((await request(app).post("/tools/yara/update-rules").send({})).status).toBe(400);
    expect(spawned).toEqual([]);
  });

  it("501s when external tools are off", async () => {
    const { app } = await singleUserApp({ withRunner: false });
    expect((await request(app).post("/tools/suricata/update-rules").send({})).status).toBe(501);
  });
});

async function teamApp() {
  const root = await mkdtemp(join(tmpdir(), "dfir-upd-global-team-"));
  const store = new CaseStore(join(root, "cases"));
  await store.createCase({ caseId: "c1", name: "Case c1", investigator: "i", aiProvider: null });
  const { runner, spawned } = recordingRunner();
  const app = createApp(store, {
    stateStore: new StateStore(store),
    toolRunner: runner,
    loadToolConfigs: suricataConfigs,
    teamAuth: new TeamAuth({
      store: new AuthStore(join(root, "auth.sqlite")),
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

  // An investigator holds "write" on c1 — enough for the per-case routes, not for a global action.
  const created = await admin.post("/auth/users").set("X-DFIR-CSRF", adminCsrf).send({
    username: "investigator",
    password: USER_PASSWORD,
    displayName: "Investigator",
  });
  expect(created.status).toBe(201);
  const grant = await admin
    .put(`/auth/cases/c1/roles/${encodeURIComponent(created.body.id as string)}`)
    .set("X-DFIR-CSRF", adminCsrf)
    .send({ role: "investigator" });
  expect(grant.status).toBe(200);
  const investigator = request.agent(app);
  const login = await investigator
    .post("/auth/local/login")
    .send({ username: "investigator", password: USER_PASSWORD });
  expect(login.status).toBe(200);
  const investigatorCsrf = (await investigator.get("/auth/me")).body.csrfToken as string;

  return { app, spawned, admin, adminCsrf, investigator, investigatorCsrf };
}

describe("POST /tools/:toolId/update-rules — team mode needs a global admin (#2259)", () => {
  it("resolves to the global-admin policy, never a case permission", () => {
    for (const path of ["/tools/suricata/update-rules", "/TOOLS/suricata/UPDATE-RULES/"]) {
      expect(resolveRequestPolicy("POST", path)).toEqual({ kind: "global", permission: "admin" });
    }
  });

  it("refuses an unauthenticated caller with 401 and spawns nothing", async () => {
    const { app, spawned } = await teamApp();
    const r = await request(app).post("/tools/suricata/update-rules").send({});
    expect(r.status).toBe(401);
    expect(spawned).toEqual([]);
  });

  it("refuses a signed-in non-admin with 403 and spawns nothing", async () => {
    const { spawned, investigator, investigatorCsrf } = await teamApp();
    const r = await investigator
      .post("/tools/suricata/update-rules")
      .set("X-DFIR-CSRF", investigatorCsrf)
      .send({});
    expect(r.status).toBe(403);
    expect(spawned).toEqual([]);
  });

  it("lets a global admin update rules", async () => {
    const { spawned, admin, adminCsrf } = await teamApp();
    const r = await admin.post("/tools/suricata/update-rules").set("X-DFIR-CSRF", adminCsrf).send({});
    expect(r.status).toBe(200);
    expect(r.body.ok).toBe(true);
    expect(spawned).toHaveLength(1);
  });
});

// The legacy per-case spelling ran the same global rule update but sat in the case "write" bucket, so
// any investigator on any case could trigger it in team mode (#2264). Same bar as the global route now.
describe("POST /cases/:id/tools/:toolId/update-rules — team mode needs a global admin (#2264)", () => {
  const SPELLINGS = [
    "/cases/c1/tools/suricata/update-rules",
    "/cases/c1/tools/suricata/update-rules/",
    "/cases/c1/TOOLS/suricata/UPDATE-RULES",
    "/cases/c1/Tools/suricata/Update-Rules/",
  ];

  it("resolves to the global-admin policy in every spelling", () => {
    for (const path of SPELLINGS) {
      expect(resolveRequestPolicy("POST", path), path).toEqual({ kind: "global", permission: "admin" });
    }
  });

  it("refuses an investigator holding case write with 403 and spawns nothing", async () => {
    const { spawned, investigator, investigatorCsrf } = await teamApp();
    for (const path of SPELLINGS) {
      const r = await investigator.post(path).set("X-DFIR-CSRF", investigatorCsrf).send({});
      expect(r.status, path).toBe(403);
    }
    expect(spawned).toEqual([]);
  });

  it("lets a global admin update rules through the per-case route", async () => {
    const { spawned, admin, adminCsrf } = await teamApp();
    const r = await admin
      .post("/cases/c1/tools/suricata/update-rules")
      .set("X-DFIR-CSRF", adminCsrf)
      .send({});
    expect(r.status).toBe(200);
    expect(r.body.ok).toBe(true);
    expect(spawned).toHaveLength(1);
  });
});

describe("Settings → Tools button (#2259)", () => {
  it("calls the case-free route and no longer blames the server", async () => {
    const src = await readFile(
      new URL("../../../public/js/dashboard-settings-tools.js", import.meta.url),
      "utf8",
    );
    const start = src.indexOf("function updateToolRules(");
    expect(start).toBeGreaterThan(-1);
    const end = src.indexOf("\n  function ", start + 1);
    const fn = src.slice(start, end === -1 ? undefined : end);
    expect(fn).toContain("fetch(`/tools/${encodeURIComponent(toolId)}/update-rules`");
    expect(fn).not.toMatch(/\/cases\//);
    expect(fn).not.toMatch(/restart the companion server/i);
  });
});
