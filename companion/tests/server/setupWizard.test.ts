import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, setServerLogger } from "../../src/server.js";
import { createConsoleLogger } from "../../src/logging/logger.js";

// Backend for the comprehensive Setup wizard (#181): generic /settings/reload (allowlisted prefix),
// /setup/status (configured?-per-integration, derived live from env), /timesketch/reconnect (hot
// reconnect), and the new /health flags.
//
// reloadEnvPrefix resolves its .env via resolveEnvFilePath(), which honours DFIR_ENV_FILE before
// falling back to cwd/.env — so we point it at a per-file temp .env (issue #173). This test used to
// snapshot-and-restore the developer's REAL companion/.env, which raced with aiReload.test.ts (the
// other file doing the same) under parallel runs: a transient read error was indistinguishable from
// "no .env existed", and the restore step then deleted the real file. Never touch cwd/.env.
let envPath: string;
let envRoot: string;

let app: ReturnType<typeof createApp>;

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-setup-"));
  envRoot = await mkdtemp(join(tmpdir(), "dfir-setup-env-"));
  envPath = join(envRoot, ".env");
  process.env.DFIR_ENV_FILE = envPath;
  const store = new CaseStore(root);
  setServerLogger(createConsoleLogger("info"));
  app = createApp(store, {});
  for (const k of ["DFIR_IRIS_URL", "DFIR_IRIS_KEY", "DFIR_VT_KEY", "DFIR_NSRL_DB", "DFIR_NSRL_FILE"]) delete process.env[k];
});

afterEach(async () => {
  delete process.env.DFIR_ENV_FILE;
  await rm(envRoot, { recursive: true, force: true });
});

describe("/settings/reload", () => {
  it("applies an allowlisted prefix and reports the applied keys", async () => {
    await writeFile(envPath, "DFIR_IRIS_URL=https://iris.example\nDFIR_IRIS_KEY=abc\nUNRELATED=x\n", "utf8");
    const res = await request(app).post("/settings/reload").send({ prefix: "DFIR_IRIS_" });
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.body.applied).toEqual(expect.arrayContaining(["DFIR_IRIS_URL", "DFIR_IRIS_KEY"]));
    expect(res.body.applied).not.toContain("UNRELATED");
    expect(process.env.DFIR_IRIS_URL).toBe("https://iris.example");
  });

  it("rejects a prefix that is not on the allowlist", async () => {
    const res = await request(app).post("/settings/reload").send({ prefix: "DFIR_SECRET_" });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/allowlist/);
  });

  it("requires a prefix", async () => {
    const res = await request(app).post("/settings/reload").send({});
    expect(res.status).toBe(400);
  });
});

describe("/setup/status", () => {
  it("reports each integration as configured or not, derived from env", async () => {
    const before = await request(app).get("/setup/status");
    expect(before.status).toBe(200);
    expect(before.body.iris).toBe(false);
    expect(before.body.enrichment.virustotal).toBe(false);

    // Save + reload IRIS + a VT key, then re-check — status reflects the live env (no restart).
    await writeFile(envPath, "DFIR_IRIS_URL=https://iris.example\nDFIR_IRIS_KEY=abc\nDFIR_VT_KEY=zzz\n", "utf8");
    await request(app).post("/settings/reload").send({ prefix: "DFIR_IRIS_" });
    await request(app).post("/settings/reload").send({ prefix: "DFIR_VT_" });

    const after = await request(app).get("/setup/status");
    expect(after.body.iris).toBe(true);
    expect(after.body.enrichment.virustotal).toBe(true);
  });
});

describe("/timesketch/reconnect", () => {
  it("returns not-configured when DFIR_TIMESKETCH_* are unset", async () => {
    await writeFile(envPath, "UNRELATED=1\n", "utf8");
    delete process.env.DFIR_TIMESKETCH_URL;
    delete process.env.DFIR_TIMESKETCH_USER;
    delete process.env.DFIR_TIMESKETCH_PASSWORD;
    const res = await request(app).post("/timesketch/reconnect");
    expect(res.status).toBe(200);
    expect(res.body.configured).toBe(false);
    expect(res.body.ok).toBe(false);
  });
});

describe("/health integration flags", () => {
  it("exposes irisEnabled and timesketchEnabled booleans", async () => {
    const res = await request(app).get("/health");
    expect(res.status).toBe(200);
    expect(typeof res.body.irisEnabled).toBe("boolean");
    expect(typeof res.body.timesketchEnabled).toBe("boolean");
  });
});
