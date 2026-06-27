import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, writeFile, rm, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, setServerLogger } from "../../src/server.js";
import { createConsoleLogger } from "../../src/logging/logger.js";

// Backend for the comprehensive Setup wizard (#181): generic /settings/reload (allowlisted prefix),
// /setup/status (configured?-per-integration, derived live from env), /timesketch/reconnect (hot
// reconnect), and the new /health flags. reloadEnvPrefix reads .env from cwd; snapshot+restore it.
const ENV_PATH = resolve(process.cwd(), ".env");

let app: ReturnType<typeof createApp>;
let savedEnv: string | undefined;
let hadEnv = false;

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-setup-"));
  const store = new CaseStore(root);
  setServerLogger(createConsoleLogger("info"));
  app = createApp(store, {});
  try { savedEnv = await readFile(ENV_PATH, "utf8"); hadEnv = true; } catch { hadEnv = false; savedEnv = undefined; }
  for (const k of ["DFIR_IRIS_URL", "DFIR_IRIS_KEY", "DFIR_VT_KEY", "DFIR_NSRL_DB", "DFIR_NSRL_FILE"]) delete process.env[k];
});

afterEach(async () => {
  if (hadEnv && savedEnv !== undefined) await writeFile(ENV_PATH, savedEnv, "utf8");
  else await rm(ENV_PATH, { force: true });
});

describe("/settings/reload", () => {
  it("applies an allowlisted prefix and reports the applied keys", async () => {
    await writeFile(ENV_PATH, "DFIR_IRIS_URL=https://iris.example\nDFIR_IRIS_KEY=abc\nUNRELATED=x\n", "utf8");
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
    await writeFile(ENV_PATH, "DFIR_IRIS_URL=https://iris.example\nDFIR_IRIS_KEY=abc\nDFIR_VT_KEY=zzz\n", "utf8");
    await request(app).post("/settings/reload").send({ prefix: "DFIR_IRIS_" });
    await request(app).post("/settings/reload").send({ prefix: "DFIR_VT_" });

    const after = await request(app).get("/setup/status");
    expect(after.body.iris).toBe(true);
    expect(after.body.enrichment.virustotal).toBe(true);
  });
});

describe("/timesketch/reconnect", () => {
  it("returns not-configured when DFIR_TIMESKETCH_* are unset", async () => {
    await writeFile(ENV_PATH, "UNRELATED=1\n", "utf8");
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
