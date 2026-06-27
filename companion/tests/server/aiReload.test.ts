import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, writeFile, rm, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, setServerLogger } from "../../src/server.js";
import { createConsoleLogger } from "../../src/logging/logger.js";

// POST /settings/ai-reload (#181, the first-run wizard's save→reload→test flow) applies the saved
// DFIR_AI_* values from .env into process.env so /diagnostics/ai-test sees them WITHOUT a restart.
// reloadEnvPrefix reads .env from process.cwd(); we write a temp .env there and restore it after.
const ENV_PATH = resolve(process.cwd(), ".env");

let app: ReturnType<typeof createApp>;
let savedEnv: string | undefined;
let hadEnv = false;

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-aireload-"));
  const store = new CaseStore(root);
  setServerLogger(createConsoleLogger("info"));
  app = createApp(store, {});
  // Snapshot any real .env so we can restore it, then write a known one.
  try {
    savedEnv = await readFile(ENV_PATH, "utf8");
    hadEnv = true;
  } catch {
    hadEnv = false;
    savedEnv = undefined;
  }
  delete process.env.DFIR_AI_PROVIDER;
  delete process.env.DFIR_AI_MODEL;
});

afterEach(async () => {
  if (hadEnv && savedEnv !== undefined) await writeFile(ENV_PATH, savedEnv, "utf8");
  else await rm(ENV_PATH, { force: true });
});

describe("/settings/ai-reload", () => {
  it("applies saved DFIR_AI_* values from .env into process.env and reports them", async () => {
    await writeFile(ENV_PATH, "DFIR_AI_PROVIDER=openai\nDFIR_AI_MODEL=gpt-4o-mini\nUNRELATED=keepme\n", "utf8");

    const res = await request(app).post("/settings/ai-reload");
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.body.applied).toContain("DFIR_AI_PROVIDER");
    expect(res.body.applied).toContain("DFIR_AI_MODEL");
    // Scoped to the DFIR_AI_ prefix only — unrelated keys are not touched.
    expect(res.body.applied).not.toContain("UNRELATED");
    // The values are now live in process.env (what buildProvider() reads).
    expect(process.env.DFIR_AI_PROVIDER).toBe("openai");
    expect(process.env.DFIR_AI_MODEL).toBe("gpt-4o-mini");
  });

  it("succeeds with an empty applied list when no DFIR_AI_* keys are present", async () => {
    await writeFile(ENV_PATH, "UNRELATED=1\n", "utf8");
    const res = await request(app).post("/settings/ai-reload");
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.body.applied).toEqual([]);
  });
});
