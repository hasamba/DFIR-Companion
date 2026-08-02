import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { CommentsStore } from "../../src/analysis/comments.js";

/**
 * POST /settings/env, at the request boundary (#422).
 *
 * The unit tests in tests/settings/envManager.test.ts cover validateEnvUpdates directly; these
 * assert the outcome that actually matters — what ends up in the .env file the server reads its
 * security configuration from. DFIR_ENV_FILE points resolveEnvFilePath at a temp file, so the
 * route writes there instead of the developer's real .env.
 */
const originalEnvFile = process.env.DFIR_ENV_FILE;
let envFile = "";

async function harness() {
  const root = await mkdtemp(join(tmpdir(), "dfir-settings-env-"));
  envFile = join(root, ".env");
  await writeFile(envFile, "# existing config\nDFIR_AI_MODEL=old-model\n", "utf8");
  process.env.DFIR_ENV_FILE = envFile;
  const store = new CaseStore(root);
  const app = createApp(store, {
    stateStore: new StateStore(store),
    commentsStore: new CommentsStore(store),
  });
  return { app };
}

beforeEach(() => {
  delete process.env.DFIR_ENV_FILE;
});
afterEach(() => {
  if (originalEnvFile === undefined) delete process.env.DFIR_ENV_FILE;
  else process.env.DFIR_ENV_FILE = originalEnvFile;
});

describe("POST /settings/env — a value may not forge a second record", () => {
  it("rejects a multiline value and leaves the protected key unwritten", async () => {
    const { app } = await harness();
    const res = await request(app)
      .post("/settings/env")
      .send({ updates: { DFIR_AI_MODEL: "gpt-4o\nDFIR_HOST=0.0.0.0" } });
    expect(res.status).toBe(400);
    const written = await readFile(envFile, "utf8");
    expect(written).not.toContain("DFIR_HOST");
    expect(written).toContain("DFIR_AI_MODEL=old-model"); // the save was refused wholesale
  });

  it("rejects a multiline KEY that starts with a writable prefix", async () => {
    const { app } = await harness();
    const res = await request(app)
      .post("/settings/env")
      .send({ updates: { "DFIR_AI_MODEL\nDFIR_CASES_ROOT": "/etc" } });
    expect(res.status).toBe(400);
    expect(res.body.error).not.toContain("\n");
    expect(await readFile(envFile, "utf8")).not.toContain("DFIR_CASES_ROOT");
  });

  it("rejects a non-string value instead of writing its stringification", async () => {
    const { app } = await harness();
    const res = await request(app)
      .post("/settings/env")
      .send({ updates: { DFIR_AI_MODEL: { a: 1 } } });
    expect(res.status).toBe(400);
    expect(await readFile(envFile, "utf8")).not.toContain("object Object");
  });

  it("still saves an ordinary value, replacing the existing record in place", async () => {
    const { app } = await harness();
    const res = await request(app)
      .post("/settings/env")
      .send({ updates: { DFIR_AI_MODEL: "claude-opus-4.5", DFIR_VT_KEY: "sk-live_A1b2/C3+d4=" } });
    expect(res.status).toBe(200);
    const written = await readFile(envFile, "utf8");
    expect(written).toContain("DFIR_AI_MODEL=claude-opus-4.5");
    expect(written).toContain("DFIR_VT_KEY=sk-live_A1b2/C3+d4=");
    expect(written).toContain("# existing config"); // comments and structure preserved
    expect(written).not.toContain("old-model");
  });
});
