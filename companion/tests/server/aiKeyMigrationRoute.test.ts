import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";

// GET/POST /settings/ai-key-migration: the one-time move of per-model keys and base URLs into the
// per-provider slots. The .env file is the source of truth, so every test points DFIR_ENV_FILE at a
// temp file and never touches the developer's real companion/.env.

const SECRET = "sk-or-do-not-leak";
let envRoot: string;
let envPath: string;
let savedEnv: NodeJS.ProcessEnv;

function isAiName(name: string): boolean {
  return name.startsWith("DFIR_AI_") || name.startsWith("DFIR_VISION_");
}

async function harness() {
  return createApp(new CaseStore(await mkdtemp(join(tmpdir(), "dfir-ai-key-migration-"))));
}

beforeEach(async () => {
  savedEnv = { ...process.env };
  for (const name of Object.keys(process.env)) if (isAiName(name)) delete process.env[name];
  envRoot = await mkdtemp(join(tmpdir(), "dfir-ai-key-migration-env-"));
  envPath = join(envRoot, ".env");
  process.env.DFIR_ENV_FILE = envPath;
});

afterEach(async () => {
  for (const name of Object.keys(process.env)) if (isAiName(name)) delete process.env[name];
  for (const [name, value] of Object.entries(savedEnv)) if (isAiName(name)) process.env[name] = value;
  if (savedEnv.DFIR_ENV_FILE === undefined) delete process.env.DFIR_ENV_FILE;
  else process.env.DFIR_ENV_FILE = savedEnv.DFIR_ENV_FILE;
  await rm(envRoot, { recursive: true, force: true });
});

const FILE = [
  "# AI models",
  "DFIR_VISION_PROVIDER=claude-code",
  "DFIR_AI_VELO_PROVIDER=openrouter",
  `DFIR_AI_VELO_KEY=${SECRET}`,
  "DFIR_AI_SYNTH_PROVIDER=gemini",
  "DFIR_AI_SYNTH_KEY=g-one",
  "DFIR_AI_KEY_GEMINI=g-two",
].join("\n");

describe("GET /settings/ai-key-migration", () => {
  it("reports the plan by name only, read from the file rather than process.env", async () => {
    await writeFile(envPath, FILE);
    process.env.DFIR_AI_RECONCILE_PROVIDER = "openai";
    process.env.DFIR_AI_RECONCILE_KEY = "only-in-process-env";

    const res = await request(await harness()).get("/settings/ai-key-migration");

    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      moves: [
        {
          role: "velociraptor",
          provider: "openrouter",
          setting: "key",
          target: "DFIR_AI_KEY_OPENROUTER",
          sources: ["DFIR_AI_VELO_KEY"],
        },
      ],
      conflicts: [{ provider: "gemini", setting: "key", roles: ["synthesis"], reason: expect.any(String) }],
    });
    expect(res.text).not.toContain(SECRET);
    expect(res.text).not.toContain("g-one");
    expect(res.text).not.toContain("only-in-process-env");
  });

  it("writes nothing", async () => {
    await writeFile(envPath, FILE);
    await request(await harness()).get("/settings/ai-key-migration");
    expect(await readFile(envPath, "utf8")).toBe(FILE);
  });
});

describe("POST /settings/ai-key-migration", () => {
  it("moves the value into the provider slot, blanks the model's copy and reloads process.env", async () => {
    await writeFile(envPath, FILE);

    const res = await request(await harness())
      .post("/settings/ai-key-migration")
      .send({ updates: { DFIR_AI_KEY_OPENAI: "forged" } });

    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.body.moves).toHaveLength(1);
    expect(res.text).not.toContain(SECRET);
    const file = await readFile(envPath, "utf8");
    expect(file).toContain(`DFIR_AI_KEY_OPENROUTER=${SECRET}`);
    expect(file).toContain("DFIR_AI_VELO_KEY=\n");
    expect(file).toContain("DFIR_AI_SYNTH_KEY=g-one");
    expect(file).toContain("# AI models");
    expect(file).not.toContain("forged");
    expect(process.env.DFIR_AI_KEY_OPENROUTER).toBe(SECRET);
    expect(process.env.DFIR_AI_VELO_KEY).toBe("");
  });

  it("finds nothing left to move on a second press", async () => {
    await writeFile(envPath, FILE);
    const app = await harness();
    await request(app).post("/settings/ai-key-migration");
    const again = await request(app).get("/settings/ai-key-migration");
    expect(again.body.moves).toEqual([]);
  });

  it("answers 500 with the reason, and no value, when the write is refused", async () => {
    // A tab inside the value is a control character, so updateEnv refuses the record.
    await writeFile(envPath, "DFIR_VISION_PROVIDER=claude-code\nDFIR_AI_VELO_KEY=bad\tvalue");

    const res = await request(await harness()).post("/settings/ai-key-migration");

    expect(res.status).toBe(500);
    expect(res.body.error).toContain("DFIR_AI_KEY_OPENROUTER");
    expect(res.text).not.toContain("bad");
  });
});
