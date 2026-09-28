import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { reloadEnvPrefix, updateEnv, validateEnvUpdates } from "../../src/settings/envManager.js";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, setServerLogger } from "../../src/server.js";
import { createConsoleLogger } from "../../src/logging/logger.js";

/**
 * SETTINGS CAN PUT A KEY BACK TO "NOT SET" (#1785).
 *
 * Every Settings select has a blank option — "not set", "default (…)" or "same as …". The .env
 * store could only write KEY=value, so choosing the blank option again was never saved. An unset
 * now removes the key's line, and the reload that follows removes it from the running process.
 */
const originalEnv = { ...process.env };
let dir: string;
let envFile: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "dfir-envunset-"));
  envFile = join(dir, ".env");
  process.env.DFIR_ENV_FILE = envFile;
});

afterEach(async () => {
  process.env = { ...originalEnv };
  await rm(dir, { recursive: true, force: true });
});

describe("updateEnv with unset keys", () => {
  it("removes the key's line and keeps the rest of the file", async () => {
    await writeFile(envFile, "# header\nDFIR_LOCAL_TELEMETRY=off\nDFIR_OTHER=keep\n", "utf8");
    await updateEnv({}, ["DFIR_LOCAL_TELEMETRY"]);

    const written = await readFile(envFile, "utf8");
    expect(written).not.toContain("DFIR_LOCAL_TELEMETRY");
    expect(written).toContain("# header");
    expect(written).toContain("DFIR_OTHER=keep");
  });

  it("removes the legacy DFIR_AI_ alias of an unset DFIR_VISION_ key", async () => {
    await writeFile(
      envFile,
      "DFIR_VISION_PROVIDER=openai\nDFIR_AI_PROVIDER=openai\nDFIR_AI_MODEL=m\n",
      "utf8",
    );
    await updateEnv({}, ["DFIR_VISION_PROVIDER"]);

    const written = await readFile(envFile, "utf8");
    expect(written).not.toMatch(/PROVIDER/);
    expect(written).toContain("DFIR_AI_MODEL=m");
  });
});

describe("reloadEnvPrefix after an unset", () => {
  it("removes the unset key from the running process and reports it applied", async () => {
    await writeFile(envFile, "DFIR_AI_SYNTH_FALLBACK_PROVIDER=gemini\n", "utf8");
    process.env.DFIR_AI_SYNTH_FALLBACK_PROVIDER = "gemini";
    await updateEnv({}, ["DFIR_AI_SYNTH_FALLBACK_PROVIDER"]);
    const applied = await reloadEnvPrefix("DFIR_AI_");

    expect(process.env.DFIR_AI_SYNTH_FALLBACK_PROVIDER).toBeUndefined();
    expect(applied).toContain("DFIR_AI_SYNTH_FALLBACK_PROVIDER");
  });

  it("removes the legacy alias of an unset vision key from the process too", async () => {
    await writeFile(envFile, "DFIR_VISION_IMAGE_DETAIL=low\nDFIR_AI_IMAGE_DETAIL=low\n", "utf8");
    process.env.DFIR_VISION_IMAGE_DETAIL = "low";
    process.env.DFIR_AI_IMAGE_DETAIL = "low";
    await updateEnv({}, ["DFIR_VISION_IMAGE_DETAIL"]);
    await reloadEnvPrefix("DFIR_VISION_");

    expect(process.env.DFIR_VISION_IMAGE_DETAIL).toBeUndefined();
    expect(process.env.DFIR_AI_IMAGE_DETAIL).toBeUndefined();
  });

  it("leaves a legacy alias that only the shell supplies", async () => {
    await writeFile(envFile, "DFIR_VISION_PROVIDER=openai\n", "utf8");
    process.env.DFIR_VISION_PROVIDER = "openai";
    process.env.DFIR_AI_PROVIDER = "openrouter";
    await updateEnv({}, ["DFIR_VISION_PROVIDER"]);
    await reloadEnvPrefix("DFIR_VISION_");

    expect(process.env.DFIR_VISION_PROVIDER).toBeUndefined();
    expect(process.env.DFIR_AI_PROVIDER).toBe("openrouter");
  });

  it("drops a legacy-only vision value on the reload of the new name", async () => {
    await writeFile(envFile, "DFIR_AI_PROVIDER=openai\n", "utf8");
    process.env.DFIR_AI_PROVIDER = "openai";
    await updateEnv({}, ["DFIR_VISION_PROVIDER"]);
    const applied = await reloadEnvPrefix("DFIR_VISION_");

    expect(process.env.DFIR_AI_PROVIDER).toBeUndefined();
    expect(applied).toContain("DFIR_VISION_PROVIDER");
  });

  it("consumes the removal: a later reload leaves a newly supplied value alone", async () => {
    await writeFile(envFile, "DFIR_CROWDSTRIKE_CLOUD=eu-1\n", "utf8");
    await updateEnv({}, ["DFIR_CROWDSTRIKE_CLOUD"]);
    await reloadEnvPrefix("DFIR_CROWDSTRIKE_");
    process.env.DFIR_CROWDSTRIKE_CLOUD = "us-2";
    await reloadEnvPrefix("DFIR_CROWDSTRIKE_");

    expect(process.env.DFIR_CROWDSTRIKE_CLOUD).toBe("us-2");
  });

  it("a key written again after its unset is not removed by the reload", async () => {
    await writeFile(envFile, "DFIR_CROWDSTRIKE_CLOUD=eu-1\n", "utf8");
    await updateEnv({}, ["DFIR_CROWDSTRIKE_CLOUD"]);
    await updateEnv({ DFIR_CROWDSTRIKE_CLOUD: "us-2" });
    await reloadEnvPrefix("DFIR_CROWDSTRIKE_");

    expect(process.env.DFIR_CROWDSTRIKE_CLOUD).toBe("us-2");
  });

  it("never removes a variable that no unset named", async () => {
    await writeFile(envFile, "", "utf8");
    process.env.DFIR_CROWDSTRIKE_REGION_HINT = "from-shell";
    await reloadEnvPrefix("DFIR_CROWDSTRIKE_");

    expect(process.env.DFIR_CROWDSTRIKE_REGION_HINT).toBe("from-shell");
  });
});

describe("validateEnvUpdates with unset keys", () => {
  it("accepts an allowlisted key", () => {
    expect(validateEnvUpdates({}, ["DFIR_LOCAL_TELEMETRY"])).toEqual([]);
  });

  it("rejects a key off the allowlist, a non-string entry and a non-array list", () => {
    expect(validateEnvUpdates({}, ["PATH"])).toEqual(["PATH"]);
    expect(validateEnvUpdates({}, [42])).toHaveLength(1);
    expect(validateEnvUpdates({}, "DFIR_LOCAL_TELEMETRY")).toHaveLength(1);
  });

  it("rejects a key that is both written and unset, including a vision key's legacy alias", () => {
    expect(validateEnvUpdates({ DFIR_LOCAL_TELEMETRY: "off" }, ["DFIR_LOCAL_TELEMETRY"])).toEqual([
      "DFIR_LOCAL_TELEMETRY",
    ]);
    expect(validateEnvUpdates({ DFIR_AI_PROVIDER: "openai" }, ["DFIR_VISION_PROVIDER"])).toEqual([
      "DFIR_AI_PROVIDER",
    ]);
  });
});

describe("POST /settings/env with unset", () => {
  it("removes the key from .env", async () => {
    await writeFile(envFile, "DFIR_LOCAL_TELEMETRY=off\n", "utf8");
    setServerLogger(createConsoleLogger("info"));
    const app = createApp(new CaseStore(await mkdtemp(join(dir, "cases-"))), {});
    const res = await request(app)
      .post("/settings/env")
      .send({ updates: {}, unset: ["DFIR_LOCAL_TELEMETRY"] });

    expect(res.status).toBe(200);
    expect(await readFile(envFile, "utf8")).not.toContain("DFIR_LOCAL_TELEMETRY");
  });

  it("refuses an unset of a key off the allowlist and writes nothing", async () => {
    await writeFile(envFile, "DFIR_LOCAL_TELEMETRY=off\n", "utf8");
    setServerLogger(createConsoleLogger("info"));
    const app = createApp(new CaseStore(await mkdtemp(join(dir, "cases-"))), {});
    const res = await request(app)
      .post("/settings/env")
      .send({ updates: {}, unset: ["DFIR_LOCAL_TELEMETRY", "PATH"] });

    expect(res.status).toBe(400);
    expect(await readFile(envFile, "utf8")).toContain("DFIR_LOCAL_TELEMETRY=off");
  });
});
