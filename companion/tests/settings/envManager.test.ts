import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { resolve, join, dirname } from "node:path";

// isSeaRuntime is evaluated at module load in serverAssets; mock it so we can drive the SEA branch
// without an actual single-executable build.
const seaState = { sea: false };
vi.mock("../../src/serverAssets.js", () => ({
  isSeaRuntime: () => seaState.sea,
}));

// existsSync gates the per-user seed vs EXE-adjacent fallback; make it controllable.
const fsState = { exists: false };
vi.mock("node:fs", () => ({
  existsSync: () => fsState.exists,
}));

import { resolveEnvFilePath, perUserEnvFile, validateEnvUpdates } from "../../src/settings/envManager.js";

describe("resolveEnvFilePath", () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    seaState.sea = false;
    fsState.exists = false;
    delete process.env.DFIR_ENV_FILE;
    delete process.env.LOCALAPPDATA;
  });

  afterEach(() => {
    process.env = { ...originalEnv };
  });

  it("honours an explicit DFIR_ENV_FILE override above everything else", () => {
    seaState.sea = true;
    fsState.exists = true;
    process.env.LOCALAPPDATA = "C:/Users/x/AppData/Local";
    process.env.DFIR_ENV_FILE = "D:/custom/my.env";
    expect(resolveEnvFilePath()).toBe(resolve("D:/custom/my.env"));
  });

  it("falls back to cwd/.env in dev/Docker (non-SEA)", () => {
    seaState.sea = false;
    expect(resolveEnvFilePath()).toBe(resolve(process.cwd(), ".env"));
  });

  it("prefers the per-user %LOCALAPPDATA% seed in a SEA build when it exists", () => {
    seaState.sea = true;
    fsState.exists = true;
    process.env.LOCALAPPDATA = "C:/Users/x/AppData/Local";
    expect(resolveEnvFilePath()).toBe(perUserEnvFile());
  });

  it("falls back to the EXE-adjacent .env in a SEA build when no per-user seed exists", () => {
    seaState.sea = true;
    fsState.exists = false;
    process.env.LOCALAPPDATA = "C:/Users/x/AppData/Local";
    expect(resolveEnvFilePath()).toBe(join(dirname(process.execPath), ".env"));
  });

  it("perUserEnvFile is null when LOCALAPPDATA is unset (non-Windows)", () => {
    delete process.env.LOCALAPPDATA;
    expect(perUserEnvFile()).toBeNull();
  });
});

describe("validateEnvUpdates", () => {
  it("accepts writable prefix keys (AI, integration, enrichment, etc.)", () => {
    const rejected = validateEnvUpdates({
      DFIR_VISION_PROVIDER: "openai",
      DFIR_AI_SYNTH_MODEL: "gpt-4o",
      DFIR_IRIS_URL: "https://iris.example",
      DFIR_VT_KEY: "abc123",
      DFIR_LOG_LEVEL: "debug",
      DFIR_NOTIFY_SLACK_WEBHOOK: "https://hooks.slack.com/x",
    });
    expect(rejected).toEqual([]);
  });

  it("rejects security-sensitive keys that could redirect case data or disable protections", () => {
    const rejected = validateEnvUpdates({
      DFIR_CASES_ROOT: "/etc",
      DFIR_ENV_FILE: "/tmp/evil.env",
      DFIR_ANONYMIZE: "off",
      DFIR_ALLOWED_ORIGINS: "https://evil.com",
      DFIR_HOST: "0.0.0.0",
      DFIR_PORT: "80",
      DFIR_DEMO_MODE: "true",
      DFIR_LOG_DIR: "/tmp",
    });
    expect(rejected).toEqual(expect.arrayContaining([
      "DFIR_CASES_ROOT", "DFIR_ENV_FILE", "DFIR_ANONYMIZE", "DFIR_ALLOWED_ORIGINS",
      "DFIR_HOST", "DFIR_PORT", "DFIR_DEMO_MODE", "DFIR_LOG_DIR",
    ]));
    expect(rejected).toHaveLength(8);
  });

  it("rejects unknown keys not on any writable prefix", () => {
    const rejected = validateEnvUpdates({
      PATH: "/usr/bin",
      HOME: "/root",
      RANDOM_KEY: "value",
      DFIR_UNKNOWN_FOO: "bar",
    });
    expect(rejected).toEqual(expect.arrayContaining(["PATH", "HOME", "RANDOM_KEY", "DFIR_UNKNOWN_FOO"]));
    expect(rejected).toHaveLength(4);
  });

  it("accepts an empty updates object", () => {
    expect(validateEnvUpdates({})).toEqual([]);
  });

  it("rejects a mix of allowed and denied keys, reporting only the denied ones", () => {
    const rejected = validateEnvUpdates({
      DFIR_VISION_MODEL: "gpt-4o-mini",   // ok
      DFIR_CASES_ROOT: "/evil",           // denied
      DFIR_SHODAN_KEY: "abc",              // ok
      DFIR_ENV_FILE: "/evil.env",          // denied
    });
    expect(rejected).toEqual(["DFIR_CASES_ROOT", "DFIR_ENV_FILE"]);
  });
});
