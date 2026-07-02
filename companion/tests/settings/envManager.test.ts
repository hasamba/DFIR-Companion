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

import { resolveEnvFilePath, perUserEnvFile } from "../../src/settings/envManager.js";

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
