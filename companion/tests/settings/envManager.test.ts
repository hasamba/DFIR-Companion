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

  // The Settings panel's Presidio URL / confidence-floor fields (task 9) POST through this same
  // validator — without DFIR_PRESIDIO_ on the allowlist, saving them would 400 with "rejected keys".
  it("accepts the DFIR_PRESIDIO_ prefix (analyzer URL + confidence floor)", () => {
    const rejected = validateEnvUpdates({
      DFIR_PRESIDIO_URL: "http://localhost:5002",
      DFIR_PRESIDIO_MIN_SCORE: "0.6",
    });
    expect(rejected).toEqual([]);
  });

  it("rejects security-sensitive keys that could redirect case data or disable protections", () => {
    const rejected = validateEnvUpdates({
      DFIR_CASES_ROOT: "/etc",
      DFIR_ENV_FILE: "/tmp/evil.env",
      DFIR_ANONYMIZE: "off",
      DFIR_ALLOWED_ORIGINS: "https://evil.com",
      DFIR_ALLOWED_HOSTS: "evil.com",
      DFIR_ALLOWED_HOST_SUFFIXES: ".evil.com",
      DFIR_HOST: "0.0.0.0",
      DFIR_PORT: "80",
      DFIR_DEMO_MODE: "true",
      DFIR_LOG_DIR: "/tmp",
    });
    expect(rejected).toEqual(
      expect.arrayContaining([
        "DFIR_CASES_ROOT",
        "DFIR_ENV_FILE",
        "DFIR_ANONYMIZE",
        "DFIR_ALLOWED_ORIGINS",
        // The host allow-lists decide which names reach the API at all — writable would mean the
        // rebinding gate (#280) could be widened from the dashboard.
        "DFIR_ALLOWED_HOSTS",
        "DFIR_ALLOWED_HOST_SUFFIXES",
        "DFIR_HOST",
        "DFIR_PORT",
        "DFIR_DEMO_MODE",
        "DFIR_LOG_DIR",
      ]),
    );
    expect(rejected).toHaveLength(10);
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

  // #422: a dotenv record is one line, so a line break inside a VALUE writes a second record.
  // The key allowlist saw one allowed key and waved it through.
  it("rejects a value carrying a newline that would land a second .env assignment", () => {
    expect(validateEnvUpdates({ DFIR_AI_MODEL: "gpt-4o\nDFIR_HOST=0.0.0.0" })).toEqual(["DFIR_AI_MODEL"]);
    expect(validateEnvUpdates({ DFIR_AI_MODEL: "gpt-4o\r\nDFIR_CASES_ROOT=/etc" })).toEqual([
      "DFIR_AI_MODEL",
    ]);
    expect(validateEnvUpdates({ DFIR_AI_MODEL: "gpt-4o\rDFIR_DEMO_MODE=true" })).toEqual(["DFIR_AI_MODEL"]);
    // A NUL is a control character too — rejected, whatever the reader would make of it.
    expect(validateEnvUpdates({ DFIR_AI_MODEL: "gpt-4o\u0000DFIR_ANONYMIZE=off" })).toEqual([
      "DFIR_AI_MODEL",
    ]);
    // A plain space is NOT a separator: one record, one value. The guard must not reject it.
    expect(validateEnvUpdates({ DFIR_AI_MODEL: "gpt-4o preview" })).toEqual([]);
  });

  // The same bypass through the KEY: startsWith() is a prefix test, and the denylist is an
  // exact-match Set, so a key that carries its own newline satisfied both.
  it("rejects a key carrying a newline even though it starts with a writable prefix", () => {
    const rejected = validateEnvUpdates({ "DFIR_AI_MODEL\nDFIR_HOST": "0.0.0.0" });
    expect(rejected).toHaveLength(1);
    expect(rejected[0]).not.toContain("\n"); // the reply and the log must not carry the payload
  });

  it("rejects non-string values rather than stringifying them into the file", () => {
    expect(validateEnvUpdates({ DFIR_AI_MODEL: 42 })).toEqual(["DFIR_AI_MODEL"]);
    expect(validateEnvUpdates({ DFIR_AI_MODEL: null })).toEqual(["DFIR_AI_MODEL"]);
    expect(validateEnvUpdates({ DFIR_AI_MODEL: { toString: () => "x" } })).toEqual(["DFIR_AI_MODEL"]);
    expect(validateEnvUpdates({ DFIR_AI_MODEL: ["a", "b"] })).toEqual(["DFIR_AI_MODEL"]);
  });

  // The guard must not cost anyone a real secret: API keys and URLs are full of punctuation.
  it("still accepts ordinary secrets containing punctuation, spaces and '='", () => {
    expect(
      validateEnvUpdates({
        DFIR_VT_KEY: "sk-live_A1b2/C3+d4=e5==",
        DFIR_IRIS_URL: "https://iris.example.test:8443/api?x=1&y=2#frag",
        DFIR_NOTIFY_SLACK_WEBHOOK: "https://hooks.slack.com/services/T0/B0/xXyYzZ",
        DFIR_AI_SYNTH_MODEL: "claude sonnet 4.5 (preview)",
        DFIR_SMTP_PASSWORD: "hunter2 — don't tell",
      }),
    ).toEqual([]);
  });

  it("reports a long malformed key truncated, not in full", () => {
    const rejected = validateEnvUpdates({ ["DFIR_AI_" + "x".repeat(500) + "\nDFIR_HOST"]: "1" });
    expect(rejected).toHaveLength(1);
    expect(rejected[0].length).toBeLessThanOrEqual(65);
  });

  it("rejects a mix of allowed and denied keys, reporting only the denied ones", () => {
    const rejected = validateEnvUpdates({
      DFIR_VISION_MODEL: "gpt-4o-mini", // ok
      DFIR_CASES_ROOT: "/evil", // denied
      DFIR_SHODAN_KEY: "abc", // ok
      DFIR_ENV_FILE: "/evil.env", // denied
    });
    expect(rejected).toEqual(["DFIR_CASES_ROOT", "DFIR_ENV_FILE"]);
  });
});
