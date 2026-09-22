import { describe, it, expect } from "vitest";
import { resolveJevSettings, type JevSettings } from "../../src/analysis/ai/jev/jevConfig.js";

// Every test starts from "on", so a failure names the branch under test rather than the switch.
const ON = { DFIR_JEV_ENABLED: "1" } as NodeJS.ProcessEnv;

function settingsOf(env: NodeJS.ProcessEnv): JevSettings {
  const out = resolveJevSettings(env);
  if (!out.settings) throw new Error(`expected settings, got: ${out.reason}`);
  return out.settings;
}

function reasonOf(env: NodeJS.ProcessEnv): string {
  const out = resolveJevSettings(env);
  if (out.settings) throw new Error("expected Jev to be unusable, but it resolved");
  return out.reason;
}

describe("resolveJevSettings — the on/off switch", () => {
  it("is OFF when nothing is set", () => {
    expect(reasonOf({})).toMatch(/DFIR_JEV_ENABLED/);
  });

  it("accepts 1, true, yes and on, in any case", () => {
    for (const value of ["1", "true", "TRUE", "yes", "On"]) {
      expect(settingsOf({ DFIR_JEV_ENABLED: value, DFIR_JEV_KEY: "k" }).enabled).toBe(true);
    }
  });

  it("stays off for 0, false, no and any other value", () => {
    for (const value of ["0", "false", "no", "off", "maybe", ""]) {
      expect(reasonOf({ DFIR_JEV_ENABLED: value, DFIR_JEV_KEY: "k" })).toMatch(/DFIR_JEV_ENABLED/);
    }
  });
});

describe("resolveJevSettings — provider, route and model defaults", () => {
  it("defaults to the OpenRouter alpha decisions route and the VERSIONED model id", () => {
    const s = settingsOf({ ...ON, DFIR_JEV_KEY: "k" });
    expect(s.provider).toBe("openrouter");
    expect(s.baseUrl).toBe("https://openrouter.ai/api/alpha/decisions");
    // typesafe/jev-latest does not exist on OpenRouter and 400s — only the versioned id works.
    expect(s.model).toBe("typesafe/jev-1.13");
  });

  it("defaults the TypeSafe direct route to api.typesafe.ai and jev-latest", () => {
    const s = settingsOf({ ...ON, DFIR_JEV_PROVIDER: "typesafe", DFIR_JEV_KEY: "ts-key" });
    expect(s.baseUrl).toBe("https://api.typesafe.ai/v1/systemone");
    expect(s.model).toBe("jev-latest");
  });

  it("honors explicit model and base URL overrides", () => {
    const s = settingsOf({
      ...ON,
      DFIR_JEV_KEY: "k",
      DFIR_JEV_MODEL: "typesafe/jev-2.0",
      DFIR_JEV_BASE_URL: "https://openrouter.ai/api/beta/decisions",
    });
    expect(s.model).toBe("typesafe/jev-2.0");
    expect(s.baseUrl).toBe("https://openrouter.ai/api/beta/decisions");
  });

  it("refuses an unknown provider by name", () => {
    expect(reasonOf({ ...ON, DFIR_JEV_PROVIDER: "anthropic", DFIR_JEV_KEY: "k" })).toMatch(
      /openrouter.*typesafe/is,
    );
  });

  it("refuses a base URL that is not a URL", () => {
    expect(reasonOf({ ...ON, DFIR_JEV_KEY: "k", DFIR_JEV_BASE_URL: "not a url" })).toMatch(
      /DFIR_JEV_BASE_URL/,
    );
  });
});

describe("resolveJevSettings — key inheritance", () => {
  it("uses DFIR_JEV_KEY when it is set, for either provider", () => {
    expect(settingsOf({ ...ON, DFIR_JEV_KEY: "own", DFIR_AI_KEY: "other" }).apiKey).toBe("own");
    expect(settingsOf({ ...ON, DFIR_JEV_PROVIDER: "typesafe", DFIR_JEV_KEY: "own" }).apiKey).toBe("own");
  });

  it("treats an empty or blank DFIR_JEV_KEY as unset and falls through", () => {
    expect(settingsOf({ ...ON, DFIR_JEV_KEY: "  ", DFIR_AI_KEY: "legacy" }).apiKey).toBe("legacy");
  });

  it("inherits the OpenRouter key in the repo's own fallback order", () => {
    const all = {
      ...ON,
      DFIR_AI_VELO_KEY: "velo",
      DFIR_AI_SYNTH_KEY: "synth",
      DFIR_VISION_KEY: "vision",
      DFIR_AI_KEY: "legacy",
    };
    expect(settingsOf(all).apiKey).toBe("velo");
    expect(settingsOf({ ...all, DFIR_AI_VELO_KEY: "" }).apiKey).toBe("synth");
    expect(settingsOf({ ...all, DFIR_AI_VELO_KEY: "", DFIR_AI_SYNTH_KEY: "" }).apiKey).toBe("vision");
    expect(
      settingsOf({ ...all, DFIR_AI_VELO_KEY: "", DFIR_AI_SYNTH_KEY: "", DFIR_VISION_KEY: "" }).apiKey,
    ).toBe("legacy");
  });

  it("says plainly when there is no key to use at all", () => {
    expect(reasonOf(ON)).toMatch(/DFIR_JEV_KEY/);
  });

  it("requires the TypeSafe route to carry its OWN key — nothing is inherited", () => {
    const reason = reasonOf({
      ...ON,
      DFIR_JEV_PROVIDER: "typesafe",
      DFIR_AI_VELO_KEY: "velo",
      DFIR_AI_SYNTH_KEY: "synth",
      DFIR_VISION_KEY: "vision",
      DFIR_AI_KEY: "legacy",
    });
    expect(reason).toMatch(/DFIR_JEV_KEY/);
    expect(reason).toMatch(/typesafe/i);
  });

  it("never sends an inherited OpenRouter key to api.typesafe.ai, even via a base-URL override", () => {
    const reason = reasonOf({
      ...ON,
      DFIR_JEV_PROVIDER: "openrouter",
      DFIR_JEV_BASE_URL: "https://api.typesafe.ai/v1/systemone",
      DFIR_AI_KEY: "an-openrouter-key",
    });
    expect(reason).toMatch(/api\.typesafe\.ai/);
    expect(reason).toMatch(/DFIR_JEV_KEY/);
  });

  it("allows an OWN key at a non-OpenRouter host — only inheritance is guarded", () => {
    const s = settingsOf({
      ...ON,
      DFIR_JEV_BASE_URL: "https://api.typesafe.ai/v1/systemone",
      DFIR_JEV_KEY: "own",
    });
    expect(s.apiKey).toBe("own");
  });
});

describe("resolveJevSettings — numeric defaults and clamps", () => {
  const base = { ...ON, DFIR_JEV_KEY: "k" };

  it("defaults the timeout, row cap and batch size", () => {
    const s = settingsOf(base);
    expect(s.timeoutMs).toBe(120_000);
    expect(s.maxRows).toBe(2000);
    expect(s.batchSize).toBe(40);
  });

  it("clamps maxRows to 1..20000", () => {
    expect(settingsOf({ ...base, DFIR_JEV_MAX_ROWS: "0" }).maxRows).toBe(1);
    expect(settingsOf({ ...base, DFIR_JEV_MAX_ROWS: "-5" }).maxRows).toBe(1);
    expect(settingsOf({ ...base, DFIR_JEV_MAX_ROWS: "1" }).maxRows).toBe(1);
    expect(settingsOf({ ...base, DFIR_JEV_MAX_ROWS: "20000" }).maxRows).toBe(20000);
    expect(settingsOf({ ...base, DFIR_JEV_MAX_ROWS: "20001" }).maxRows).toBe(20000);
    expect(settingsOf({ ...base, DFIR_JEV_MAX_ROWS: "abc" }).maxRows).toBe(2000);
  });

  it("clamps batchSize to 1..100", () => {
    expect(settingsOf({ ...base, DFIR_JEV_BATCH_SIZE: "0" }).batchSize).toBe(1);
    expect(settingsOf({ ...base, DFIR_JEV_BATCH_SIZE: "1" }).batchSize).toBe(1);
    expect(settingsOf({ ...base, DFIR_JEV_BATCH_SIZE: "100" }).batchSize).toBe(100);
    expect(settingsOf({ ...base, DFIR_JEV_BATCH_SIZE: "101" }).batchSize).toBe(100);
    expect(settingsOf({ ...base, DFIR_JEV_BATCH_SIZE: "" }).batchSize).toBe(40);
  });

  it("falls back to the default timeout for a non-positive or unreadable value", () => {
    expect(settingsOf({ ...base, DFIR_JEV_TIMEOUT_MS: "0" }).timeoutMs).toBe(120_000);
    expect(settingsOf({ ...base, DFIR_JEV_TIMEOUT_MS: "nope" }).timeoutMs).toBe(120_000);
    expect(settingsOf({ ...base, DFIR_JEV_TIMEOUT_MS: "30000" }).timeoutMs).toBe(30_000);
  });

  it("reads process.env when no env is passed", () => {
    // No DFIR_JEV_ENABLED in the test process → the disabled branch, not a crash.
    expect(resolveJevSettings().settings).toBeNull();
  });
});
