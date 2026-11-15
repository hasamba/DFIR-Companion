import { describe, it, expect } from "vitest";
import {
  AI_ROLE_SOURCES,
  providerEnv,
  resolveAiRoleSetting,
  PROVIDER_ENV_NAMES,
  resolveRoleSetting,
  visionEnv,
  withVisionEnvAliases,
  VISION_ENV_SUFFIXES,
} from "../../src/config/aiEnv.js";
import { buildAiDiagnostics } from "../../src/analysis/diagnostics.js";

// The screenshot/vision provider config was renamed DFIR_AI_* → DFIR_VISION_* with the legacy names
// kept as a deprecated fallback (new name wins). These guard that contract end-to-end.

describe("visionEnv (DFIR_VISION_* with legacy DFIR_AI_* fallback)", () => {
  it("prefers the new DFIR_VISION_* name when both are set", () => {
    const env = { DFIR_VISION_MODEL: "new", DFIR_AI_MODEL: "old" };
    expect(visionEnv(env, "MODEL")).toBe("new");
  });

  it("falls back to the legacy DFIR_AI_* name when the new one is unset", () => {
    expect(visionEnv({ DFIR_AI_PROVIDER: "openai" }, "PROVIDER")).toBe("openai");
    expect(visionEnv({ DFIR_AI_BASE_URL: "http://x" }, "BASE_URL")).toBe("http://x");
  });

  it("is undefined when neither name is set", () => {
    expect(visionEnv({}, "KEY")).toBeUndefined();
  });

  it("covers the whole vision family", () => {
    expect(VISION_ENV_SUFFIXES).toEqual(["PROVIDER", "MODEL", "KEY", "BASE_URL", "IMAGE_DETAIL"]);
  });
});

describe("withVisionEnvAliases (Settings-form migration display)", () => {
  it("surfaces a legacy value under the new key when the new key is absent", () => {
    const out = withVisionEnvAliases({ DFIR_AI_MODEL: "gpt-4o-mini" });
    expect(out.DFIR_VISION_MODEL).toBe("gpt-4o-mini");
    expect(out.DFIR_AI_MODEL).toBe("gpt-4o-mini"); // legacy key left in place, nothing hidden
  });

  it("keeps the new value when both are present (new wins)", () => {
    const out = withVisionEnvAliases({ DFIR_VISION_MODEL: "new", DFIR_AI_MODEL: "old" });
    expect(out.DFIR_VISION_MODEL).toBe("new");
  });

  it("does not invent keys when neither is set", () => {
    expect("DFIR_VISION_KEY" in withVisionEnvAliases({})).toBe(false);
  });
});

describe("buildAiDiagnostics honors the rename", () => {
  it("reads the new DFIR_VISION_* names", () => {
    const d = buildAiDiagnostics({ DFIR_VISION_PROVIDER: "openai", DFIR_VISION_MODEL: "gpt-4o-mini" });
    expect(d.configured).toBe(true);
    expect(d.provider).toBe("openai");
    expect(d.model).toBe("gpt-4o-mini");
  });

  it("still reads legacy DFIR_AI_* names (fallback)", () => {
    const d = buildAiDiagnostics({ DFIR_AI_PROVIDER: "anthropic", DFIR_AI_MODEL: "claude" });
    expect(d.configured).toBe(true);
    expect(d.provider).toBe("anthropic");
    expect(d.model).toBe("claude");
  });

  it("prefers the new name when both are set", () => {
    const d = buildAiDiagnostics({
      DFIR_VISION_MODEL: "new",
      DFIR_AI_MODEL: "old",
      DFIR_VISION_PROVIDER: "openai",
    });
    expect(d.model).toBe("new");
  });
});

// One saved key and base URL per provider: switching a role's provider must not send the old
// provider's key or URL.
describe("resolveRoleSetting — per-provider keys and base URLs", () => {
  it("uses the role's own value first", () => {
    const env = { DFIR_AI_KEY_GEMINI: "gemini-key" };
    expect(resolveRoleSetting(env, "gemini", "KEY", "role-key")).toBe("role-key");
  });

  it("uses the provider value when the role value is unset, before the vision value", () => {
    const env = {
      DFIR_AI_KEY_GEMINI: "gemini-key",
      DFIR_VISION_KEY: "openrouter-key",
      DFIR_AI_BASE_URL_LITELLM: "http://proxy.example.com/v1",
      DFIR_VISION_BASE_URL: "https://openrouter.ai/api/v1",
    };
    expect(resolveRoleSetting(env, "gemini", "KEY", undefined)).toBe("gemini-key");
    expect(resolveRoleSetting(env, " Gemini ", "KEY", undefined)).toBe("gemini-key");
    expect(resolveRoleSetting(env, "litellm", "BASE_URL", undefined)).toBe("http://proxy.example.com/v1");
  });

  it("treats a blank role value as unset when a provider value exists", () => {
    const env = { DFIR_AI_KEY_OPENROUTER: "or-key", DFIR_AI_BASE_URL_OPENROUTER: "https://or.example.com" };
    expect(resolveRoleSetting(env, "openrouter", "KEY", "  ")).toBe("or-key");
    expect(resolveRoleSetting(env, "openrouter", "BASE_URL", "")).toBe("https://or.example.com");
  });

  it("keeps the old role ?? vision result when the provider has no saved value", () => {
    const env = { DFIR_VISION_KEY: "vision-key", DFIR_AI_KEY_GEMINI: "" };
    expect(resolveRoleSetting(env, "gemini", "KEY", undefined)).toBe("vision-key");
    expect(resolveRoleSetting(env, "gemini", "KEY", "")).toBe("");
    expect(resolveRoleSetting({ DFIR_AI_KEY: "legacy" }, "openai", "KEY", undefined)).toBe("legacy");
    expect(resolveRoleSetting({ DFIR_AI_BASE_URL: "http://old" }, "gemini", "BASE_URL", undefined)).toBe(
      "http://old",
    );
  });

  it("gives CLI providers no provider value", () => {
    expect(providerEnv({ DFIR_AI_KEY_OPENAI: "k" }, "codex", "KEY")).toBeUndefined();
    expect(providerEnv({ DFIR_AI_KEY_OPENAI: "k" }, undefined, "KEY")).toBeUndefined();
  });

  it("names every API provider the model picker lists", () => {
    expect(Object.keys(PROVIDER_ENV_NAMES).sort()).toEqual([
      "anthropic",
      "gemini",
      "litellm",
      "ollama",
      "openai",
      "openrouter",
    ]);
  });
});

describe("the watson role (U2)", () => {
  it("runs on its own provider, or on the synthesis provider when blank", () => {
    const synth = { DFIR_VISION_PROVIDER: "gemini", DFIR_AI_SYNTH_PROVIDER: "openrouter" };
    expect(AI_ROLE_SOURCES.watson.provider(synth)).toBe("openrouter");
    expect(AI_ROLE_SOURCES.watson.provider({ ...synth, DFIR_AI_WATSON_PROVIDER: " " })).toBe("openrouter");
    expect(AI_ROLE_SOURCES.watson.provider({ DFIR_VISION_PROVIDER: "gemini" })).toBe("gemini");
    expect(AI_ROLE_SOURCES.watson.provider({ ...synth, DFIR_AI_WATSON_PROVIDER: "anthropic" })).toBe(
      "anthropic",
    );
    expect(AI_ROLE_SOURCES.watson.ownNames("KEY")).toEqual(["DFIR_AI_WATSON_KEY"]);
  });

  it("sends the synthesis key when its provider and key are blank, its own key otherwise", () => {
    const env = { DFIR_AI_SYNTH_PROVIDER: "openai", DFIR_AI_SYNTH_KEY: "s", DFIR_AI_KEY_OPENAI: "slot" };
    expect(resolveAiRoleSetting(env, "watson", "KEY")).toBe("s");
    expect(resolveAiRoleSetting({ ...env, DFIR_AI_WATSON_KEY: "w" }, "watson", "KEY")).toBe("w");
  });
});
