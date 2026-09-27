import { describe, it, expect } from "vitest";
import { synthesisFallbackConfig } from "../../src/composition/aiProviders.js";

// #1734: the fallback synthesis model is opt-in and never the synthesis model itself.
describe("synthesisFallbackConfig (#1734)", () => {
  const base = {
    DFIR_AI_SYNTH_PROVIDER: "claude-code",
    DFIR_AI_SYNTH_MODEL: "opus",
    DFIR_AI_SYNTH_KEY: "synth-key",
  };

  it("is off when no fallback model is set, or it is blank", () => {
    expect(synthesisFallbackConfig(base)).toBeUndefined();
    expect(synthesisFallbackConfig({ ...base, DFIR_AI_SYNTH_FALLBACK_MODEL: "   " })).toBeUndefined();
  });

  it("uses its own provider and model", () => {
    expect(
      synthesisFallbackConfig({
        ...base,
        DFIR_AI_SYNTH_FALLBACK_PROVIDER: "codex",
        DFIR_AI_SYNTH_FALLBACK_MODEL: "gpt-6-sol",
      }),
    ).toMatchObject({ provider: "codex", model: "gpt-6-sol", label: "gpt-6-sol" });
  });

  it("inherits the synthesis provider and the synthesis key when its own are blank", () => {
    expect(
      synthesisFallbackConfig({
        DFIR_AI_SYNTH_PROVIDER: "openrouter",
        DFIR_AI_SYNTH_MODEL: "anthropic/claude-opus-5.5",
        DFIR_AI_SYNTH_KEY: "synth-key",
        DFIR_AI_SYNTH_FALLBACK_PROVIDER: " ",
        DFIR_AI_SYNTH_FALLBACK_MODEL: "openai/gpt-6-sol",
      }),
    ).toMatchObject({ provider: "openrouter", model: "openai/gpt-6-sol", apiKey: "synth-key" });
  });

  it("prefers its own key and base URL", () => {
    expect(
      synthesisFallbackConfig({
        ...base,
        DFIR_AI_SYNTH_FALLBACK_PROVIDER: "openrouter",
        DFIR_AI_SYNTH_FALLBACK_MODEL: "openai/gpt-6-sol",
        DFIR_AI_SYNTH_FALLBACK_KEY: "fb-key",
        DFIR_AI_SYNTH_FALLBACK_BASE_URL: "https://example.com/v1",
      }),
    ).toMatchObject({ apiKey: "fb-key", baseUrl: "https://example.com/v1" });
  });

  it("is off when it names the synthesis model itself", () => {
    expect(synthesisFallbackConfig({ ...base, DFIR_AI_SYNTH_FALLBACK_MODEL: "opus" })).toBeUndefined();
    expect(
      synthesisFallbackConfig({
        ...base,
        DFIR_AI_SYNTH_FALLBACK_PROVIDER: "claude-code",
        DFIR_AI_SYNTH_FALLBACK_MODEL: "opus",
      }),
    ).toBeUndefined();
  });

  it("follows blank provider fields to the provider synthesis really runs on", () => {
    const env = {
      DFIR_VISION_PROVIDER: "openrouter",
      DFIR_VISION_MODEL: "anthropic/claude-opus-5.5",
      DFIR_AI_SYNTH_PROVIDER: "",
      DFIR_AI_SYNTH_FALLBACK_PROVIDER: "",
    };
    expect(
      synthesisFallbackConfig({ ...env, DFIR_AI_SYNTH_FALLBACK_MODEL: "openai/gpt-6-sol" }),
    ).toMatchObject({
      provider: "openrouter",
      model: "openai/gpt-6-sol",
    });
    expect(
      synthesisFallbackConfig({ ...env, DFIR_AI_SYNTH_FALLBACK_MODEL: "anthropic/claude-opus-5.5" }),
    ).toBeUndefined();
  });
});
