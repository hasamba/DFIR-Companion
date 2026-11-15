import { describe, expect, it } from "vitest";
import { buildSynthesisProvider } from "../../src/composition/aiProviders.js";
import { buildWatsonProvider } from "../../src/composition/watsonProvider.js";
import { AI_ROLE_SOURCES, resolveAiRoleSetting } from "../../src/config/aiEnv.js";

// Watson may run on its own provider, key and base URL (user decision U2). Blank provider = today's
// behaviour: the synthesis connection with the Watson model override. A different provider needs its
// own model: Watson never guesses one.

describe("buildWatsonProvider — its own provider (U2)", () => {
  it("blank Watson provider: identical to the synthesis provider with the Watson model override", () => {
    const env = {
      DFIR_AI_SYNTH_PROVIDER: "claude-code",
      DFIR_AI_SYNTH_MODEL: "opus",
      DFIR_AI_WATSON_MODEL: "sonnet",
    };
    const w = buildWatsonProvider(env)!;
    expect([w.name, w.model]).toEqual(["claude-code", "sonnet"]);
    const s = buildSynthesisProvider(env, "sonnet")!;
    expect([w.name, w.model]).toEqual([s.name, s.model]);
  });

  it("blank Watson provider and model: the synthesis provider exactly as synthesis builds it", () => {
    const env = { DFIR_AI_SYNTH_PROVIDER: "openrouter", DFIR_AI_SYNTH_MODEL: "x/y", DFIR_AI_SYNTH_KEY: "k" };
    const w = buildWatsonProvider(env)!;
    expect([w.name, w.model]).toEqual(["openrouter", "x/y"]);
  });

  it("Watson on the Anthropic API while synthesis is on Claude Code", () => {
    const env = {
      DFIR_AI_SYNTH_PROVIDER: "claude-code",
      DFIR_AI_WATSON_PROVIDER: "anthropic",
      DFIR_AI_WATSON_MODEL: "claude-sonnet-5",
      DFIR_AI_WATSON_KEY: "k-w",
    };
    const w = buildWatsonProvider(env)!;
    expect([w.name, w.model]).toEqual(["anthropic", "claude-sonnet-5"]);
    expect(resolveAiRoleSetting(env, "watson", "KEY")).toBe("k-w");
  });

  it("a set provider uses its own saved key when DFIR_AI_WATSON_KEY is blank (resolveAiRoleSetting)", () => {
    const env = {
      DFIR_AI_SYNTH_PROVIDER: "openrouter",
      DFIR_AI_SYNTH_KEY: "k-synth",
      DFIR_AI_WATSON_PROVIDER: "anthropic",
      DFIR_AI_WATSON_MODEL: "claude-sonnet-5",
      DFIR_AI_WATSON_KEY: "",
      DFIR_AI_KEY_ANTHROPIC: "k-anthropic",
      DFIR_AI_BASE_URL_ANTHROPIC: "https://anthropic.example",
    };
    expect(resolveAiRoleSetting(env, "watson", "KEY")).toBe("k-anthropic");
    expect(resolveAiRoleSetting(env, "watson", "BASE_URL")).toBe("https://anthropic.example");
  });

  it("blank provider + blank Watson key/base URL resolve to the synthesis key/base URL", () => {
    const env = {
      DFIR_VISION_PROVIDER: "gemini",
      DFIR_VISION_KEY: "k-vision",
      DFIR_AI_SYNTH_PROVIDER: "openrouter",
      DFIR_AI_SYNTH_KEY: "k-synth",
      DFIR_AI_SYNTH_BASE_URL: "https://synth.example",
      DFIR_AI_WATSON_PROVIDER: "",
      DFIR_AI_WATSON_KEY: "",
      DFIR_AI_WATSON_BASE_URL: "",
    };
    expect(resolveAiRoleSetting(env, "watson", "KEY")).toBe("k-synth");
    expect(resolveAiRoleSetting(env, "watson", "BASE_URL")).toBe("https://synth.example");
  });

  it("a different provider with a blank Watson model builds no provider (no guessed model)", () => {
    expect(
      buildWatsonProvider({ DFIR_AI_SYNTH_PROVIDER: "claude-code", DFIR_AI_WATSON_PROVIDER: "anthropic" }),
    ).toBeUndefined();
    expect(
      buildWatsonProvider({
        DFIR_AI_SYNTH_PROVIDER: "claude-code",
        DFIR_AI_SYNTH_MODEL: "opus",
        DFIR_AI_WATSON_PROVIDER: "anthropic",
        DFIR_AI_WATSON_MODEL: "  ",
      }),
    ).toBeUndefined();
  });

  it("the same provider as synthesis with a blank Watson model uses the synthesis model", () => {
    const env = {
      DFIR_AI_SYNTH_PROVIDER: "openrouter",
      DFIR_AI_SYNTH_MODEL: "x/y",
      DFIR_AI_WATSON_PROVIDER: "openrouter",
    };
    const w = buildWatsonProvider(env)!;
    expect([w.name, w.model]).toEqual(["openrouter", "x/y"]);
  });

  it("reads the Watson provider name in any case, with spaces trimmed", () => {
    const env = {
      DFIR_AI_SYNTH_PROVIDER: "claude-code",
      DFIR_AI_WATSON_PROVIDER: " Anthropic ",
      DFIR_AI_WATSON_MODEL: "m",
    };
    expect(AI_ROLE_SOURCES.watson.provider(env)).toBe("anthropic");
    expect(buildWatsonProvider(env)!.name).toBe("anthropic");
  });

  it("builds nothing when no provider is configured at all", () => {
    expect(buildWatsonProvider({})).toBeUndefined();
  });
});
