import { describe, expect, it } from "vitest";
import { AI_ROLE_SOURCES, visionEnv, withVisionEnvAliases } from "../../src/config/aiEnv.js";

/**
 * A BLANK VALUE MEANS "NOT SET" (#1785).
 *
 * `KEY=` in .env loads as "", and "" passes a `??` fallback. For DFIR_VISION_IMAGE_DETAIL that
 * sent `detail: ""` to the vision API instead of the "high" default. For a role provider it built
 * no provider at all (buildProviderFrom refuses ""), so a blank second-opinion or synthesis
 * provider switched the role off instead of running it on the main provider.
 */
describe("visionEnv treats a blank value as unset", () => {
  it("returns undefined for a blank new name with no legacy value", () => {
    expect(visionEnv({ DFIR_VISION_IMAGE_DETAIL: "" }, "IMAGE_DETAIL")).toBeUndefined();
    expect(visionEnv({ DFIR_VISION_PROVIDER: "  " }, "PROVIDER")).toBeUndefined();
  });

  it("falls back to the legacy name when the new one is blank", () => {
    expect(visionEnv({ DFIR_VISION_PROVIDER: "", DFIR_AI_PROVIDER: "openai" }, "PROVIDER")).toBe("openai");
  });

  it("returns undefined when the legacy name is blank too", () => {
    expect(visionEnv({ DFIR_AI_IMAGE_DETAIL: "" }, "IMAGE_DETAIL")).toBeUndefined();
  });
});

describe("withVisionEnvAliases shows what runtime uses for a blank new name", () => {
  it("surfaces the legacy value under a blank new name", () => {
    expect(withVisionEnvAliases({ DFIR_VISION_MODEL: "", DFIR_AI_MODEL: "gpt" }).DFIR_VISION_MODEL).toBe(
      "gpt",
    );
  });
});

describe("role providers inherit on a blank value", () => {
  const env = { DFIR_VISION_PROVIDER: "openrouter" };

  it("second opinion runs on the main provider when its own is blank", () => {
    expect(AI_ROLE_SOURCES["second-opinion"].provider({ ...env, DFIR_AI_SECOND_OPINION_PROVIDER: "" })).toBe(
      "openrouter",
    );
  });

  it("synthesis runs on the main provider when its own is blank", () => {
    expect(AI_ROLE_SOURCES.synthesis.provider({ ...env, DFIR_AI_SYNTH_PROVIDER: " " })).toBe("openrouter");
  });

  it("the synthesis fallback follows a blank synthesis provider to the main provider", () => {
    expect(
      AI_ROLE_SOURCES["synthesis-fallback"].provider({
        ...env,
        DFIR_AI_SYNTH_PROVIDER: "",
        DFIR_AI_SYNTH_FALLBACK_PROVIDER: "",
      }),
    ).toBe("openrouter");
  });

  it("a named provider still wins", () => {
    expect(
      AI_ROLE_SOURCES["second-opinion"].provider({ ...env, DFIR_AI_SECOND_OPINION_PROVIDER: "gemini" }),
    ).toBe("gemini");
  });
});
