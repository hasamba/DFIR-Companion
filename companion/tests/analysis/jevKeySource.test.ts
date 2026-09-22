import { describe, it, expect } from "vitest";
import { describeJevKeySource, JEV_KEY_INHERIT_CHAIN } from "../../src/analysis/ai/jev/jevConfig.js";

// The settings screen used to promise an inheritance that may not exist: "the OpenRouter key you
// already configured for the other AI roles is used". On a setup whose vision and synthesis roles
// run on claude-code, none of those keys is set — that provider needs no key — so the analyst only
// found out after enabling the review and pressing the button. This is the answer, computed before
// they press anything, and it must never carry the key itself.

const blank: NodeJS.ProcessEnv = {};

describe("describeJevKeySource", () => {
  it("reports no inheritance when every fallback is unset", () => {
    expect(describeJevKeySource(blank)).toEqual({ ownKeySet: false, inheritable: false });
  });

  it("names the setting a key would be inherited from", () => {
    const r = describeJevKeySource({ DFIR_AI_SYNTH_KEY: "any-value" });
    expect(r.inheritable).toBe(true);
    expect(r.inheritedFrom).toBe("DFIR_AI_SYNTH_KEY");
  });

  it("follows the same precedence the provider factories use", () => {
    const all = {
      DFIR_AI_VELO_KEY: "a",
      DFIR_AI_SYNTH_KEY: "b",
      DFIR_VISION_KEY: "c",
      DFIR_AI_KEY: "d",
    };
    expect(describeJevKeySource(all).inheritedFrom).toBe("DFIR_AI_VELO_KEY");
    const { DFIR_AI_VELO_KEY: _v, ...rest } = all;
    expect(describeJevKeySource(rest).inheritedFrom).toBe("DFIR_AI_SYNTH_KEY");
  });

  it("treats a blank value as unset, and walks past it", () => {
    // aiProviders chains with ??, where a blank DFIR_VISION_KEY would shadow a real DFIR_AI_KEY.
    const r = describeJevKeySource({ DFIR_VISION_KEY: "   ", DFIR_AI_KEY: "real" });
    expect(r.inheritedFrom).toBe("DFIR_AI_KEY");
  });

  it("says when a key is set on the review itself", () => {
    const r = describeJevKeySource({ DFIR_JEV_KEY: "set-here" });
    expect(r.ownKeySet).toBe(true);
    expect(r.inheritable).toBe(false);
  });

  it("NEVER returns a key value, from any source", () => {
    const secret = "do-not-leak-this-value";
    const serialized = JSON.stringify(
      describeJevKeySource({
        DFIR_JEV_KEY: secret,
        DFIR_AI_VELO_KEY: secret,
        DFIR_AI_SYNTH_KEY: secret,
        DFIR_VISION_KEY: secret,
        DFIR_AI_KEY: secret,
      }),
    );
    expect(serialized).not.toContain(secret);
  });

  it("exposes the chain it walks, so the hint can name every setting that would do", () => {
    expect([...JEV_KEY_INHERIT_CHAIN]).toEqual([
      "DFIR_AI_VELO_KEY",
      "DFIR_AI_SYNTH_KEY",
      "DFIR_VISION_KEY",
      "DFIR_AI_KEY",
    ]);
  });
});
