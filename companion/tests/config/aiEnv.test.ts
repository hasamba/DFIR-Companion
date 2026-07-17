import { describe, it, expect } from "vitest";
import { visionEnv, withVisionEnvAliases, VISION_ENV_SUFFIXES } from "../../src/config/aiEnv.js";
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
    const d = buildAiDiagnostics({ DFIR_VISION_MODEL: "new", DFIR_AI_MODEL: "old", DFIR_VISION_PROVIDER: "openai" });
    expect(d.model).toBe("new");
  });
});
