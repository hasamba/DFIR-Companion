import { describe, it, expect } from "vitest";
import { buildProviderFrom } from "../../src/server.js";
import { isLocalAiProvider } from "../../src/analysis/anonymize.js";

describe("buildProviderFrom — codex wiring", () => {
  it("resolves the codex provider by name with no API key", () => {
    const p = buildProviderFrom({ provider: "codex", model: "gpt-5-codex" });
    expect(p?.name).toBe("codex");
    expect(p?.model).toBe("gpt-5-codex");
  });

  it("treats codex as NON-local (evidence leaves the machine to OpenAI)", () => {
    expect(isLocalAiProvider("codex", undefined)).toBe(false);
  });
});
