import { describe, it, expect } from "vitest";
import { buildProviderFrom } from "../../src/server.js";
import { isLocalAiProvider } from "../../src/analysis/anonymize.js";

describe("buildProviderFrom — claude-code wiring", () => {
  it("resolves the claude-code provider by name with no API key", () => {
    const p = buildProviderFrom({ provider: "claude-code", model: "haiku" });
    expect(p?.name).toBe("claude-code");
    expect(p?.model).toBe("haiku");
  });

  it("treats claude-code as NON-local (evidence leaves the machine to Anthropic)", () => {
    // Anonymization must still apply, exactly as for the hosted `anthropic` provider.
    expect(isLocalAiProvider("claude-code", undefined)).toBe(false);
  });
});
