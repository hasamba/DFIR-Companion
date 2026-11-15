import { describe, expect, it } from "vitest";
import { buildAiDiagnostics } from "../../src/analysis/diagnostics.js";
import { watsonDiagnosticsLine } from "../../src/analysis/watsonDiagnostics.js";

// U2: Watson may run on its own provider. The Diagnostics AI view must name it, and "local" must not
// claim that nothing leaves the machine while Watson talks to a cloud provider.

// Local by provider name, with no base URL: a vision base URL would also become Watson's fallback.
const LOCAL = { DFIR_VISION_PROVIDER: "ollama", DFIR_VISION_MODEL: "llava" };

describe("Diagnostics AI view with Watson's own provider", () => {
  it("is not local when Watson uses a cloud provider while the rest is local", () => {
    const ai = buildAiDiagnostics({
      ...LOCAL,
      DFIR_AI_WATSON_PROVIDER: "Anthropic ",
      DFIR_AI_WATSON_MODEL: "claude-sonnet-5",
    });
    expect(ai.local).toBe(false);
    expect(ai.watson).toEqual({ provider: "anthropic", model: "claude-sonnet-5", local: false });
  });

  it("stays local when Watson uses the synthesis connection, and names no separate Watson", () => {
    const ai = buildAiDiagnostics({ ...LOCAL, DFIR_AI_WATSON_MODEL: "llama3" });
    expect(ai.local).toBe(true);
    expect(ai.watson).toBeNull();
  });

  it("stays local when Watson's own provider is local too", () => {
    const ai = buildAiDiagnostics({
      ...LOCAL,
      DFIR_AI_WATSON_PROVIDER: "litellm",
      DFIR_AI_WATSON_BASE_URL: "http://localhost:4000",
      DFIR_AI_WATSON_MODEL: "m",
    });
    expect(ai.local).toBe(true);
    expect(ai.watson).toEqual({ provider: "litellm", model: "m", local: true });
  });

  it("shows no Watson model when Watson is off (another provider, no model)", () => {
    const ai = buildAiDiagnostics({ ...LOCAL, DFIR_AI_WATSON_PROVIDER: "anthropic" });
    expect(ai.watson).toEqual({ provider: "anthropic", model: null, local: false });
  });

  it("never carries the Watson key", () => {
    const ai = buildAiDiagnostics({
      ...LOCAL,
      DFIR_AI_WATSON_PROVIDER: "anthropic",
      DFIR_AI_WATSON_KEY: "sk-watson-secret",
      DFIR_AI_WATSON_MODEL: "claude-sonnet-5",
    });
    expect(JSON.stringify(ai)).not.toContain("sk-watson-secret");
  });
});

describe("Diagnostics text", () => {
  it("prints a Watson line when Watson has its own provider", () => {
    const ai = buildAiDiagnostics({
      ...LOCAL,
      DFIR_AI_WATSON_PROVIDER: "anthropic",
      DFIR_AI_WATSON_MODEL: "claude-sonnet-5",
    });
    expect(watsonDiagnosticsLine(ai.watson!)).toBe("  watson:   anthropic / claude-sonnet-5 (external)");
    expect(watsonDiagnosticsLine({ provider: "anthropic", model: null, local: false })).toBe(
      "  watson:   anthropic / no model configured (external)",
    );
  });
});

describe("Diagnostics dashboard view", () => {
  it("shows a Watson row with the provider, the model and local or external", async () => {
    const { readFile } = await import("node:fs/promises");
    // Windows checkouts use CRLF; the check below expects LF.
    const js = (
      await readFile(new URL("../../../public/js/dashboard-diagnostics.js", import.meta.url), "utf8")
    ).replace(/\r\n/g, "\n");
    expect(js).toContain('diagRow(\n              "Watson",');
    expect(js).toContain("esc(ai.watson.provider)");
    expect(js).toContain('esc(ai.watson.model || "no model configured")');
  });
});
