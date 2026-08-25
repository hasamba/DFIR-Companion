import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";

// The setup wizard's AI step is the ONLY place a first-run analyst configures a provider, and it
// had drifted away from Settings → AI in four ways at once: its rows misaligned whenever a hint
// wrapped, its vision block had no heading (so the bare "Provider" select read as a global one and
// the separate synthesis provider below looked like the only choice), and both model fields were
// free text while Settings offered a live model list. Each of those is a one-line regression in a
// large HTML file, so they are pinned here rather than left to whoever opens the wizard next.

const dashboard = async (): Promise<string> =>
  readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");

/** The wizard's AI pane only — so a match cannot be satisfied by the Settings modal instead. */
async function aiPane(): Promise<string> {
  const html = await dashboard();
  const start = html.indexOf('<div id="wizPaneAi">');
  const end = html.indexOf('<div id="wizPaneDynamic"', start);
  expect(start, "wizard AI pane not found").toBeGreaterThan(-1);
  expect(end, "wizard dynamic pane not found").toBeGreaterThan(start);
  return html.slice(start, end);
}

describe("setup wizard, AI step", () => {
  it("heads the vision block, so its provider is not read as the page-wide one", async () => {
    const pane = await aiPane();
    const heads = [...pane.matchAll(/<div class="settings-group-head"[^>]*>([^<]*)/g)].map((m) =>
      m[1].trim(),
    );
    expect(heads).toContain("Vision model");
    expect(heads).toContain("Synthesis model");
    expect(pane).toMatch(/<label>Vision provider/);
    expect(pane).toMatch(/<label>Synth provider/);
  });

  it("lets the synthesis model use a provider of its own", async () => {
    const pane = await aiPane();
    const synth = pane.match(/<select id="wizSynthProvider">[\s\S]*?<\/select>/)?.[0] ?? "";
    const vision = pane.match(/<select id="wizProvider">[\s\S]*?<\/select>/)?.[0] ?? "";
    for (const provider of ["openai", "openrouter", "ollama", "litellm", "gemini", "anthropic"]) {
      expect(vision, `vision provider list is missing ${provider}`).toContain(`value="${provider}"`);
      expect(synth, `synth provider list is missing ${provider}`).toContain(`value="${provider}"`);
    }
    // Blank means "reuse the vision provider", so it must say which one it reuses.
    expect(synth).toMatch(/<option value="">— same as the vision provider —<\/option>/);
  });

  it("offers a model list beside each model field, as Settings → AI does", async () => {
    const pane = await aiPane();
    for (const [key, input] of [
      ["wizard-vision", "wizModel"],
      ["wizard-synthesis", "wizSynthModel"],
    ]) {
      expect(
        pane.match(
          new RegExp(
            `<div class="wiz-combo">\\s*<select id="ai-model-picker-${key}"[\\s\\S]*?</select>\\s*<input id="${input}"[\\s\\S]*?<button[^>]+id="load-ai-models-${key}"`,
          ),
        ),
        `${input} has no model picker beside it`,
      ).not.toBeNull();
      expect(pane, `${key} reports no load status`).toContain(`id="ai-model-status-${key}"`);
    }
  });

  it("drives those pickers with the Settings code rather than a second copy", async () => {
    const js = await readFile(
      new URL("../../../public/js/dashboard-wizard-ai-step.js", import.meta.url),
      "utf8",
    );
    expect(js).toContain("wireAiModelPicker");
    // The server's role enum has one "vision" and one "synthesis"; the element ids must NOT, or
    // the wizard picker and the Settings picker of the same role share one <select>.
    expect(js).toContain('elementKey: "wizard-vision"');
    expect(js).toContain('elementKey: "wizard-synthesis"');
    for (const role of ['role: "vision"', 'role: "synthesis"']) expect(js).toContain(role);
    // Its synthesis picker borrows the WIZARD's vision fields, never the Settings modal's.
    expect(js).toContain('fallbackProviderId: "wizProvider"');
    expect(js).not.toContain("env-DFIR_VISION_PROVIDER");
  });

  it("aligns each row's labels, inputs and hints on shared row tracks", async () => {
    const css = await readFile(new URL("../../../public/css/dashboard-panels.css", import.meta.url), "utf8");
    const row = css.match(/^\.wiz-row \{[^}]*\}/m)?.[0] ?? "";
    const field = css.match(/^\.wiz-row > \.wiz-field \{[^}]*\}/m)?.[0] ?? "";
    expect(row, ".wiz-row must be a grid, not a flex row").toContain("display: grid");
    expect(field, ".wiz-field must share the row's tracks").toContain("grid-template-rows: subgrid");
    expect(field).toContain("grid-row: span 3");
  });
});
