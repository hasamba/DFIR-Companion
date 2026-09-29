import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runInNewContext } from "node:vm";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { PROVIDER_ENV_NAMES, resolveAiRoleSetting } from "../../src/config/aiEnv.js";
import { planAiKeyMigration } from "../../src/config/aiKeyMigration.js";
import { parse as parseLines } from "dotenv";
import { reloadEnvPrefix, updateEnv } from "../../src/settings/envManager.js";

// #1870: the setup wizard saved every key as a per-model override (DFIR_VISION_KEY,
// DFIR_AI_SYNTH_KEY). Since #1720 the provider slots are the normal home and a per-model value is an
// override, so a fresh wizard run produced exactly the layout Settings → AI then asked the analyst
// to "Move". The wizard now writes the slot and clears the override it would otherwise leave behind.

const read = (f: string) => readFile(new URL(`../../../public/js/${f}`, import.meta.url), "utf8");

type Body = { updates: Record<string, string>; unset?: string[] };
type El = Record<string, unknown> & { value?: string };

async function wizard(opts: { saveOk?: boolean } = {}) {
  const src = await read("dashboard-wizard-ai-step.js");
  const els: Record<string, El> = {};
  for (const id of [
    "wizProvider",
    "wizModel",
    "wizKey",
    "wizBaseUrl",
    "wizSynthProvider",
    "wizSynthModel",
    "wizSynthKey",
    "wizSynthBaseUrl",
  ])
    els[id] = { value: "", addEventListener: () => {}, dispatchEvent: () => {} };
  for (const id of ["wizResult", "wizSynthResult", "wizModelHint"])
    els[id] = { style: {}, textContent: "", innerHTML: "" };
  for (const id of ["wizTestSaveBtn", "wizSynthSaveBtn"]) els[id] = { disabled: false };
  els.wizBaseUrlField = { style: {} };
  const saves: Body[] = [];
  const win: Record<string, unknown> = {};
  const sandbox = {
    window: win,
    Event: class {
      constructor(readonly type: string) {}
    },
    wizEl: (id: string) => els[id] ?? null,
    wizRefreshStatus: async () => {},
    esc: (s: unknown) => String(s),
    escAttr: (s: unknown) => String(s),
    fetch: async (url: string, init?: { body?: string }) => {
      if (url === "/settings/env") {
        saves.push(JSON.parse(init?.body ?? "{}") as Body);
        return { ok: opts.saveOk ?? true, status: 500, json: async () => ({}) };
      }
      return { ok: true, status: 200, json: async () => ({ ok: true, provider: "x", latencyMs: 1 }) };
    },
  };
  runInNewContext(src, sandbox);
  (win.initWizardAiStep as () => void)();
  const saveVision = async (provider: string, key: string, baseUrl = "") => {
    els.wizProvider.value = provider;
    els.wizModel.value = "some-model";
    els.wizKey.value = key;
    els.wizBaseUrl.value = baseUrl;
    await (els.wizTestSaveBtn.onclick as () => Promise<void>)();
    return saves[saves.length - 1];
  };
  const synth = (provider: string, key: string, baseUrl = "") =>
    (win.wizAiSynthUpdates as (p: string, k: string, b: string) => Body)(provider, key, baseUrl);
  const reset = () => (win.wizResetAiStep as () => void)();
  return { saveVision, synth, reset, saves };
}

describe("setup wizard saves provider keys (#1870)", () => {
  it("writes every key-based provider's key and base URL into that provider's slot", async () => {
    const w = await wizard();
    for (const [provider, slot] of Object.entries(PROVIDER_ENV_NAMES)) {
      const body = await w.saveVision(provider, "k-" + provider, "http://proxy.example.com/v1");
      expect(body.updates).toEqual({
        DFIR_VISION_PROVIDER: provider,
        DFIR_VISION_MODEL: "some-model",
        [`DFIR_AI_KEY_${slot}`]: "k-" + provider,
        [`DFIR_AI_BASE_URL_${slot}`]: "http://proxy.example.com/v1",
      });
      expect(body.unset).toEqual(["DFIR_VISION_KEY", "DFIR_VISION_BASE_URL"]);
    }
  });

  it("clears a stale override on a rerun even when the field is left blank", async () => {
    const w = await wizard();
    // A local provider with no key, after an earlier run saved an OpenAI key and a proxy URL.
    const body = await w.saveVision("ollama", "", "");
    expect(body.updates).toEqual({ DFIR_VISION_PROVIDER: "ollama", DFIR_VISION_MODEL: "some-model" });
    expect(body.unset).toEqual(["DFIR_VISION_KEY", "DFIR_VISION_BASE_URL"]);
    const lite = await w.saveVision("litellm", "", "http://localhost:4000");
    expect(lite.updates.DFIR_AI_BASE_URL_LITELLM).toBe("http://localhost:4000");
  });

  it("keeps the per-model names for a CLI provider, which has no provider slot", async () => {
    const w = await wizard();
    const body = await w.saveVision("claude-code", "");
    expect(body.updates).toEqual({ DFIR_VISION_PROVIDER: "claude-code", DFIR_VISION_MODEL: "some-model" });
    expect(body.unset ?? []).toEqual([]);
  });

  describe("synthesis", () => {
    it("before any vision save: per-model override, exactly as before", async () => {
      const w = await wizard();
      expect(w.synth("openai", "s-key", "")).toEqual({
        updates: { DFIR_AI_SYNTH_KEY: "s-key" },
        unset: [],
      });
    });

    it("after a FAILED vision save: still the per-model override", async () => {
      const w = await wizard({ saveOk: false });
      await w.saveVision("openai", "v-key");
      expect(w.synth("", "s-key", "")).toEqual({ updates: { DFIR_AI_SYNTH_KEY: "s-key" }, unset: [] });
    });

    it("same provider, same key: the slot, and no synthesis override left", async () => {
      const w = await wizard();
      await w.saveVision("openai", "v-key");
      for (const provider of ["", "openai"]) {
        expect(w.synth(provider, "v-key", "")).toEqual({
          updates: { DFIR_AI_KEY_OPENAI: "v-key" },
          unset: ["DFIR_AI_SYNTH_KEY"],
        });
      }
    });

    it("same provider, a different key: that key stays a synthesis-only override", async () => {
      const w = await wizard();
      await w.saveVision("openai", "v-key");
      expect(w.synth("openai", "other-key", "")).toEqual({
        updates: { DFIR_AI_SYNTH_KEY: "other-key" },
        unset: [],
      });
    });

    it("a different provider: that provider's slot", async () => {
      const w = await wizard();
      await w.saveVision("openai", "v-key");
      expect(w.synth("anthropic", "a-key", "")).toEqual({
        updates: { DFIR_AI_KEY_ANTHROPIC: "a-key" },
        unset: ["DFIR_AI_SYNTH_KEY"],
      });
    });

    it("blank key and base URL keep a saved synthesis override (a model-only rerun)", async () => {
      const w = await wizard();
      await w.saveVision("openai", "v-key");
      for (const provider of ["", "openai", "anthropic"])
        expect(w.synth(provider, "", "")).toEqual({ updates: {}, unset: [] });
    });

    it("a CLI provider: no slot, per-model names", async () => {
      const w = await wizard();
      await w.saveVision("openai", "v-key");
      expect(w.synth("codex", "", "")).toEqual({ updates: {}, unset: [] });
    });

    it("forgets the saved vision values when the wizard is reset", async () => {
      const w = await wizard();
      await w.saveVision("openai", "v-key");
      w.reset();
      expect(w.synth("openai", "v-key", "")).toEqual({ updates: { DFIR_AI_SYNTH_KEY: "v-key" }, unset: [] });
    });
  });

  it("the synthesis save sends the helper's writes and its unset list", async () => {
    const src = await read("dashboard-setup-wizard.js");
    const fn = src.slice(src.indexOf("async function wizSaveSynth"), src.indexOf("function wizRenderStep"));
    expect(fn).toContain("wizAiSynthUpdates(");
    expect(fn).toMatch(/JSON\.stringify\(\{ updates, unset \}\)/);
    expect(fn).not.toContain('prefix: "DFIR_AI_SYNTH_"');
    // The running synthesis provider is built at startup, so a save is not live (#1870 review).
    expect(fn).not.toContain("Used on the next synthesis run");
  });
});

describe("a fresh wizard run through the real .env writer (#1870)", () => {
  let dir = "";
  const saved: Record<string, string | undefined> = {};
  const touched = [
    "DFIR_ENV_FILE",
    "DFIR_VISION_PROVIDER",
    "DFIR_VISION_MODEL",
    "DFIR_VISION_KEY",
    "DFIR_VISION_BASE_URL",
    "DFIR_AI_KEY",
    "DFIR_AI_KEY_OPENAI",
    "DFIR_AI_PROVIDER",
    "DFIR_AI_SYNTH_KEY",
    "DFIR_AI_SYNTH_PROVIDER",
  ];

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "wiz-1870-"));
    for (const k of touched) saved[k] = process.env[k];
    for (const k of touched) delete process.env[k];
    process.env.DFIR_ENV_FILE = join(dir, ".env");
  });
  afterEach(async () => {
    for (const k of touched) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
    await rm(dir, { recursive: true, force: true });
  });

  it("leaves the provider key, no per-model key, and nothing to migrate", async () => {
    // A rerun over an old wizard's layout, legacy alias included.
    await writeFile(
      process.env.DFIR_ENV_FILE as string,
      "DFIR_VISION_PROVIDER=openrouter\nDFIR_VISION_KEY=old-key\nDFIR_AI_KEY=older-key\n",
    );
    const w = await wizard();
    const body = await w.saveVision("openai", "sk-new");
    await updateEnv(body.updates, body.unset ?? []);
    await reloadEnvPrefix("DFIR_VISION_");
    await reloadEnvPrefix("DFIR_AI_");

    const file = parseLines(await readFile(process.env.DFIR_ENV_FILE as string, "utf8"));
    expect(file.DFIR_AI_KEY_OPENAI).toBe("sk-new");
    expect(file).not.toHaveProperty("DFIR_VISION_KEY");
    expect(file).not.toHaveProperty("DFIR_AI_KEY");
    expect(resolveAiRoleSetting(process.env, "vision", "KEY")).toBe("sk-new");
    expect(resolveAiRoleSetting(process.env, "synthesis", "KEY")).toBe("sk-new");
    expect(planAiKeyMigration(file).moves).toEqual([]);
  });
});
