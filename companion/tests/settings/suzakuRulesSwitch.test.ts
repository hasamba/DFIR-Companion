import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

/**
 * #2509: the Suzaku rules setting is an on/off switch (the #2465 rule). The server reads it as ON
 * unless it says off / 0 / false / no, in any case and with any spacing (analysis/sigmaSettings.ts).
 * The switch offers only "on" and "off", so every value the server accepts must load as one of
 * them — otherwise it loads as no selection, and "— default (on) —" could never remove it.
 */

const KEY = "DFIR_SIGMA_SUZAKU_RULES";

interface Field {
  id: string;
  value: string;
  tagName: string;
  textContent: string;
  style: Record<string, string>;
  dispatchEvent: () => void;
  addEventListener: () => void;
}

const plain = (id: string): Field => ({
  id,
  value: "",
  tagName: "SELECT",
  textContent: "",
  style: {},
  dispatchEvent: () => {},
  addEventListener: () => {},
});

/** Like the browser's select: a value it has no option for leaves it on no option at all. */
function suzakuSwitch(): Field & { selected: () => string | null } {
  let current: string | null = "";
  return {
    ...plain(`env-${KEY}`),
    get value() {
      return current ?? "";
    },
    set value(v: string) {
      current = ["", "on", "off"].includes(v) ? v : null;
    },
    selected: () => current,
  };
}

async function loadThenSave(loaded: Record<string, string>, edit: (f: Field) => void = () => {}) {
  const field = suzakuSwitch();
  const posts: Array<Record<string, unknown>> = [];
  const byId = new Map<string, Field>([
    [field.id, field],
    ["settingsSaveMsg", plain("settingsSaveMsg")],
    ["settingsInvestigator", plain("settingsInvestigator")],
  ]);
  const api = loadDashboardModule<{ fetchEnvSettings(): Promise<void>; saveSettings(): Promise<boolean> }>(
    "dashboard-env-settings.js",
    ["dashboard-env-empty-lines.js"],
    {
      localStorage: { getItem: () => null, setItem: () => {}, removeItem: () => {} },
      SECTION_DEFS: [],
      SECTIONS_VIS_KEY: "dfir.sections",
      applySectionsVis: () => {},
      setTimeout: () => 0,
      Event: class {},
      document: {
        getElementById: (id: string) => byId.get(id) ?? null,
        querySelectorAll: (selector: string) => (selector === "[id^='env-']" ? [field] : []),
        createElement: () => plain("created"),
      },
      fetch: async (url: string, init?: { method?: string; body?: string }) => {
        if (url === "/settings/env" && init?.method === "POST") {
          posts.push(JSON.parse(init.body ?? "{}"));
          return { ok: true, json: async () => ({ ok: true }) };
        }
        if (url === "/settings/env") return { ok: true, json: async () => ({ env: loaded }) };
        if (url === "/settings/reload") return { ok: true, json: async () => ({ applied: [], rebuilt: [] }) };
        return { ok: true, json: async () => ({}) };
      },
    },
  );
  await api.fetchEnvSettings();
  const shown = field.selected();
  edit(field);
  await api.saveSettings();
  return { shown, posts };
}

describe("Suzaku rules switch — load and save (#2509)", () => {
  it("an absent key shows the default and saves nothing", async () => {
    const { shown, posts } = await loadThenSave({});
    expect(shown).toBe("");
    expect(posts).toEqual([]);
  });

  it.each([
    ["on", "on"],
    ["off", "off"],
    ["false", "off"],
    ["no", "off"],
    ["0", "off"],
    [" OFF ", "off"],
    ["False", "off"],
    ["true", "on"],
    ["yes", "on"],
    ["anything", "on"],
  ])("a stored %j shows as %j and an unchanged save keeps the file as it is", async (stored, expected) => {
    const { shown, posts } = await loadThenSave({ [KEY]: stored });
    expect(shown).toBe(expected);
    expect(posts).toEqual([]);
  });

  it("an off alias set back to the default is removed, so the rules come back on", async () => {
    const { posts } = await loadThenSave({ [KEY]: "false" }, (f) => (f.value = ""));
    expect(posts).toEqual([{ updates: {}, unset: [KEY] }]);
  });

  it("an off alias switched to on is written as on", async () => {
    const { posts } = await loadThenSave({ [KEY]: "no" }, (f) => (f.value = "on"));
    expect(posts).toEqual([{ updates: { [KEY]: "on" }, unset: [] }]);
  });

  it("an empty KEY= line still loads as the default and is removed on save (#2496)", async () => {
    const { shown, posts } = await loadThenSave({ [KEY]: "" });
    expect(shown).toBe("");
    expect(posts).toEqual([{ updates: {}, unset: [KEY] }]);
  });
});
