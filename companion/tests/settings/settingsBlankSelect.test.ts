import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

/**
 * A SELECT PUT BACK TO ITS BLANK OPTION IS A CHANGE, AND SAVE MUST SEND IT (#1785).
 *
 * Every Settings select has a blank option: "— not set —", "— default (…) —" or "— same as … —".
 * The save used to skip every blank select, so reverting one posted nothing and the modal said
 * "✓ No .env changes to save" while the old value stayed on disk. Telemetry switched off could not
 * be switched back on to its default this way, and an AI role could not go back to inheriting.
 *
 * The guard it replaced still matters in one case: a select that LOADED blank (the key is unset,
 * or holds a value the select has no option for) and is still blank is not a change, and must not
 * erase that unknown value.
 */

interface Field {
  id: string;
  value: string;
  tagName: string;
  type?: string;
  textContent: string;
  style: Record<string, string>;
  placeholder?: string;
  dispatchEvent: () => void;
  addEventListener: () => void;
}

const select = (id: string): Field => ({
  id,
  value: "",
  tagName: "SELECT",
  textContent: "",
  style: {},
  dispatchEvent: () => {},
  addEventListener: () => {},
});

async function saveAfter(loaded: Record<string, string>, fields: Field[], edit: () => void) {
  const posts: Array<Record<string, unknown>> = [];
  const byId = new Map(fields.map((f) => [f.id, f]));
  const msg = select("settingsSaveMsg");
  byId.set("settingsSaveMsg", msg);
  byId.set("settingsInvestigator", select("settingsInvestigator"));
  const api = loadDashboardModule<{ fetchEnvSettings(): Promise<void>; saveSettings(): Promise<boolean> }>(
    "dashboard-env-settings.js",
    [],
    {
      localStorage: { getItem: () => null, setItem: () => {}, removeItem: () => {} },
      SECTION_DEFS: [],
      SECTIONS_VIS_KEY: "dfir.sections",
      applySectionsVis: () => {},
      setTimeout: () => 0,
      Event: class {},
      document: {
        getElementById: (id: string) => byId.get(id) ?? null,
        querySelectorAll: (selector: string) => (selector === "[id^='env-']" ? fields : []),
        createElement: () => select("created"),
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
  edit();
  await api.saveSettings();
  return { posts, message: msg.textContent };
}

describe("Settings save — a select set back to its blank option", () => {
  it("sends the key as unset when it loaded with a value", async () => {
    const telemetry = select("env-DFIR_LOCAL_TELEMETRY");
    const { posts, message } = await saveAfter({ DFIR_LOCAL_TELEMETRY: "off" }, [telemetry], () => {
      telemetry.value = "";
    });

    expect(posts).toEqual([{ updates: {}, unset: ["DFIR_LOCAL_TELEMETRY"] }]);
    expect(message).not.toMatch(/no \.env changes/i);
  });

  it("sends nothing for a select that loaded blank and is still blank", async () => {
    const fallback = select("env-DFIR_AI_SYNTH_FALLBACK_PROVIDER");
    const { posts, message } = await saveAfter({ DFIR_AI_SYNTH_FALLBACK_PROVIDER: "" }, [fallback], () => {});

    expect(posts).toEqual([]);
    expect(message).toMatch(/no \.env changes/i);
  });

  it("still writes a changed non-blank select as a value", async () => {
    const cloud = select("env-DFIR_CROWDSTRIKE_CLOUD");
    const { posts } = await saveAfter({ DFIR_CROWDSTRIKE_CLOUD: "us-1" }, [cloud], () => {
      cloud.value = "eu-1";
    });

    expect(posts).toEqual([{ updates: { DFIR_CROWDSTRIKE_CLOUD: "eu-1" }, unset: [] }]);
  });
});
