import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

/**
 * A SETTING THE ANALYST EMPTIES IS REMOVED FROM .env, NOT WRITTEN BACK AS `KEY=` (#2465).
 *
 * Two holes in the Settings save, both closed through the existing `unset` path (#1785):
 *
 *   - A text field emptied over a loaded value was posted as `updates[key] = ""`, and the server
 *     rewrote the line as `KEY=`. An empty value is not "unset": a parser with a `??` default reads
 *     "" instead of its default.
 *   - A secret loads blank behind "(already set)", so emptying it changed nothing and there was no
 *     way to remove a leaked key or switch an integration off without editing .env by hand. A
 *     "Clear" control beside every set secret now marks it for removal.
 *
 * A secret left blank WITHOUT pressing Clear must still send nothing — blank is how it loads.
 */

interface Fake {
  id: string;
  value: string;
  tagName: string;
  type?: string;
  hidden?: boolean;
  textContent: string;
  placeholder?: string;
  style: Record<string, string>;
  dataset: Record<string, string>;
  handlers: Record<string, Array<() => void>>;
  dispatchEvent: () => void;
  addEventListener: (ev: string, fn: () => void) => void;
  insertAdjacentElement: (where: string, node: Fake) => void;
  fire: (ev: string) => void;
}

function fake(id: string, tagName = "INPUT", type?: string): Fake {
  const f: Fake = {
    id,
    value: "",
    tagName,
    type,
    textContent: "",
    style: {},
    dataset: {},
    handlers: {},
    dispatchEvent: () => {},
    addEventListener: (ev, fn) => {
      (f.handlers[ev] ??= []).push(fn);
    },
    insertAdjacentElement: () => {},
    fire: (ev) => (f.handlers[ev] ?? []).forEach((fn) => fn()),
  };
  return f;
}

async function harness(loaded: Record<string, string>, fields: Fake[]) {
  const posts: Array<Record<string, unknown>> = [];
  const byId = new Map(fields.map((f) => [f.id, f]));
  const msg = fake("settingsSaveMsg");
  byId.set("settingsSaveMsg", msg);
  byId.set("settingsInvestigator", fake("settingsInvestigator"));
  const created: Fake[] = [];
  for (const f of fields) {
    f.insertAdjacentElement = (_where, node) => {
      byId.set(node.id, node);
    };
  }
  const api = loadDashboardModule<{ fetchEnvSettings(): Promise<void>; saveSettings(): Promise<boolean> }>(
    "dashboard-env-settings.js",
    ["dashboard-env-secret-clear.js", "dashboard-env-empty-lines.js"],
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
        createElement: (tag: string) => {
          const el = fake("", tag.toUpperCase());
          created.push(el);
          return el;
        },
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
  const clearButton = (key: string) => byId.get(`secretclear-${key}`);
  return { api, posts, message: () => msg.textContent, clearButton, created };
}

describe("Settings save — a cleared text field (#2465)", () => {
  it("removes the key instead of writing KEY=", async () => {
    const url = fake("env-DFIR_TIMESKETCH_URL");
    const h = await harness({ DFIR_TIMESKETCH_URL: "https://ts.example.test" }, [url]);
    url.value = "   ";
    await h.api.saveSettings();
    expect(h.posts).toEqual([{ updates: {}, unset: ["DFIR_TIMESKETCH_URL"] }]);
  });

  it("sends nothing for a blank text field whose key is not in .env", async () => {
    const url = fake("env-DFIR_TIMESKETCH_URL");
    const h = await harness({}, [url]);
    await h.api.saveSettings();
    expect(h.posts).toEqual([]);
  });

  it("still writes a changed text value as an update", async () => {
    const url = fake("env-DFIR_TIMESKETCH_URL");
    const h = await harness({ DFIR_TIMESKETCH_URL: "https://a.example.test" }, [url]);
    url.value = "https://b.example.test";
    await h.api.saveSettings();
    expect(h.posts).toEqual([{ updates: { DFIR_TIMESKETCH_URL: "https://b.example.test" }, unset: [] }]);
  });
});

describe("Settings — the Clear control on a masked secret (#2465)", () => {
  it("shows Clear only beside a secret that is set", async () => {
    const set = fake("env-DFIR_CLOUD_PROXY_URL", "INPUT", "password");
    const unsetKey = fake("env-DFIR_MISP_KEY", "INPUT", "password");
    const h = await harness({ DFIR_CLOUD_PROXY_URL: "••••••••", DFIR_MISP_KEY: "" }, [set, unsetKey]);
    expect(h.clearButton("DFIR_CLOUD_PROXY_URL")?.hidden).toBe(false);
    expect(h.clearButton("DFIR_MISP_KEY")?.hidden ?? true).toBe(true);
    // The control's id must not start with env-, or the save loop would treat it as a setting.
    expect(h.clearButton("DFIR_CLOUD_PROXY_URL")?.id.startsWith("env-")).toBe(false);
  });

  it("a secret marked with Clear is sent as unset and says so before saving", async () => {
    const proxy = fake("env-DFIR_CLOUD_PROXY_URL", "INPUT", "password");
    const h = await harness({ DFIR_CLOUD_PROXY_URL: "••••••••" }, [proxy]);
    h.clearButton("DFIR_CLOUD_PROXY_URL")!.fire("click");
    expect(proxy.placeholder).toMatch(/removed on save/i);
    await h.api.saveSettings();
    expect(h.posts).toEqual([{ updates: {}, unset: ["DFIR_CLOUD_PROXY_URL"] }]);
    expect(h.message()).not.toMatch(/no \.env changes/i);
    // After the save the field reads as not set, and the control is gone.
    expect(proxy.placeholder).toBe("(not set)");
    expect(h.clearButton("DFIR_CLOUD_PROXY_URL")?.hidden).toBe(true);
  });

  it("pressing Clear twice undoes the mark", async () => {
    const proxy = fake("env-DFIR_CLOUD_PROXY_URL", "INPUT", "password");
    const h = await harness({ DFIR_CLOUD_PROXY_URL: "••••••••" }, [proxy]);
    const btn = h.clearButton("DFIR_CLOUD_PROXY_URL")!;
    btn.fire("click");
    btn.fire("click");
    expect(proxy.placeholder).toBe("(already set)");
    await h.api.saveSettings();
    expect(h.posts).toEqual([]);
  });

  it("typing a new value cancels the mark and saves the value", async () => {
    const proxy = fake("env-DFIR_CLOUD_PROXY_URL", "INPUT", "password");
    const h = await harness({ DFIR_CLOUD_PROXY_URL: "••••••••" }, [proxy]);
    h.clearButton("DFIR_CLOUD_PROXY_URL")!.fire("click");
    proxy.value = "https://new-proxy.example.test";
    proxy.fire("input");
    await h.api.saveSettings();
    expect(h.posts).toEqual([
      { updates: { DFIR_CLOUD_PROXY_URL: "https://new-proxy.example.test" }, unset: [] },
    ]);
  });

  it("a secret left blank without Clear sends nothing", async () => {
    const proxy = fake("env-DFIR_CLOUD_PROXY_URL", "INPUT", "password");
    const h = await harness({ DFIR_CLOUD_PROXY_URL: "••••••••" }, [proxy]);
    await h.api.saveSettings();
    expect(h.posts).toEqual([]);
    expect(h.message()).toMatch(/no \.env changes/i);
  });

  it("reloading the settings resets a pending mark and does not add a second control", async () => {
    const proxy = fake("env-DFIR_CLOUD_PROXY_URL", "INPUT", "password");
    const h = await harness({ DFIR_CLOUD_PROXY_URL: "••••••••" }, [proxy]);
    h.clearButton("DFIR_CLOUD_PROXY_URL")!.fire("click");
    await h.api.fetchEnvSettings();
    expect(proxy.placeholder).toBe("(already set)");
    expect(h.created.filter((c) => c.tagName === "BUTTON")).toHaveLength(1);
    await h.api.saveSettings();
    expect(h.posts).toEqual([]);
  });
});

/**
 * AN EMPTY `KEY=` LINE LEFT IN .env BY AN OLDER SAVE OR A HAND EDIT IS REMOVED ON SAVE (#2496).
 *
 * The server returns such a line as `KEY: ""`, and a key that is not in the file not at all. The form
 * used to read both as "blank", so the line could never be removed from Settings.
 */
describe("Settings save — an empty KEY= line already in .env (#2496)", () => {
  it("removes a blank text field whose key loaded as an empty line", async () => {
    const url = fake("env-DFIR_TIMESKETCH_URL");
    const h = await harness({ DFIR_TIMESKETCH_URL: "" }, [url]);
    await h.api.saveSettings();
    expect(h.posts).toEqual([{ updates: {}, unset: ["DFIR_TIMESKETCH_URL"] }]);
  });

  it("removes an empty secret line without the Clear control", async () => {
    const key = fake("env-DFIR_MISP_KEY", "INPUT", "password");
    const h = await harness({ DFIR_MISP_KEY: "" }, [key]);
    expect(h.clearButton("DFIR_MISP_KEY")?.hidden ?? true).toBe(true);
    await h.api.saveSettings();
    expect(h.posts).toEqual([{ updates: {}, unset: ["DFIR_MISP_KEY"] }]);
  });

  it("writes a value typed into a field that loaded as an empty line", async () => {
    const key = fake("env-DFIR_MISP_KEY", "INPUT", "password");
    const h = await harness({ DFIR_MISP_KEY: "" }, [key]);
    key.value = "new-key-value";
    await h.api.saveSettings();
    expect(h.posts).toEqual([{ updates: { DFIR_MISP_KEY: "new-key-value" }, unset: [] }]);
  });

  it("does not send the removed line again on a second save", async () => {
    const url = fake("env-DFIR_TIMESKETCH_URL");
    const h = await harness({ DFIR_TIMESKETCH_URL: "" }, [url]);
    await h.api.saveSettings();
    await h.api.saveSettings();
    expect(h.posts).toEqual([{ updates: {}, unset: ["DFIR_TIMESKETCH_URL"] }]);
  });

  it("leaves an empty line for a read-only field in place", async () => {
    const root = Object.assign(fake("env-DFIR_CASES_ROOT"), { readOnly: true });
    const h = await harness({ DFIR_CASES_ROOT: "" }, [root]);
    await h.api.saveSettings();
    expect(h.posts).toEqual([]);
  });
});
