import { readFile } from "node:fs/promises";
import { describe, expect, it, vi } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

/**
 * Per-model keys and base URLs are optional overrides of the provider boxes. The Settings → AI
 * notice offers to move old per-model values up to the provider boxes, driven by
 * GET/POST /settings/ai-key-migration.
 */

type Listener = () => void | Promise<void>;
interface FakeElement {
  value: string;
  textContent: string;
  disabled: boolean;
  dataset: Record<string, string>;
  children: FakeElement[];
  style: { display: string };
  addEventListener(type: string, listener: Listener): void;
  focus(): void;
  replaceChildren(...children: FakeElement[]): void;
}

interface Reply {
  ok: boolean;
  status?: number;
  body: unknown;
}

function harness(replies: { get: Reply | (() => Reply) | Error; post?: Reply }) {
  const elements = new Map<string, FakeElement>();
  const listeners = new Map<string, Listener[]>();
  const element = (id: string): FakeElement => {
    let current = elements.get(id);
    if (current) return current;
    current = {
      value: "",
      textContent: "",
      disabled: false,
      dataset: {},
      children: [],
      style: { display: "" },
      addEventListener(type, listener) {
        const key = `${id}:${type}`;
        listeners.set(key, [...(listeners.get(key) ?? []), listener]);
      },
      focus() {},
      replaceChildren(...children) {
        this.children = children;
      },
    };
    elements.set(id, current);
    return current;
  };
  // The markup starts the notice hidden.
  element("aiKeyMigration").style.display = "none";
  const requests: Array<{ url: string; method: string }> = [];
  const respond = (r: Reply) => ({ ok: r.ok, status: r.status ?? 200, json: async () => r.body });
  const fetchStub = async (url: string, init?: RequestInit) => {
    const method = init?.method ?? "GET";
    requests.push({ url, method });
    if (url === "/settings/env") return respond({ ok: true, body: { env: {} } });
    if (url === "/settings/ai-key-migration") {
      if (method === "POST") return respond(replies.post ?? { ok: false, status: 500, body: {} });
      const get = typeof replies.get === "function" ? replies.get() : replies.get;
      if (get instanceof Error) throw get;
      return respond(get);
    }
    return respond({ ok: true, body: { models: [] } });
  };
  const api = loadDashboardModule<{ initEnvSettings(): void; fetchEnvSettings(): Promise<void> }>(
    "dashboard-env-settings.js",
    [],
    {
      document: { getElementById: element, createElement: () => element(`created-${elements.size}`) },
      fetch: fetchStub,
    },
  );
  api.initEnvSettings();
  const click = async () => {
    for (const l of listeners.get("aiKeyMigrationBtn:click") ?? []) await l();
  };
  return { api, element, requests, click };
}

const PLAN = {
  moves: [
    {
      role: "synthesis",
      provider: "gemini",
      setting: "key",
      target: "DFIR_AI_KEY_GEMINI",
      sources: ["DFIR_AI_SYNTH_KEY"],
    },
    {
      role: "vision",
      provider: "litellm",
      setting: "baseUrl",
      target: "DFIR_AI_BASE_URL_LITELLM",
      sources: ["DFIR_VISION_BASE_URL"],
    },
  ],
  conflicts: [],
};

describe("Settings → AI: the move-to-provider notice", () => {
  it("stays hidden when there is nothing to move", async () => {
    const h = harness({ get: { ok: true, body: { moves: [], conflicts: [] } } });
    await h.api.fetchEnvSettings();
    expect(h.requests.some((r) => r.url === "/settings/ai-key-migration")).toBe(true);
    expect(h.element("aiKeyMigration").style.display).toBe("none");
  });

  it("lists each move with readable role and provider names", async () => {
    const h = harness({ get: { ok: true, body: PLAN } });
    await h.api.fetchEnvSettings();
    expect(h.element("aiKeyMigration").style.display).toBe("");
    expect(h.element("aiKeyMigrationText").textContent).toBe(
      "2 saved settings can move to the provider boxes: Synthesis key → Gemini key; " +
        "Screenshot base URL → LiteLLM base URL. Nothing changes in how the models run.",
    );
    expect(h.element("aiKeyMigrationConflicts").textContent).toBe("");
    expect(h.element("aiKeyMigrationBtn").disabled).toBe(false);
  });

  it("names the settings kept as overrides", async () => {
    const plan = {
      ...PLAN,
      conflicts: [
        {
          provider: "openrouter",
          setting: "key",
          roles: ["velociraptor", "second-opinion"],
          reason: "different values",
        },
        { provider: "ollama", setting: "baseUrl", roles: ["reconcile"], reason: "different values" },
      ],
    };
    const h = harness({ get: { ok: true, body: plan } });
    await h.api.fetchEnvSettings();
    expect(h.element("aiKeyMigrationConflicts").textContent).toBe(
      "Kept as overrides: Velociraptor, 2nd opinion (OpenRouter key); Referee (Ollama Cloud base URL).",
    );
  });

  it("moves on click, reports the result and reloads the fields", async () => {
    let calls = 0;
    const h = harness({
      // First load offers the move; the reload after it finds nothing left.
      get: () =>
        calls++ === 0 ? { ok: true, body: PLAN } : { ok: true, body: { moves: [], conflicts: [] } },
      post: { ok: true, body: { ok: true, moves: PLAN.moves, conflicts: [] } },
    });
    await h.api.fetchEnvSettings();
    const envLoadsBefore = h.requests.filter((r) => r.url === "/settings/env").length;
    await h.click();
    expect(h.requests).toContainEqual({ url: "/settings/ai-key-migration", method: "POST" });
    expect(h.requests.filter((r) => r.url === "/settings/env").length).toBe(envLoadsBefore + 1);
    expect(h.element("aiKeyMigration").style.display).toBe("");
    expect(h.element("aiKeyMigrationText").textContent).toBe(
      "Moved 2 settings. Restart the server for running analysis to use them.",
    );
    expect(h.element("aiKeyMigrationBtn").style.display).toBe("none");
  });

  it("shows the server's error and re-enables the button when the move fails", async () => {
    const h = harness({
      get: { ok: true, body: PLAN },
      post: { ok: false, status: 500, body: { error: "could not write .env" } },
    });
    await h.api.fetchEnvSettings();
    await h.click();
    expect(h.element("aiKeyMigrationText").textContent).toBe("Could not move settings: could not write .env");
    expect(h.element("aiKeyMigrationBtn").disabled).toBe(false);
  });

  it("keeps the notice hidden when the check fails", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      for (const get of [new Error("offline"), { ok: false, status: 404, body: {} }]) {
        const h = harness({ get });
        await h.api.fetchEnvSettings();
        expect(h.element("aiKeyMigration").style.display).toBe("none");
        expect(h.element("aiKeyMigrationText").textContent).toBe("");
      }
      expect(warn).toHaveBeenCalled();
    } finally {
      warn.mockRestore();
    }
  });
});

describe("Settings → AI: per-model key and base URL are optional overrides", () => {
  const ENVS = [
    "DFIR_VISION",
    "DFIR_AI_SYNTH",
    "DFIR_AI_VELO",
    "DFIR_AI_SECOND_OPINION",
    "DFIR_AI_RECONCILE",
  ];

  it("labels every per-model key and base URL as an override, outside Essential", async () => {
    const html = await readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
    for (const env of ENVS) {
      for (const [suffix, label, hint] of [
        ["KEY", "Override key (optional)", "blank = provider key"],
        ["BASE_URL", "Override base URL (optional)", "blank = provider base URL"],
      ]) {
        const id = `env-${env}_${suffix}`;
        const field = html.match(
          new RegExp(`<div class="sfield"[^>]*><label for="${id}">[\\s\\S]*?</div>`),
        )?.[0];
        expect(field, `${id} field not found`).toBeDefined();
        expect(field).toContain(`${label}<span class="sfield-hint">${env}_${suffix} — ${hint}</span>`);
        expect(field, `${id} must not be Essential`).not.toMatch(/data-essential/);
      }
    }
  });

  it("puts a hidden, Essential move notice under the provider intro", async () => {
    const html = await readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
    const intro = html.indexOf("Save one key and base URL per provider.");
    const notice = html.indexOf('<div id="aiKeyMigration"');
    const firstKey = html.indexOf('id="env-DFIR_AI_KEY_OPENAI"');
    expect(intro).toBeGreaterThan(-1);
    expect(notice).toBeGreaterThan(intro);
    expect(notice).toBeLessThan(firstKey);
    const tag = html.slice(notice, html.indexOf(">", notice) + 1);
    expect(tag).toMatch(/\bdata-essential\b/);
    expect(tag).toContain("display:none");
    expect(html).toMatch(
      /<button type="button" id="aiKeyMigrationBtn" class="btn-mini"[^>]*>Move them<\/button>/,
    );
  });
});
