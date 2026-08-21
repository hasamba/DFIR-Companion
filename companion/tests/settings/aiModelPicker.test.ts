import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

const MODEL_FIELDS = [
  ["DFIR_VISION_MODEL", "vision"],
  ["DFIR_AI_SYNTH_MODEL", "synthesis"],
  ["DFIR_AI_VELO_MODEL", "velociraptor"],
  ["DFIR_AI_SECOND_OPINION_MODEL", "second-opinion"],
] as const;

describe("Settings AI model pickers", () => {
  it("gives every AI role a visible model dropdown plus custom-ID input", async () => {
    const html = await readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");

    for (const [key, role] of MODEL_FIELDS) {
      const field = html.match(new RegExp(`<input[^>]+id="env-${key}"[^>]*>`))?.[0] ?? "";
      const picker = html.match(new RegExp(`<select[^>]+id="ai-model-picker-${role}"[^>]*>`))?.[0] ?? "";
      const alignedControls = html.match(
        new RegExp(
          `<div[^>]+><select[^>]+id="ai-model-picker-${role}"[\\s\\S]*?</select>[\\s\\S]*?<input[^>]+id="env-${key}"[^>]*>[\\s\\S]*?<button[^>]+id="load-ai-models-${role}"[\\s\\S]*?</button></div>`,
        ),
      )?.[0];
      expect(field, `${key} has no custom-ID input`).not.toBe("");
      expect(picker, `${key} has no visible model dropdown`).not.toBe("");
      expect(alignedControls, `${key} model controls are not aligned in one row`).toBeDefined();
    }
  });

  it("loads provider models from the server without saving the settings first", async () => {
    const js = await readFile(
      new URL("../../../public/js/dashboard-env-settings.js", import.meta.url),
      "utf8",
    );

    expect(js).toContain('fetch("/settings/ai-models"');
    expect(js).toContain("apiKey");
    expect(js).toContain("baseUrl");
    expect(js).toContain('addEventListener("change"');
  });

  it("loads a provider change into the dropdown and copies a selection to the saved field", async () => {
    type Listener = () => void | Promise<void>;
    interface FakeElement {
      value: string;
      textContent: string;
      dataset: Record<string, string>;
      children: FakeElement[];
      style: { display: string };
      addEventListener(type: string, listener: Listener): void;
      focus(): void;
      replaceChildren(...children: FakeElement[]): void;
    }

    const elements = new Map<string, FakeElement>();
    const listeners = new Map<string, Listener[]>();
    const element = (id: string): FakeElement => {
      let current = elements.get(id);
      if (current) return current;
      current = {
        value: "",
        textContent: "",
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
    const requests: Array<{ url: string; init?: RequestInit }> = [];
    let modelCatalogAvailable = true;
    const fetchStub = async (url: string, init?: RequestInit) => {
      requests.push({ url, init });
      if (url === "/settings/env") {
        return {
          ok: true,
          json: async () => ({ env: { DFIR_VISION_PROVIDER: "openai" } }),
        };
      }
      if (!modelCatalogAvailable) {
        return {
          ok: false,
          json: async () => ({ error: "Provider model list returned HTTP 401" }),
        };
      }
      return {
        ok: true,
        json: async () => ({ models: ["gpt-4o", "gpt-4o-mini"] }),
      };
    };
    const api = loadDashboardModule<{ initEnvSettings(): void; fetchEnvSettings(): Promise<void> }>(
      "dashboard-env-settings.js",
      [],
      {
        document: {
          getElementById: element,
          createElement: () => element(`created-${elements.size}`),
        },
        fetch: fetchStub,
      },
    );
    api.initEnvSettings();
    await api.fetchEnvSettings();

    const modelRequest = requests.find((request) => {
      if (request.url !== "/settings/ai-models") return false;
      return JSON.parse(String(request.init?.body)).role === "vision";
    });
    expect(modelRequest).toBeDefined();
    expect(JSON.parse(String(modelRequest?.init?.body))).toMatchObject({
      provider: "openai",
      role: "vision",
    });
    expect(element("ai-model-picker-vision").children.map((option) => option.value)).toEqual([
      "",
      "gpt-4o",
      "gpt-4o-mini",
      "__custom__",
    ]);
    element("ai-model-picker-vision").value = "gpt-4o-mini";
    await listeners.get("ai-model-picker-vision:change")?.[0]?.();
    expect(element("env-DFIR_VISION_MODEL").value).toBe("gpt-4o-mini");
    expect(element("env-DFIR_VISION_MODEL").style.display).toBe("none");

    element("ai-model-picker-vision").value = "__custom__";
    await listeners.get("ai-model-picker-vision:change")?.[0]?.();
    expect(element("env-DFIR_VISION_MODEL").style.display).toBe("");
    expect(element("env-DFIR_VISION_MODEL").value).toBe("gpt-4o-mini");

    modelCatalogAvailable = false;
    await listeners.get("env-DFIR_VISION_PROVIDER:change")?.[0]?.();
    expect(element("ai-model-picker-vision").style.display).toBe("none");
    expect(element("env-DFIR_VISION_MODEL").style.display).toBe("");
    expect(element("ai-model-status-vision").textContent).toContain(
      "Could not load models: Provider model list returned HTTP 401",
    );
  });
});
