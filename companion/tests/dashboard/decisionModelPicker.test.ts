import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// The Settings → Decision model picker (#2224), driven the way the browser drives it.
//
// On OpenRouter it lists ONLY decision models, each with its price, and still lets the analyst type
// any id. On TypeSafe there is nothing to pick (TypeSafe serves Jev only), so the list hides. A list
// that arrives after the analyst switched to TypeSafe paints nothing, and the saved model in the
// text box is never overwritten by loading a list.

interface Api {
  initDecisionModelPicker(): void;
  refreshDecisionModels(): Promise<void>;
}

interface FakeEl {
  id: string;
  value: string;
  textContent: string;
  hidden: boolean;
  disabled: boolean;
  options: FakeEl[];
  addEventListener(type: string, fn: () => void): void;
  fire(type: string): void;
  replaceChildren(...kids: FakeEl[]): void;
}

function makeEl(id = ""): FakeEl {
  const handlers: Record<string, (() => void)[]> = {};
  const el: FakeEl = {
    id,
    value: "",
    textContent: "",
    hidden: false,
    disabled: false,
    options: [],
    addEventListener: (type, fn) => {
      (handlers[type] ||= []).push(fn);
    },
    fire: (type) => (handlers[type] || []).forEach((f) => f()),
    replaceChildren: (...kids) => {
      el.options = kids;
    },
  };
  return el;
}

const IDS = [
  "env-DFIR_JEV_PROVIDER",
  "env-DFIR_JEV_MODEL",
  "decision-model-picker",
  "decision-model-refresh",
  "decision-model-status",
] as const;

const LIST = {
  models: [
    { id: "baseten/mammoth-1:free", name: "Baseten: Mammoth 1 (free)", free: true, inputPerMillionUSD: 0 },
    { id: "typesafe/jev-1.14", name: "TypeSafe: Jev 1.14", free: false, inputPerMillionUSD: 0.02 },
  ],
  fetchedAt: "2026-10-22T00:00:00.000Z",
  stale: false,
};

function harness(respond: () => Promise<{ ok: boolean; body: unknown }>) {
  const els = Object.fromEntries(IDS.map((id) => [id, makeEl(id)])) as Record<(typeof IDS)[number], FakeEl>;
  let calls = 0;
  const document = {
    getElementById: (id: string) => (els as Record<string, FakeEl>)[id] ?? null,
    createElement: () => makeEl(),
  };
  const fetch = async (url: string) => {
    calls += 1;
    expect(url).toBe("/settings/jev/models");
    const r = await respond();
    return { ok: r.ok, status: r.ok ? 200 : 502, json: async () => r.body };
  };
  const api = loadDashboardModule<Api>("dashboard-decision-model-picker.js", [], { document, fetch });
  return { api, els, calls: () => calls };
}

const picker = (h: ReturnType<typeof harness>) => h.els["decision-model-picker"];
const input = (h: ReturnType<typeof harness>) => h.els["env-DFIR_JEV_MODEL"];
const status = (h: ReturnType<typeof harness>) => h.els["decision-model-status"].textContent;

describe("the decision model picker", () => {
  it("lists only what the server returned, with a price or 'free', plus a default and manual entry", async () => {
    const h = harness(async () => ({ ok: true, body: LIST }));
    await h.api.refreshDecisionModels();
    const labels = picker(h).options.map((o) => o.textContent);
    expect(labels).toContain("Baseten: Mammoth 1 (free) — free");
    expect(labels).toContain("TypeSafe: Jev 1.14 — $0.02");
    expect(labels[0]).toMatch(/default.*jev-1\.14/i);
    expect(labels.at(-1)).toMatch(/manually/i);
    expect(picker(h).hidden).toBe(false);
    expect(picker(h).value).toBe(""); // blank saved model = the default
    expect(input(h).hidden).toBe(true);
  });

  it("selects the saved model and never rewrites the text box", async () => {
    const h = harness(async () => ({ ok: true, body: LIST }));
    input(h).value = "typesafe/jev-1.14";
    await h.api.refreshDecisionModels();
    expect(picker(h).value).toBe("typesafe/jev-1.14");
    expect(input(h).value).toBe("typesafe/jev-1.14");
  });

  it("shows the text box for a saved model the list does not have", async () => {
    const h = harness(async () => ({ ok: true, body: LIST }));
    input(h).value = "vendor/private-decider";
    await h.api.refreshDecisionModels();
    expect(picker(h).value).toBe("__custom__");
    expect(input(h).hidden).toBe(false);
    expect(input(h).value).toBe("vendor/private-decider");
  });

  it("writes a picked model into the saved field, and opens the text box for manual entry", async () => {
    const h = harness(async () => ({ ok: true, body: LIST }));
    h.api.initDecisionModelPicker();
    await h.api.refreshDecisionModels();
    picker(h).value = "baseten/mammoth-1:free";
    picker(h).fire("change");
    expect(input(h).value).toBe("baseten/mammoth-1:free");
    picker(h).value = "__custom__";
    picker(h).fire("change");
    expect(input(h).hidden).toBe(false);
  });

  it("asks nothing and hides the list on TypeSafe, which serves Jev only", async () => {
    const h = harness(async () => ({ ok: true, body: LIST }));
    h.els["env-DFIR_JEV_PROVIDER"].value = "typesafe";
    await h.api.refreshDecisionModels();
    expect(h.calls()).toBe(0);
    expect(picker(h).hidden).toBe(true);
    expect(input(h).hidden).toBe(false);
    expect(status(h)).toMatch(/TypeSafe/);
  });

  it("paints nothing from a list that arrives after the analyst switched to TypeSafe", async () => {
    let release: () => void = () => undefined;
    const h = harness(
      () =>
        new Promise((resolve) => {
          release = () => resolve({ ok: true, body: LIST });
        }),
    );
    const pending = h.api.refreshDecisionModels();
    h.els["env-DFIR_JEV_PROVIDER"].value = "typesafe";
    await h.api.refreshDecisionModels();
    release();
    await pending;
    expect(picker(h).hidden).toBe(true);
    expect(status(h)).toMatch(/TypeSafe/);
  });

  it("falls back to typing a model id when the list cannot load", async () => {
    const h = harness(async () => ({
      ok: false,
      body: { error: "Could not load the decision model list: HTTP 503" },
    }));
    input(h).value = "typesafe/jev-1.14";
    await h.api.refreshDecisionModels();
    expect(picker(h).hidden).toBe(true);
    expect(input(h).hidden).toBe(false);
    expect(input(h).value).toBe("typesafe/jev-1.14");
    expect(status(h)).toMatch(/503.*type a model id/i);
  });

  it("says when prices may be out of date", async () => {
    const h = harness(async () => ({ ok: true, body: { ...LIST, stale: true } }));
    await h.api.refreshDecisionModels();
    expect(status(h)).toMatch(/out of date/i);
  });

  it("reloads the list when the provider changes back to OpenRouter", async () => {
    const h = harness(async () => ({ ok: true, body: LIST }));
    h.api.initDecisionModelPicker();
    h.els["env-DFIR_JEV_PROVIDER"].value = "openrouter";
    h.els["env-DFIR_JEV_PROVIDER"].fire("change");
    await new Promise((r) => setTimeout(r, 0));
    expect(h.calls()).toBe(1);
  });
});
