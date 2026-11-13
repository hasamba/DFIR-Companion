// #2623: opening the narrative editor while a generation runs seeded the textarea with the OLD
// text, and Save then PUT it over the fresh narrative. Edit is now disabled while generating, and
// Generate refuses while the editor is open.
import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

interface NarrativeApi {
  genNarrative: () => void;
  initNarrativeTimeline: () => void;
}

type Reply = { ok: boolean; status: number; body: unknown };
const settle = () => new Promise((r) => setTimeout(r, 10));

function el(id: string) {
  const handlers: Record<string, (e: unknown) => void> = {};
  return {
    id,
    value: "",
    textContent: "",
    innerHTML: "",
    disabled: false,
    dataset: {} as Record<string, string>,
    style: { display: "" } as Record<string, string>,
    addEventListener: (type: string, fn: (e: unknown) => void) => void (handlers[type] = fn),
    // A disabled button fires no click, as in a browser.
    click(this: { disabled: boolean }) {
      if (!this.disabled) handlers.click?.({ stopPropagation: () => {} });
    },
    focus: () => {},
    querySelectorAll: () => [],
  };
}

function setup() {
  const elements: Record<string, ReturnType<typeof el>> = {};
  const get = (id: string) => (elements[id] ??= el(id));
  get("caseId").value = "case-1";
  get("narrativeEditWrap").style.display = "none";
  const calls: { url: string; method: string }[] = [];
  let release: (r: Reply) => void = () => {};
  const globals = {
    document: { getElementById: get, querySelector: () => null, addEventListener: () => {} },
    fetch: (url: string, init?: { method?: string }) => {
      calls.push({ url, method: init?.method ?? "GET" });
      return new Promise((resolve) => {
        release = (r) => resolve({ ok: r.ok, status: r.status, json: () => Promise.resolve(r.body) });
      });
    },
    isSectionVisible: () => true,
    loadSectionsVis: () => ({}),
    narrativeViewHtml: (t: string) => `<p>${t}</p>`,
    DfirState: { lastState: () => null },
  };
  const api = loadDashboardModule<NarrativeApi>("dashboard-narrative.js", [], globals);
  api.initNarrativeTimeline();
  return { get, calls, api, resolve: (r: Reply) => release(r) };
}

describe("narrative editor vs generation (#2623)", () => {
  it("disables Edit while generating and re-enables it on success", async () => {
    const t = setup();
    t.api.genNarrative();
    expect(t.get("editNarrativeBtn").disabled).toBe(true);
    t.resolve({ ok: true, status: 200, body: { narrativeTimeline: "fresh" } });
    await settle();
    expect(t.get("editNarrativeBtn").disabled).toBe(false);
    expect(t.get("narrativeView").dataset.raw).toBe("fresh");
  });

  it("re-enables Edit when generation fails", async () => {
    const t = setup();
    t.api.genNarrative();
    t.resolve({ ok: false, status: 500, body: { error: "boom" } });
    await settle();
    expect(t.get("editNarrativeBtn").disabled).toBe(false);
    expect(t.get("genNarrativeBtn").disabled).toBe(false);
    expect(t.get("genNarrativeMsg").textContent).toContain("boom");
  });

  it("a click on Edit during generation does not open the editor or seed old text", async () => {
    const t = setup();
    t.get("narrativeView").dataset.raw = "old";
    t.api.genNarrative();
    t.get("editNarrativeBtn").click();
    expect(t.get("narrativeEditWrap").style.display).toBe("none");
    expect(t.get("narrativeText").value).toBe("");
    t.resolve({ ok: true, status: 200, body: { narrativeTimeline: "fresh" } });
    await settle();
    expect(t.get("narrativeView").dataset.raw).toBe("fresh");
    expect(t.calls.every((c) => c.method === "POST")).toBe(true);
  });

  it("refuses Generate while the editor is open, with an explanation and no request", () => {
    const t = setup();
    t.get("narrativeView").dataset.raw = "old";
    t.get("editNarrativeBtn").click();
    t.api.genNarrative();
    expect(t.calls).toHaveLength(0);
    expect(t.get("genNarrativeMsg").textContent).toMatch(/close the editor/i);
    expect(t.get("genNarrativeBtn").disabled).toBe(false);
  });

  it("allows Generate again once the editor is cancelled", () => {
    const t = setup();
    t.get("editNarrativeBtn").click();
    t.get("cancelNarrativeBtn").click();
    t.api.genNarrative();
    expect(t.calls).toHaveLength(1);
  });
});
