import { afterEach, describe, expect, it, vi } from "vitest";

/**
 * THE GRAMMAR REFERENCE HAS TO LOAD ONCE A CASE IS OPEN (#2461).
 *
 * The page loads with no case, so the init-time catalogue load returns at once. The case picker
 * then writes the case box and fires `change`; that handler reloaded saved hunts only, and it
 * also recorded the case as "requested", which then stopped the observer fallback from loading
 * the catalogue. The Grammar reference kept its placeholder forever.
 *
 * The workbench wires itself to the DOM on import, so these tests give it a small fake DOM with a
 * MutationObserver and requestAnimationFrame the test can drive.
 */

type Listener = (event?: unknown) => unknown;

class FakeElement {
  id: string;
  value = "";
  textContent = "";
  className = "";
  disabled = false;
  title = "";
  selectionStart = 0;
  placeholder = "";
  nonce = "";
  innerHTML = "";
  dataset: Record<string, string> = {};
  classList = { remove: () => {}, add: () => {} };
  listeners = new Map<string, Listener[]>();
  constructor(id: string) {
    this.id = id;
  }
  addEventListener(type: string, listener: Listener): void {
    this.listeners.set(type, [...(this.listeners.get(type) ?? []), listener]);
  }
  async fire(type: string): Promise<void> {
    for (const listener of this.listeners.get(type) ?? []) await listener({ target: this });
  }
  appendChild(): void {}
  focus(): void {}
  scrollIntoView(): void {}
  querySelectorAll(): unknown[] {
    return [];
  }
}

const PLACEHOLDER = "Open a case to load the typed grammar and field catalogue.";
const CATALOG = {
  grammar: "query := clause (AND clause)*",
  fields: [
    { name: "host.name", type: "string", description: "Host", indexed: true },
    { name: "severity", type: "severity", description: "Severity", indexed: true },
  ],
  errors: [],
};

interface Harness {
  el: (id: string) => FakeElement;
  urls: string[];
  /** Run the pending MutationObserver tick (the dashboard re-rendered). */
  tick: () => Promise<void>;
  settle: () => Promise<void>;
}

async function mount(catalogOk = true): Promise<Harness> {
  const elements = new Map<string, FakeElement>();
  const el = (id: string): FakeElement => {
    if (!elements.has(id)) elements.set(id, new FakeElement(id));
    return elements.get(id)!;
  };
  el("hqGrammar").textContent = PLACEHOLDER;
  const urls: string[] = [];
  let observerCallback: (() => void) | null = null;
  let frame: (() => void) | null = null;

  vi.stubGlobal("document", {
    readyState: "complete",
    getElementById: (id: string) => (id === "dfir-runtime-styles" ? null : el(id)),
    createElement: (tag: string) => new FakeElement(tag),
    head: new FakeElement("head"),
    body: new FakeElement("body"),
    querySelectorAll: () => [],
  });
  vi.stubGlobal(
    "MutationObserver",
    class {
      constructor(callback: () => void) {
        observerCallback = callback;
      }
      observe(): void {}
    },
  );
  vi.stubGlobal("requestAnimationFrame", (callback: () => void) => {
    frame = callback;
    return 0;
  });
  vi.stubGlobal("localStorage", { getItem: () => null, setItem: () => {} });
  vi.stubGlobal("fetch", async (url: string) => {
    urls.push(url);
    if (url.endsWith("/catalog") && !catalogOk) {
      return { ok: false, status: 500, json: async () => ({ error: "boom" }) };
    }
    const value = url.endsWith("/catalog") ? CATALOG : [];
    return { ok: true, status: 200, json: async () => value };
  });

  vi.resetModules();
  await import("../../../public/js/hunt-workbench.js");
  const settle = async () => {
    for (let i = 0; i < 20; i++) await Promise.resolve();
    await new Promise((resolve) => setImmediate(resolve));
  };
  const tick = async () => {
    observerCallback?.();
    const run = frame;
    frame = null;
    run?.();
    await settle();
  };
  await settle();
  return { el, urls, tick, settle };
}

const catalogFetches = (h: Harness) => h.urls.filter((url) => url.endsWith("/hunt-query/catalog"));

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("hunt workbench — Grammar reference loads with a case open (#2461)", () => {
  it("does not fetch the catalogue while no case is open", async () => {
    const h = await mount();
    expect(catalogFetches(h)).toHaveLength(0);
    expect(h.el("hqGrammar").textContent).toBe(PLACEHOLDER);
  });

  it("loads the grammar and the typed field list when the case picker opens a case", async () => {
    const h = await mount();
    h.el("caseId").value = "case-1";
    await h.el("caseId").fire("input");
    await h.el("caseId").fire("change");
    await h.settle();
    await h.tick(); // the dashboard re-renders after a case opens

    expect(catalogFetches(h)).toEqual(["/cases/case-1/hunt-query/catalog"]);
    const text = h.el("hqGrammar").textContent;
    expect(text).toContain(CATALOG.grammar);
    expect(text).toContain("host.name");
    expect(text).toContain("severity");
    expect(text).not.toContain(PLACEHOLDER);
  });

  it("loads it when a case is set silently and only the observer notices", async () => {
    const h = await mount();
    h.el("caseId").value = "case-2";
    await h.tick();

    expect(catalogFetches(h)).toEqual(["/cases/case-2/hunt-query/catalog"]);
    expect(h.el("hqGrammar").textContent).toContain(CATALOG.grammar);
  });

  it("does not refetch the catalogue on every re-render of the same case", async () => {
    const h = await mount();
    h.el("caseId").value = "case-1";
    await h.el("caseId").fire("change");
    await h.settle();
    await h.tick();
    await h.tick();

    expect(catalogFetches(h)).toHaveLength(1);
  });

  it("says so when the grammar reference fails to load", async () => {
    const h = await mount(false);
    h.el("caseId").value = "case-1";
    await h.el("caseId").fire("change");
    await h.settle();

    expect(h.el("hqGrammar").textContent).toMatch(/could not load the grammar reference/i);
  });
});
