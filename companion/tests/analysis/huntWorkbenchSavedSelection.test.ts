import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

/**
 * THE SAVED-HUNT SELECTION HAS TO SURVIVE A RUN (#1776), AND A LATE VALIDATE MUST NOT OVERWRITE
 * A NEWER STATUS LINE (#1777).
 *
 * Run of a saved hunt reloads the saved-hunt list, and rebuilding a <select>'s options resets its
 * value to the first option. Three readers of that value then went wrong at once: Delete did
 * nothing, Save POSTed a duplicate hunt, and a second Run recorded no execution history.
 *
 * The workbench is an ES module that wires itself to the DOM on import, so these tests give it a
 * small fake DOM. The one behaviour that matters is modelled exactly: setting a select's innerHTML
 * resets its value, and a value that is not an option is refused.
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
  dataset: Record<string, string> = {};
  classList = { remove: () => {}, add: () => {} };
  listeners = new Map<string, Listener[]>();
  private html = "";
  constructor(id: string) {
    this.id = id;
  }
  get innerHTML(): string {
    return this.html;
  }
  set innerHTML(html: string) {
    this.html = html;
  }
  addEventListener(type: string, listener: Listener): void {
    this.listeners.set(type, [...(this.listeners.get(type) ?? []), listener]);
  }
  async fire(type: string, target: unknown = this): Promise<void> {
    for (const listener of this.listeners.get(type) ?? []) await listener({ target });
  }
  appendChild(): void {}
  focus(): void {}
  scrollIntoView(): void {}
  /** Models HTMLInputElement.setRangeText with "end": replace [start, end) and move the cursor. */
  setRangeText(text: string, start: number, end: number): void {
    this.value = this.value.slice(0, start) + text + this.value.slice(end);
    this.selectionStart = start + text.length;
  }
  querySelectorAll(): unknown[] {
    return [];
  }
}

/** A select whose value only takes one of its options, and resets when its options are rebuilt. */
function fakeSelect(id: string): FakeElement {
  const element = new FakeElement(id);
  let html = "";
  let options: string[] = [];
  let current = "";
  Object.defineProperty(element, "innerHTML", {
    get: () => html,
    set: (next: string) => {
      html = next;
      options = [...next.matchAll(/<option value="([^"]*)"/g)].map((m) => m[1]);
      current = options[0] ?? "";
    },
  });
  Object.defineProperty(element, "value", {
    get: () => current,
    set: (next: string) => {
      current = options.includes(next) ? next : "";
    },
  });
  return element;
}

interface Call {
  method: string;
  url: string;
  body: Record<string, unknown> | null;
}

interface Harness {
  el: (id: string) => FakeElement;
  calls: Call[];
  confirms: string[];
  /** Hold the next POST /validate reply until release() is called. */
  holdValidate: () => { release: () => void };
  settle: () => Promise<void>;
}

const HUNTS = [
  { id: "h1", name: "delrace", dataset: "forensic", query: "severity>=High", author: "a", parameters: {} },
  { id: "h2", name: "other", dataset: "forensic", query: "host.name=x", author: "a", parameters: {} },
];

async function mount(): Promise<Harness> {
  const elements = new Map<string, FakeElement>();
  const el = (id: string): FakeElement => {
    if (!elements.has(id)) elements.set(id, id === "hqSaved" ? fakeSelect(id) : new FakeElement(id));
    return elements.get(id)!;
  };
  el("caseId").value = "case-1";
  const calls: Call[] = [];
  const confirms: string[] = [];
  let hunts = [...HUNTS];
  let validateGate: Promise<void> | null = null;

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
      observe(): void {}
    },
  );
  vi.stubGlobal("requestAnimationFrame", () => 0);
  vi.stubGlobal("localStorage", { getItem: () => null, setItem: () => {} });
  vi.stubGlobal("confirm", (text: string) => {
    confirms.push(text);
    return true;
  });
  vi.stubGlobal("prompt", (_text: string, fallback: string) => fallback);
  vi.stubGlobal("fetch", async (url: string, init: { method?: string; body?: string } = {}) => {
    const method = init.method ?? "GET";
    const body = init.body ? (JSON.parse(init.body) as Record<string, unknown>) : null;
    calls.push({ method, url, body });
    const reply = (value: unknown) => ({ ok: true, status: 200, json: async () => value });
    if (url.endsWith("/validate")) {
      const gate = validateGate;
      validateGate = null;
      if (gate) await gate;
      return reply({ explanation: "Filter: explanation" });
    }
    if (url.endsWith("/execute")) {
      return reply({
        matched: 10,
        scanned: 50,
        durationMs: 3,
        explanation: "ran",
        events: [],
        dataset: "forensic",
      });
    }
    if (url.endsWith("/saved") && method === "GET") return reply(hunts);
    if (url.endsWith("/saved") && method === "POST") {
      const created = { ...HUNTS[0], id: "h3", name: String(body?.name) };
      hunts = [...hunts, created];
      return reply(created);
    }
    const one = url.match(/\/saved\/([^/]+)$/);
    if (one && method === "PUT") return reply({ ...hunts.find((h) => h.id === one[1]), name: body?.name });
    if (one && method === "DELETE") {
      hunts = hunts.filter((h) => h.id !== decodeURIComponent(one[1]));
      return reply({ ok: true });
    }
    return reply({ fields: [], grammar: "" });
  });

  vi.resetModules();
  await import("../../../public/js/hunt-workbench.js");
  const settle = async () => {
    for (let i = 0; i < 20; i++) await Promise.resolve();
    await new Promise((resolve) => setImmediate(resolve));
  };
  await settle();
  return {
    el,
    calls,
    confirms,
    settle,
    holdValidate: () => {
      let release = () => {};
      validateGate = new Promise<void>((resolve) => {
        release = resolve;
      });
      return { release };
    },
  };
}

async function selectHunt(h: Harness, id: string): Promise<void> {
  h.el("hqSaved").value = id;
  await h.el("hqSaved").fire("change");
  await h.settle();
}

async function click(h: Harness, id: string): Promise<void> {
  await h.el(id).fire("click");
  await h.settle();
}

beforeEach(() => {
  vi.useRealTimers();
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe("hunt workbench — saved-hunt selection across a Run (#1776)", () => {
  it("keeps the selected saved hunt after Run", async () => {
    const h = await mount();
    await selectHunt(h, "h1");
    await click(h, "hqRun");

    expect(h.el("hqSaved").value).toBe("h1");
  });

  it("Delete after Run asks and deletes the selected hunt", async () => {
    const h = await mount();
    await selectHunt(h, "h1");
    await click(h, "hqRun");
    await click(h, "hqDelete");

    expect(h.confirms).toHaveLength(1);
    expect(h.calls.some((c) => c.method === "DELETE" && c.url.endsWith("/saved/h1"))).toBe(true);
  });

  it("a second Run of the same hunt still records its execution", async () => {
    const h = await mount();
    await selectHunt(h, "h1");
    await click(h, "hqRun");
    await click(h, "hqRun");

    const runs = h.calls.filter((c) => c.url.endsWith("/execute"));
    expect(runs.map((c) => c.body?.savedHuntId)).toEqual(["h1", "h1"]);
  });

  it("Save after Run updates the selected hunt instead of creating a duplicate", async () => {
    const h = await mount();
    await selectHunt(h, "h1");
    await click(h, "hqRun");
    await click(h, "hqSave");

    expect(h.calls.some((c) => c.method === "PUT" && c.url.endsWith("/saved/h1"))).toBe(true);
    expect(h.calls.some((c) => c.method === "POST" && c.url.endsWith("/saved"))).toBe(false);
  });

  it("Delete with nothing selected says so and sends nothing", async () => {
    const h = await mount();
    await click(h, "hqDelete");

    expect(h.confirms).toHaveLength(0);
    expect(h.calls.some((c) => c.method === "DELETE")).toBe(false);
    expect(h.el("hqStatus").textContent).toMatch(/select a saved hunt first/i);
  });

  it("a case change does not carry the old selection over", async () => {
    const h = await mount();
    await selectHunt(h, "h1");
    h.el("caseId").value = "case-2";
    await h.el("caseId").fire("change");
    await h.settle();

    expect(h.el("hqSaved").value).toBe("");
  });
});

describe("hunt workbench — a late validate reply (#1777)", () => {
  it("does not overwrite the Run result it raced", async () => {
    const h = await mount();
    h.el("hqQuery").value = "severity>=High";
    const held = h.holdValidate();
    void h.el("hqExplain").fire("click"); // validate in flight, reply held
    await h.settle();
    await click(h, "hqRun");
    held.release();
    await h.settle();

    expect(h.el("hqStatus").textContent).toMatch(/10 match\(es\)/);
  });

  it("does not overwrite the Saved message it raced", async () => {
    const h = await mount();
    h.el("hqQuery").value = "severity>=High";
    const held = h.holdValidate();
    void h.el("hqExplain").fire("click");
    await h.settle();
    await click(h, "hqSave");
    held.release();
    await h.settle();

    expect(h.el("hqStatus").textContent).toMatch(/^Saved/);
  });

  it("Save inside the debounce window cancels the pending validate", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    const h = await mount();
    h.el("hqQuery").value = "severity>=High";
    await h.el("hqQuery").fire("input");
    await click(h, "hqSave");
    vi.advanceTimersByTime(1000);
    await h.settle();

    expect(h.calls.filter((c) => c.url.endsWith("/validate"))).toHaveLength(0);
    expect(h.el("hqStatus").textContent).toMatch(/^Saved/);
  });

  it("a query edit makes an in-flight validate stale", async () => {
    // Fake timers only so the edit's own debounced validate never fires after the test ends.
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    const h = await mount();
    h.el("hqQuery").value = "severity>=High";
    const held = h.holdValidate();
    void h.el("hqExplain").fire("click");
    await h.settle();
    h.el("hqStatus").textContent = "before";
    h.el("hqQuery").value = "";
    await h.el("hqQuery").fire("input");
    held.release();
    await h.settle();

    expect(h.el("hqStatus").textContent).toBe("before");
  });

  it("an autocomplete pick makes an in-flight validate stale", async () => {
    // Fake timers only so the pick's own debounced validate never fires after the test ends.
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    const h = await mount();
    h.el("hqQuery").value = "severity>=High";
    const held = h.holdValidate();
    void h.el("hqExplain").fire("click");
    await h.settle();
    h.el("hqStatus").textContent = "before";
    await h.el("hqSuggestions").fire("click", { closest: () => ({ dataset: { hqComplete: "host.name" } }) });
    held.release();
    await h.settle();

    expect(h.el("hqStatus").textContent).toBe("before");
  });

  it("an autocomplete pick re-validates the completed query (#1912)", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    const h = await mount();
    const query = h.el("hqQuery");
    query.value = "user";
    query.selectionStart = 4;
    await h.el("hqSuggestions").fire("click", { closest: () => ({ dataset: { hqComplete: "user.name" } }) });
    expect(query.value).toBe("user.name");
    vi.advanceTimersByTime(400);
    await h.settle();

    const validates = h.calls.filter((c) => c.url.endsWith("/validate"));
    expect(validates.map((c) => c.body?.query)).toEqual(["user.name"]);
    expect(h.el("hqStatus").textContent).toBe("Filter: explanation");
  });

  it("a successful Save clears an earlier error colour", async () => {
    const h = await mount();
    h.el("hqStatus").className = "hq-status hq-error";
    await click(h, "hqSave");

    expect(h.el("hqStatus").className).not.toMatch(/hq-error/);
  });
});
