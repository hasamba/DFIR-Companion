import { afterEach, describe, expect, it, vi } from "vitest";
import { renderHuntHistory } from "../../../public/js/hunt-workbench.js";

/**
 * A SAVED HUNT'S EXECUTION HISTORY IS SHOWN WHEN THE HUNT IS SELECTED (#1833).
 *
 * The server records every run of a saved hunt, and GET /hunt-query/saved already returns that
 * history. The workbench never rendered it. Analyst names, parameter keys and values, and error
 * text are untrusted, so the renderer escapes each one.
 */

interface Run {
  id: string;
  executedAt: string;
  executedBy: string;
  status: string;
  matched: number;
  scanned: number;
  durationMs: number;
  parameters: Record<string, string | number | boolean | null>;
  error?: string;
}

const run = (over: Partial<Run> = {}): Run => ({
  id: "r1",
  executedAt: "2026-09-01T10:00:00.000Z",
  executedBy: "alice",
  status: "completed",
  matched: 3,
  scanned: 40,
  durationMs: 12,
  parameters: {},
  ...over,
});

describe("renderHuntHistory", () => {
  it("renders nothing when no saved hunt is selected", () => {
    expect(renderHuntHistory(null)).toBe("");
    expect(renderHuntHistory(undefined)).toBe("");
  });

  it('says "Not run yet" for a hunt with no history', () => {
    expect(renderHuntHistory({ history: [] })).toMatch(/Not run yet/);
    expect(renderHuntHistory({})).toMatch(/Not run yet/);
  });

  it("lists runs newest first with time, analyst, status, matches and duration", () => {
    const html = renderHuntHistory({
      history: [
        run({ id: "old", executedAt: "2026-09-01T10:00:00.000Z", executedBy: "older-analyst" }),
        run({
          id: "new",
          executedAt: "2026-09-02T10:00:00.000Z",
          executedBy: "newer-analyst",
          matched: 7,
          durationMs: 250,
        }),
      ],
    });
    for (const header of ["Time", "Analyst", "Status", "Matches", "Duration"]) {
      expect(html).toContain(`<th>${header}</th>`);
    }
    expect(html.indexOf("newer-analyst")).toBeLessThan(html.indexOf("older-analyst"));
    expect(html).toContain("2026-09-02T10:00:00.000Z");
    expect(html).toContain("250 ms");
    expect(html).toMatch(/>7</);
  });

  it("does not reorder the hunt's own history array", () => {
    const history = [
      run({ id: "a", executedAt: "2026-09-01T00:00:00.000Z" }),
      run({ id: "b", executedAt: "2026-09-03T00:00:00.000Z" }),
    ];
    renderHuntHistory({ history });
    expect(history.map((entry) => entry.id)).toEqual(["a", "b"]);
  });

  it("puts parameters in an expandable row that spans the table", () => {
    const html = renderHuntHistory({ history: [run({ parameters: { account: "jdoe", threshold: 5 } })] });
    expect(html).toMatch(/<tr class="hq-history-params"><td colspan="5"><details>/);
    expect(html).toContain("<summary>Parameters</summary>");
    expect(html).toContain("account");
    expect(html).toContain("jdoe");
    expect(html).toContain("threshold");
  });

  it("says a run had no parameters", () => {
    expect(renderHuntHistory({ history: [run()] })).toMatch(/No parameters/);
  });

  it("escapes analyst names, parameters, errors and status", () => {
    const html = renderHuntHistory({
      history: [
        run({
          executedBy: "<img src=x onerror=alert(1)>",
          status: 'failed" onmouseover="x',
          parameters: { "<b>k</b>": "<script>alert(2)</script>" },
          error: "<svg onload=alert(3)>",
        }),
      ],
    });
    expect(html).not.toMatch(/<img|<script|<svg|<b>k/);
    expect(html).toContain("&lt;img src=x onerror=alert(1)&gt;");
    expect(html).toContain("&lt;script&gt;alert(2)&lt;/script&gt;");
    expect(html).toContain("&lt;svg onload=alert(3)&gt;");
    expect(html).not.toContain('" onmouseover="');
  });

  it("uses a status as a class only when it is a known status", () => {
    expect(renderHuntHistory({ history: [run({ status: "failed" })] })).toContain("hq-run-failed");
    expect(renderHuntHistory({ history: [run({ status: "weird" })] })).not.toContain("hq-run-weird");
  });

  it("shows the error text of a failed run", () => {
    const html = renderHuntHistory({ history: [run({ status: "failed", error: "index missing" })] });
    expect(html).toContain("index missing");
  });
});

// ---------------------------------------------------------------------------------------------
// Mounted: the workbench wires itself to a small fake DOM on import.
// ---------------------------------------------------------------------------------------------

type Listener = (event?: unknown) => unknown;

class FakeElement {
  id: string;
  value = "";
  textContent = "";
  className = "";
  disabled = false;
  title = "";
  selectionStart = 0;
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
  setRangeText(): void {}
  querySelectorAll(): unknown[] {
    return [];
  }
}

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

interface Hunt {
  id: string;
  name: string;
  dataset: string;
  query: string;
  author: string;
  parameters: Record<string, string>;
  history: Run[];
}

interface Harness {
  el: (id: string) => FakeElement;
  settle: () => Promise<void>;
  failNextExecute: () => void;
  /** Hold the next GET /saved reply; release() lets it answer (reject = fail it). */
  holdSaved: () => { release: (reject?: boolean) => void };
  /** Fire the workbench's body MutationObserver, as a dashboard re-render would. */
  mutate: () => Promise<void>;
  /** Hold the next POST /execute until release(); abort rejects it like a real fetch. */
  holdExecute: () => { release: () => void };
  savedGets: () => string[];
}

async function mount(initial: Hunt[]): Promise<Harness> {
  const elements = new Map<string, FakeElement>();
  const el = (id: string): FakeElement => {
    if (!elements.has(id)) elements.set(id, id === "hqSaved" ? fakeSelect(id) : new FakeElement(id));
    return elements.get(id)!;
  };
  el("caseId").value = "case-1";
  let hunts = initial.map((hunt) => ({ ...hunt, history: [...hunt.history] }));
  let failExecute = false;
  let savedGate: Promise<boolean> | null = null;
  let counter = 0;
  let observerCallback: () => void = () => {};
  let executeGate: Promise<void> | null = null;
  const savedGets: string[] = [];

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
    callback();
    return 0;
  });
  vi.stubGlobal("localStorage", { getItem: () => null, setItem: () => {} });
  vi.stubGlobal("confirm", () => true);
  vi.stubGlobal("prompt", () => "Fresh hunt");
  vi.stubGlobal(
    "fetch",
    async (url: string, init: { method?: string; body?: string; signal?: AbortSignal } = {}) => {
      const method = init.method ?? "GET";
      const body = init.body ? (JSON.parse(init.body) as Record<string, unknown>) : null;
      const reply = (value: unknown, ok = true) => ({ ok, status: ok ? 200 : 500, json: async () => value });
      if (url.endsWith("/validate")) return reply({ explanation: "ok" });
      if (url.endsWith("/cancel")) return reply({ cancelled: true });
      if (url.endsWith("/execute")) {
        const gate = executeGate;
        executeGate = null;
        if (gate) {
          const signal = init.signal;
          const aborted = await Promise.race([
            gate.then(() => false),
            new Promise<boolean>((resolve) => signal?.addEventListener("abort", () => resolve(true))),
          ]);
          if (aborted) {
            // The server records the cancelled run a moment after the client sees its abort.
            setTimeout(() => {
              const entry = run({
                id: "cancelled-run",
                executedAt: "2026-09-09T00:00:00.000Z",
                status: "cancelled",
                matched: 0,
              });
              hunts = hunts.map((hunt) =>
                hunt.id === body?.savedHuntId ? { ...hunt, history: [entry, ...hunt.history] } : hunt,
              );
            }, 100);
            throw Object.assign(new Error("aborted"), { name: "AbortError" });
          }
        }
        counter += 1;
        const entry = run({
          id: `run-${counter}`,
          executedAt: `2026-09-0${counter}T00:00:00.000Z`,
          executedBy: String(body?.author),
          status: failExecute ? "failed" : "completed",
          matched: failExecute ? 0 : counter * 10,
        });
        hunts = hunts.map((hunt) =>
          hunt.id === body?.savedHuntId ? { ...hunt, history: [entry, ...hunt.history] } : hunt,
        );
        if (failExecute) {
          failExecute = false;
          return reply({ error: { message: "boom" } }, false);
        }
        return reply({
          matched: entry.matched,
          scanned: 1,
          durationMs: 1,
          explanation: "ran",
          events: [],
          dataset: "forensic",
        });
      }
      if (url.endsWith("/saved") && method === "GET") {
        savedGets.push(url);
        const gate = savedGate;
        savedGate = null;
        const snapshot = hunts;
        if (gate && (await gate)) return reply({ error: "down" }, false);
        return reply(snapshot);
      }
      if (url.endsWith("/saved") && method === "POST") {
        const created: Hunt = {
          id: "h-new",
          name: "Fresh hunt",
          dataset: "forensic",
          query: "x",
          author: "a",
          parameters: {},
          history: [],
        };
        hunts = [created, ...hunts];
        return reply(created);
      }
      return reply({ fields: [], grammar: "" });
    },
  );

  vi.resetModules();
  await import("../../../public/js/hunt-workbench.js");
  const settle = async () => {
    for (let i = 0; i < 20; i++) await Promise.resolve();
    await new Promise((resolve) => setImmediate(resolve));
  };
  await settle();
  return {
    el,
    settle,
    savedGets: () => savedGets,
    mutate: async () => {
      observerCallback();
      await settle();
    },
    holdExecute: () => {
      let release = () => {};
      executeGate = new Promise<void>((resolve) => {
        release = resolve;
      });
      return { release };
    },
    failNextExecute: () => {
      failExecute = true;
    },
    holdSaved: () => {
      let release: (reject?: boolean) => void = () => {};
      savedGate = new Promise<boolean>((resolve) => {
        release = (reject = false) => resolve(reject);
      });
      return { release };
    },
  };
}

const HUNT: Hunt = {
  id: "h1",
  name: "logons",
  dataset: "forensic",
  query: "event.category=authentication",
  author: "alice",
  parameters: {},
  history: [run({ id: "seed", executedBy: "seed-analyst" })],
};
const EMPTY: Hunt = { ...HUNT, id: "h2", name: "never", history: [] };

async function select(h: Harness, id: string): Promise<void> {
  h.el("hqSaved").value = id;
  await h.el("hqSaved").fire("change");
  await h.settle();
}

async function click(h: Harness, id: string): Promise<void> {
  await h.el(id).fire("click");
  await h.settle();
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("hunt workbench — execution history panel (#1833)", () => {
  it("shows the selected hunt's history, and nothing for an unsaved query", async () => {
    const h = await mount([HUNT, EMPTY]);
    expect(h.el("hqHistory").innerHTML).toBe("");

    await select(h, "h1");
    expect(h.el("hqHistory").innerHTML).toContain("seed-analyst");

    await select(h, "h2");
    expect(h.el("hqHistory").innerHTML).toMatch(/Not run yet/);

    await select(h, "");
    expect(h.el("hqHistory").innerHTML).toBe("");
  });

  it("refreshes after a Run and keeps the selection (#1776)", async () => {
    const h = await mount([HUNT]);
    await select(h, "h1");
    h.el("hqAuthor").value = "bob";
    await click(h, "hqRun");
    await click(h, "hqRun");

    const html = h.el("hqHistory").innerHTML;
    expect(h.el("hqSaved").value).toBe("h1");
    expect(html.match(/<tr class="hq-history-run/g)).toHaveLength(3);
    expect(html.indexOf(">20<")).toBeLessThan(html.indexOf(">10<"));
  });

  it("refreshes after a failed Run too", async () => {
    const h = await mount([EMPTY]);
    await select(h, "h2");
    h.failNextExecute();
    await click(h, "hqRun");

    expect(h.el("hqHistory").innerHTML).toContain("hq-run-failed");
  });

  it('a newly saved hunt shows "Not run yet"', async () => {
    const h = await mount([HUNT]);
    await click(h, "hqSave");

    expect(h.el("hqSaved").value).toBe("h-new");
    expect(h.el("hqHistory").innerHTML).toMatch(/Not run yet/);
  });

  it("a stale failed load does not clear a newer history", async () => {
    const h = await mount([HUNT]);
    await select(h, "h1");
    const held = h.holdSaved();
    void h.el("caseId").fire("change"); // older load, held
    await h.settle();
    await h.el("caseId").fire("change"); // newer load, answers
    await h.settle();
    await select(h, "h1");
    held.release(true); // older load now fails
    await h.settle();

    expect(h.el("hqHistory").innerHTML).toContain("seed-analyst");
  });

  it("hides the old case's history the moment the case changes", async () => {
    const h = await mount([HUNT]);
    await select(h, "h1");
    h.holdSaved(); // the new case's list never answers
    h.el("caseId").value = "case-2";
    void h.el("caseId").fire("change");
    await h.settle();

    expect(h.el("hqHistory").innerHTML).toBe("");
  });

  it("a case opened without an input event still reloads the list and hides the old history", async () => {
    const h = await mount([HUNT]);
    await select(h, "h1");
    const before = h.savedGets().length;
    h.el("caseId").value = "case-2"; // new-case / demo / import set the box directly
    await h.mutate();

    expect(h.savedGets().length).toBe(before + 1);
    expect(h.savedGets().at(-1)).toContain("/cases/case-2/");
    expect(h.el("hqHistory").innerHTML).toBe("");
  });

  it("one case change sends exactly one saved-hunts request (#1962)", async () => {
    const h = await mount([HUNT]);
    const before = h.savedGets().length;
    h.el("caseId").value = "case-2";
    // the case picker replays both events on one case change
    await h.el("caseId").fire("input");
    await h.el("caseId").fire("change");
    await h.settle();

    expect(h.savedGets().length).toBe(before + 1);
    expect(h.savedGets().at(-1)).toContain("/cases/case-2/");
  });

  it("a picked case still loads its saved hunts (#1962)", async () => {
    const h = await mount([HUNT]);
    h.el("caseId").value = "case-2";
    await h.el("caseId").fire("input");
    await h.el("caseId").fire("change");
    await h.settle();
    await select(h, "h1");

    expect(h.el("hqSaved").value).toBe("h1");
    expect(h.el("hqHistory").innerHTML).toContain("seed-analyst");
  });

  it("a re-render with the same case does not reload the list", async () => {
    const h = await mount([HUNT]);
    const before = h.savedGets().length;
    await h.mutate();

    expect(h.savedGets().length).toBe(before);
  });

  it("a cancelled Run shows the cancelled row once the server has recorded it", async () => {
    const h = await mount([EMPTY]);
    await select(h, "h2");
    h.holdExecute();
    const running = h.el("hqRun").fire("click");
    await h.settle();
    await h.el("hqCancel").fire("click");
    await running;
    await h.settle();

    expect(h.el("hqSaved").value).toBe("h2");
    expect(h.el("hqHistory").innerHTML).toContain("hq-run-cancelled");
  });
});
