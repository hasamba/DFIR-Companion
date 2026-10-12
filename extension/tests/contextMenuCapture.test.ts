// Behavioural tests for contextMenuCapture.ts — right-click table targeting and the result toast
// (#2171). The vitest environment is plain `node`, so the DOM and browser namespace are stubs.

import { afterEach, describe, expect, it, vi } from "vitest";
import type { ContextTableResult } from "../src/types.js";

type Listener = (...args: unknown[]) => unknown;

let contextMenuHandler: ((e: { target: unknown }) => void) | undefined;
let runtimeListener: Listener | undefined;
let created: { id: string; textContent: string; style: Record<string, string> }[];

// A stand-in Element so `e.target instanceof Element` holds in the node environment.
class FakeElement {
  constructor(private readonly table: unknown) {}
  closest(selector: string): unknown {
    return selector === "table" ? this.table : null;
  }
}

function cell(text: string) {
  return { textContent: text };
}

function row(tag: "th" | "td", texts: string[]) {
  const cells = texts.map(cell);
  return { querySelectorAll: (sel: string) => (sel === tag || sel === "td,th" ? cells : []) };
}

// Just enough of an HTMLTableElement for readTableMatrix: a header row of <th> then body rows.
function fakeTable(headers: string[], body: string[][]) {
  const trs = [row("th", headers), ...body.map((r) => row("td", r))];
  return {
    querySelectorAll: (sel: string) => (sel === "tr" ? trs : []),
    querySelector: () => null,
  };
}

async function load(isEnabled?: () => boolean) {
  vi.resetModules();
  contextMenuHandler = undefined;
  runtimeListener = undefined;
  created = [];
  vi.stubGlobal("Element", FakeElement);
  vi.stubGlobal("window", {
    setTimeout: () => 1,
    clearTimeout: () => undefined,
  });
  const body = { appendChild: vi.fn() };
  vi.stubGlobal("document", {
    addEventListener: vi.fn((type: string, handler: (e: { target: unknown }) => void) => {
      if (type === "contextmenu") contextMenuHandler = handler;
    }),
    getElementById: () => null,
    createElement: () => {
      const el = { id: "", textContent: "", style: {} as Record<string, string>, remove: vi.fn() };
      created.push(el);
      return el;
    },
    body,
    documentElement: body,
  });
  vi.doMock("../src/browser.js", () => ({
    browserApi: { runtime: { onMessage: { addListener: (fn: Listener) => { runtimeListener = fn; } } } },
  }));
  const mod = await import("../src/contextMenuCapture.js");
  mod.initContextMenuCapture(isEnabled);
}

function ask(msg: unknown): ContextTableResult | undefined {
  let response: ContextTableResult | undefined;
  runtimeListener?.(msg, {}, (r: ContextTableResult) => { response = r; });
  return response;
}

afterEach(() => {
  vi.doUnmock("../src/browser.js");
  vi.unstubAllGlobals();
});

describe("get_context_table", () => {
  it("returns no rows when nothing has been right-clicked", async () => {
    await load();
    expect(ask({ kind: "get_context_table" })).toEqual({ rows: null });
  });

  it("returns the rows of the table under the last right-click", async () => {
    await load();
    const table = fakeTable(["Name", "Pid"], [["svchost.exe", "1234"], ["cmd.exe", "5678"]]);
    contextMenuHandler?.({ target: new FakeElement(table) });
    expect(ask({ kind: "get_context_table" })).toEqual({
      rows: [
        { Name: "svchost.exe", Pid: "1234" },
        { Name: "cmd.exe", Pid: "5678" },
      ],
    });
  });

  it("returns no rows when the right-click target is not inside a table", async () => {
    await load();
    contextMenuHandler?.({ target: new FakeElement(null) });
    expect(ask({ kind: "get_context_table" })).toEqual({ rows: null });
  });

  it("returns no rows when site access is disabled, even over a table", async () => {
    await load(() => false);
    const table = fakeTable(["Name"], [["svchost.exe"]]);
    contextMenuHandler?.({ target: new FakeElement(table) });
    expect(ask({ kind: "get_context_table" })).toEqual({ rows: null });
  });
});

describe("context_push_result", () => {
  it("shows a toast with the result message when enabled", async () => {
    await load();
    ask({ kind: "context_push_result", ok: true, message: "Sent 2 rows" });
    expect(created).toHaveLength(1);
    expect(created[0].textContent).toBe("Sent 2 rows");
  });

  it("shows nothing when site access is disabled", async () => {
    await load(() => false);
    ask({ kind: "context_push_result", ok: false, message: "Push failed" });
    expect(created).toHaveLength(0);
  });
});
