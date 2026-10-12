// Behavioural tests for the isolated-world half of the capture pipeline (artifactCapture.ts, #102).
//
// The receiving end of the MAIN-world hook is a window.postMessage listener, and that channel is
// page-forgeable (#430): any script on the page can post a DFIR_CAPTURE_MSG. bridge.ts's
// isAcceptableCaptureBody predicate is tested in pageHook.test.ts; what these tests pin is that the
// listener actually checks `ev.source === window` and calls that predicate, so a regression that
// drops either check goes red instead of shipping (#2171).
//
// The extension's vitest environment is plain `node` (no jsdom), so window/document/location and
// the browser namespace are hand-rolled stubs, installed fresh per test before a dynamic import.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DFIR_CAPTURE_MSG, DFIR_CONFIG_MSG, DFIR_READY_MSG, MAX_CAPTURE_BODY } from "../src/adapters/bridge.js";
import type { CaptureStatusResult } from "../src/types.js";

type Listener = (...args: unknown[]) => unknown;

interface FakeElement {
  id: string;
  type?: string;
  textContent: string;
  style: Record<string, string>;
  addEventListener: Listener;
  getBoundingClientRect: () => { left: number; top: number; width: number; height: number };
  remove: () => void;
}

const VELOCIRAPTOR_URL = "https://velociraptor.lab.test/app/index.html";
const GET_TABLE_BODY = JSON.stringify({
  columns: ["Name", "Pid"],
  rows: [{ cell: ["svchost.exe", "1234"] }, { cell: ["cmd.exe", "5678"] }],
});

let pageListener: ((ev: { source: unknown; data: unknown }) => void) | undefined;
let extensionListener: Listener | undefined;
let postMessage: ReturnType<typeof vi.fn>;
let sendMessage: ReturnType<typeof vi.fn>;
let elements: Map<string, FakeElement>;

function fakeElement(): FakeElement {
  const el: FakeElement = {
    id: "",
    textContent: "",
    style: {},
    addEventListener: vi.fn(),
    getBoundingClientRect: () => ({ left: 0, top: 0, width: 100, height: 30 }),
    remove: () => { elements.delete(el.id); },
  };
  return el;
}

function installGlobals(href: string, caseId = "c1"): void {
  elements = new Map();
  pageListener = undefined;
  extensionListener = undefined;
  postMessage = vi.fn();
  sendMessage = vi.fn(() => Promise.resolve(undefined));

  const fakeWindow = {
    addEventListener: vi.fn((type: string, handler: (ev: { source: unknown; data: unknown }) => void) => {
      if (type === "message") pageListener = handler;
    }),
    postMessage,
    setTimeout: (fn: () => void, ms: number) => setTimeout(fn, ms),
    innerWidth: 1280,
    innerHeight: 800,
  };
  const body = { appendChild: (el: FakeElement) => { elements.set(el.id, el); } };
  const fakeDocument = {
    title: "",
    body,
    documentElement: body,
    getElementById: (id: string) => elements.get(id) ?? null,
    createElement: () => fakeElement(),
    querySelectorAll: () => [],
  };
  vi.stubGlobal("window", fakeWindow);
  vi.stubGlobal("document", fakeDocument);
  vi.stubGlobal("location", { href });
  vi.stubGlobal("MutationObserver", class { observe(): void { /* no-op */ } });

  const browserApi = {
    runtime: {
      sendMessage,
      onMessage: { addListener: (fn: Listener) => { extensionListener = fn; } },
    },
    storage: {
      local: {
        get: () => Promise.resolve({ settings: { caseId } }),
        set: () => Promise.resolve(),
      },
      onChanged: { addListener: vi.fn() },
    },
  };
  vi.doMock("../src/browser.js", () => ({ browserApi }));
}

async function loadModule(href = VELOCIRAPTOR_URL) {
  vi.resetModules();
  installGlobals(href);
  const mod = await import("../src/artifactCapture.js");
  await mod.initArtifactCapture();
  return mod;
}

// Let ingestCapturedBody's awaited decode settle. Several macrotask turns so a negative assertion
// ("nothing was ingested") cannot pass merely because the async work had not finished yet.
async function flush(): Promise<void> {
  for (let i = 0; i < 5; i++) await new Promise((r) => setTimeout(r, 0));
}

function status(): CaptureStatusResult {
  let result: CaptureStatusResult | undefined;
  extensionListener?.({ kind: "get_capture_status" }, {}, (r: CaptureStatusResult) => { result = r; });
  if (!result) throw new Error("get_capture_status got no response");
  return result;
}

function dispatchPage(source: unknown, data: unknown): void {
  if (!pageListener) throw new Error("no window message listener registered");
  pageListener({ source, data });
}

function configPosts(): unknown[] {
  return postMessage.mock.calls
    .map((c) => c[0] as { source?: string; patterns?: string[] })
    .filter((m) => m.source === DFIR_CONFIG_MSG);
}

beforeEach(() => {
  vi.useRealTimers();
});

afterEach(() => {
  vi.doUnmock("../src/browser.js");
  vi.unstubAllGlobals();
});

describe("initArtifactCapture on a recognised console", () => {
  it("asks the service worker to inject the hook and posts the adapter's URL patterns", async () => {
    await loadModule();
    expect(sendMessage).toHaveBeenCalledWith({ kind: "ensure_hook" });
    const configs = configPosts() as { patterns: string[] }[];
    expect(configs.length).toBeGreaterThan(0);
    expect(configs[0].patterns).toContain("/api/v1/GetTable");
    expect(status().detectedAdapterId).toBe("velociraptor");
  });

  it("re-posts the config when the hook announces it is ready", async () => {
    await loadModule();
    const before = configPosts().length;
    dispatchPage(window, { source: DFIR_READY_MSG });
    expect(configPosts().length).toBe(before + 1);
  });

  it("does nothing on an unrecognised page", async () => {
    await loadModule("https://example.test/");
    expect(sendMessage).not.toHaveBeenCalled();
    expect(configPosts()).toEqual([]);
    dispatchPage(window, { source: DFIR_CAPTURE_MSG, url: "/api/v1/GetTable", body: GET_TABLE_BODY });
    await flush();
    expect(status().rowCount).toBe(0);
  });
});

describe("page → content capture messages (#430 boundary)", () => {
  it("ingests rows from a capture message whose source is this window", async () => {
    await loadModule();
    dispatchPage(window, { source: DFIR_CAPTURE_MSG, url: "/api/v1/GetTable", body: GET_TABLE_BODY });
    await flush();
    expect(status().rowCount).toBe(2);
  });

  it("ignores a capture message that did not come from this window", async () => {
    await loadModule();
    dispatchPage({}, { source: DFIR_CAPTURE_MSG, url: "/api/v1/GetTable", body: GET_TABLE_BODY });
    dispatchPage(null, { source: DFIR_CAPTURE_MSG, url: "/api/v1/GetTable", body: GET_TABLE_BODY });
    await flush();
    expect(status().rowCount).toBe(0);
  });

  it("accepts a body exactly at the receiver-side cap", async () => {
    await loadModule();
    const body = GET_TABLE_BODY + " ".repeat(MAX_CAPTURE_BODY - GET_TABLE_BODY.length);
    expect(body.length).toBe(MAX_CAPTURE_BODY);
    dispatchPage(window, { source: DFIR_CAPTURE_MSG, url: "/api/v1/GetTable", body });
    await flush();
    expect(status().rowCount).toBe(2);
  });

  it("rejects a body one character over the cap, even though it would otherwise decode", async () => {
    await loadModule();
    // Valid JSON padded with whitespace the decoder trims away, so only the cap stops it.
    const body = GET_TABLE_BODY + " ".repeat(MAX_CAPTURE_BODY + 1 - GET_TABLE_BODY.length);
    dispatchPage(window, { source: DFIR_CAPTURE_MSG, url: "/api/v1/GetTable", body });
    await flush();
    expect(status().rowCount).toBe(0);
  });

  it.each([
    ["a non-string body", { source: DFIR_CAPTURE_MSG, url: "/api/v1/GetTable", body: { rows: [] } }],
    ["null data", null],
    ["data without a source", { url: "/api/v1/GetTable", body: GET_TABLE_BODY }],
    ["a non-string source", { source: 7, body: GET_TABLE_BODY }],
    ["an unrelated source", { source: "something-else", body: GET_TABLE_BODY }],
  ])("ignores %s without throwing", async (_label, data) => {
    await loadModule();
    expect(() => dispatchPage(window, data)).not.toThrow();
    await flush();
    expect(status().rowCount).toBe(0);
  });
});

describe("setArtifactCaptureEnabled", () => {
  it("disabling clears the hook's patterns and stops ingesting captures", async () => {
    const mod = await loadModule();
    mod.setArtifactCaptureEnabled(false);
    const last = configPosts().at(-1) as { patterns: string[] };
    expect(last.patterns).toEqual([]);
    dispatchPage(window, { source: DFIR_CAPTURE_MSG, url: "/api/v1/GetTable", body: GET_TABLE_BODY });
    await flush();
    expect(status().rowCount).toBe(0);
    expect(status().activeLabel).toBeNull();
  });

  it("a popup override while disabled returns the status unchanged", async () => {
    const mod = await loadModule();
    mod.setArtifactCaptureEnabled(false);
    const before = status();
    let response: CaptureStatusResult | undefined;
    const keepOpen = extensionListener?.(
      { kind: "set_adapter_override", overrideAdapterId: "splunk" },
      {},
      (r: CaptureStatusResult) => { response = r; },
    );
    expect(keepOpen).toBe(true);
    expect(response).toEqual(before);
    expect(response?.activeLabel).toBeNull();
  });

  it("re-enabling restores capture on the detected adapter", async () => {
    const mod = await loadModule();
    mod.setArtifactCaptureEnabled(false);
    mod.setArtifactCaptureEnabled(true);
    dispatchPage(window, { source: DFIR_CAPTURE_MSG, url: "/api/v1/GetTable", body: GET_TABLE_BODY });
    await flush();
    expect(status().rowCount).toBe(2);
  });
});
