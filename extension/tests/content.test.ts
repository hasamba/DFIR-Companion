// Behavioural tests for content.ts — the content-script entry that wires site-access toggling,
// user-event notification and extension-context-invalidation teardown around artifactCapture.ts
// and contextMenuCapture.ts (#2171). Those two modules are mocked: this file pins only the wiring.
//
// content.ts runs everything at import time, so each test installs fresh stubs, resets the module
// registry and re-imports it. The vitest environment is plain `node`, so document/location and the
// browser namespace are hand-rolled.

import { afterEach, describe, expect, it, vi } from "vitest";

type Listener = (...args: unknown[]) => unknown;

const PAGE_URL = "https://velociraptor.lab.test/app/index.html";
const PAGE_ORIGIN = "https://velociraptor.lab.test/*";

let docListeners: Record<string, Listener>;
let runtimeListener: Listener | undefined;
let sendMessage: ReturnType<typeof vi.fn>;
let initArtifactCapture: ReturnType<typeof vi.fn>;
let setArtifactCaptureEnabled: ReturnType<typeof vi.fn>;
let initContextMenuCapture: ReturnType<typeof vi.fn>;

async function loadContent(initResult: () => Promise<void> = () => Promise.resolve()): Promise<void> {
  vi.resetModules();
  docListeners = {};
  runtimeListener = undefined;
  sendMessage = vi.fn(() => Promise.resolve(undefined));
  initArtifactCapture = vi.fn(initResult);
  setArtifactCaptureEnabled = vi.fn();
  initContextMenuCapture = vi.fn();

  vi.stubGlobal("document", {
    addEventListener: vi.fn((type: string, handler: Listener) => { docListeners[type] = handler; }),
  });
  vi.stubGlobal("location", { href: PAGE_URL });

  const browserApi = {
    runtime: {
      sendMessage,
      onMessage: { addListener: (fn: Listener) => { runtimeListener = fn; } },
    },
  };
  vi.doMock("../src/browser.js", () => ({ browserApi }));
  vi.doMock("../src/artifactCapture.js", () => ({ initArtifactCapture, setArtifactCaptureEnabled }));
  vi.doMock("../src/contextMenuCapture.js", () => ({ initContextMenuCapture }));

  await import("../src/content.js");
  // Let the initArtifactCapture().catch(...) chain settle.
  await Promise.resolve();
  await Promise.resolve();
}

function siteAccess(message: unknown): void {
  if (!runtimeListener) throw new Error("no runtime.onMessage listener registered");
  runtimeListener(message, {}, () => undefined);
}

afterEach(() => {
  vi.doUnmock("../src/browser.js");
  vi.doUnmock("../src/artifactCapture.js");
  vi.doUnmock("../src/contextMenuCapture.js");
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe("content.ts start-up", () => {
  it("initialises context-menu capture and artifact capture exactly once", async () => {
    await loadContent();
    expect(initContextMenuCapture).toHaveBeenCalledTimes(1);
    expect(initArtifactCapture).toHaveBeenCalledTimes(1);
    // The enabled-gate it hands contextMenuCapture reflects the current site-access state.
    const isEnabled = initContextMenuCapture.mock.calls[0][0] as () => boolean;
    expect(isEnabled()).toBe(true);
    siteAccess({ kind: "site_access_changed", origins: [PAGE_ORIGIN], allowed: false });
    expect(isEnabled()).toBe(false);
  });

  it("tears capture down when init fails because the extension context was invalidated", async () => {
    await loadContent(() => Promise.reject(new Error("Extension context invalidated.")));
    expect(setArtifactCaptureEnabled).toHaveBeenCalledWith(false);
    docListeners.click();
    expect(sendMessage).not.toHaveBeenCalled();
  });

  it("leaves capture alone when init fails for any other reason", async () => {
    await loadContent(() => Promise.reject(new Error("storage quota exceeded")));
    expect(setArtifactCaptureEnabled).not.toHaveBeenCalled();
  });
});

describe("site_access_changed", () => {
  it("disables capture when this page's origin is revoked and re-enables it when granted", async () => {
    await loadContent();
    siteAccess({ kind: "site_access_changed", origins: [PAGE_ORIGIN], allowed: false });
    expect(setArtifactCaptureEnabled).toHaveBeenLastCalledWith(false);
    siteAccess({ kind: "site_access_changed", origins: [PAGE_ORIGIN], allowed: true });
    expect(setArtifactCaptureEnabled).toHaveBeenLastCalledWith(true);
  });

  it.each([
    ["another origin", { kind: "site_access_changed", origins: ["https://other.test/*"], allowed: false }],
    ["non-array origins", { kind: "site_access_changed", origins: PAGE_ORIGIN, allowed: false }],
    ["a different message kind", { kind: "user_event", origins: [PAGE_ORIGIN], allowed: false }],
  ])("ignores %s", async (_label, message) => {
    await loadContent();
    siteAccess(message);
    expect(setArtifactCaptureEnabled).not.toHaveBeenCalled();
  });
});

describe("user-event notification", () => {
  it("reports a click to the service worker", async () => {
    await loadContent();
    docListeners.click();
    expect(sendMessage).toHaveBeenCalledWith({ kind: "user_event", reason: "click" });
  });

  it("sends nothing once site access for this page is revoked", async () => {
    await loadContent();
    siteAccess({ kind: "site_access_changed", origins: [PAGE_ORIGIN], allowed: false });
    docListeners.click();
    docListeners.keydown();
    expect(sendMessage).not.toHaveBeenCalled();
  });

  it("debounces keydown bursts to one notification per 3 seconds", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-01T00:00:10Z"));
    await loadContent();
    docListeners.keydown();
    vi.setSystemTime(new Date("2026-01-01T00:00:11Z"));
    docListeners.keydown();
    expect(sendMessage).toHaveBeenCalledTimes(1);
    expect(sendMessage).toHaveBeenCalledWith({ kind: "user_event", reason: "keydown" });
    vi.setSystemTime(new Date("2026-01-01T00:00:14Z"));
    docListeners.keydown();
    expect(sendMessage).toHaveBeenCalledTimes(2);
  });

  it("disables capture when a notification hits an invalidated extension context", async () => {
    await loadContent();
    sendMessage.mockImplementationOnce(() => { throw new Error("Extension context invalidated."); });
    docListeners.click();
    expect(setArtifactCaptureEnabled).toHaveBeenCalledWith(false);
    docListeners.click();
    expect(sendMessage).toHaveBeenCalledTimes(1);
  });
});
