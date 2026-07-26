import { describe, it, expect, vi, afterEach } from "vitest";
import { readdirSync, readFileSync, statSync } from "fs";
import { resolve, dirname, relative } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const read = (name: string) => JSON.parse(readFileSync(resolve(__dirname, "..", name), "utf-8"));
const firefoxManifest = read("manifest-firefox.json");
const chromeManifest = read("manifest.json");

describe("manifest-firefox.json", () => {
  it("has browser_specific_settings with a gecko id", () => {
    expect(firefoxManifest.browser_specific_settings).toBeDefined();
    expect(firefoxManifest.browser_specific_settings.gecko.id).toMatch(/.+@.+/);
  });

  it("uses background.scripts instead of service_worker", () => {
    // Firefox has no MV3 service worker (bugzil.la/1573659) — it runs an event page instead.
    expect(firefoxManifest.background.service_worker).toBeUndefined();
    expect(firefoxManifest.background.scripts).toContain("serviceWorker.js");
  });

  it("requests host access via host_permissions, not permissions", () => {
    // MV3 splits the two keys: match patterns in `permissions` are not valid MV3 and Firefox
    // drops them with a manifest warning, leaving the add-on with no host access at all.
    expect(firefoxManifest.host_permissions).toContain("<all_urls>");
    const matchPatterns = (firefoxManifest.permissions as string[]).filter(
      (p) => p.includes("://") || p === "<all_urls>",
    );
    expect(matchPatterns).toEqual([]);
  });

  it("keeps the same capture shortcut", () => {
    expect(firefoxManifest.commands["toggle-capture"].suggested_key.default).toBe("Ctrl+Shift+S");
  });

  // These two lock the MAIN-world precondition from both ends. injectHook() requests
  // world: "MAIN" unconditionally, which is only safe because every Firefox that can install this
  // add-on supports it (128+). Lower the floor and the injection silently degrades to the isolated
  // world on older Firefox: the hook installs, wraps a `fetch` no page script calls, posts "ready",
  // and captures nothing — no error anywhere, just an add-on that quietly stops intercepting.
  it("requires Firefox 128+, where scripting.executeScript gained world: MAIN", () => {
    const min = firefoxManifest.browser_specific_settings.gecko.strict_min_version;
    expect(min).toMatch(/^\d+(\.\d+)*$/);
    expect(Number.parseInt(min, 10)).toBeGreaterThanOrEqual(128);
  });

  it("injects pageHook into the MAIN world unconditionally", () => {
    // Asserted against source: serviceWorker.ts registers listeners at import time, so it can't be
    // imported here without standing up the whole extension environment.
    const sw = readFileSync(resolve(__dirname, "../src/serviceWorker.ts"), "utf-8");
    // Up to the closing brace at column 0, i.e. the end of the function.
    const injectHook = /^async function injectHook[\s\S]*?^}/m.exec(sw)?.[0];
    expect(injectHook, "injectHook not found in serviceWorker.ts").toBeDefined();
    expect(injectHook).toContain('world: "MAIN"');
    expect(injectHook).toContain('files: ["pageHook.js"]');
  });
});

describe("manifest parity with manifest.json", () => {
  // The two manifests are maintained by hand; anything that isn't deliberately browser-specific
  // must not drift. `background` and `host_permissions`/`permissions` differ by design.
  it.each(["version", "name", "description", "icons", "options_ui", "action", "commands", "content_scripts"])(
    "%s matches the Chrome manifest",
    (key) => {
      expect(firefoxManifest[key]).toEqual(chromeManifest[key]);
    },
  );

  it("declares the same API permissions", () => {
    const apiPerms = (m: { permissions: string[] }) =>
      m.permissions.filter((p) => !p.includes("://") && p !== "<all_urls>").sort();
    expect(apiPerms(firefoxManifest)).toEqual(apiPerms(chromeManifest));
  });

  it("requests the same host access, however each manifest spells it", () => {
    const hosts = (m: { host_permissions?: string[]; permissions: string[] }) =>
      [...(m.host_permissions ?? []), ...m.permissions.filter((p) => p.includes("://") || p === "<all_urls>")].sort();
    expect(hosts(firefoxManifest)).toEqual(hosts(chromeManifest));
  });
});

describe("no direct chrome.* value references", () => {
  // The reason this is a test and not a review habit: a stray `chrome.storage.local.get(...)`
  // compiles cleanly (@types/chrome declares it), passes every test (node has no namespace at
  // all), and ships — then returns undefined on Firefox, whose `chrome` is the callback-only
  // porting aid. The failure is invisible until someone runs the add-on. See src/browser.ts.
  //
  // Heuristic, not a proof: `chrome.` preceded by `: ` is a type annotation (chrome.tabs.Tab,
  // chrome.runtime.MessageSender), which is fine — those have no runtime existence. Everything
  // else is a value reference and must go through browserApi.
  const srcRoot = resolve(__dirname, "../src");

  function tsFiles(dir: string): string[] {
    return readdirSync(dir).flatMap((name) => {
      const full = resolve(dir, name);
      if (statSync(full).isDirectory()) return tsFiles(full);
      return name.endsWith(".ts") ? [full] : [];
    });
  }

  it.each(tsFiles(srcRoot).map((f) => relative(srcRoot, f)).filter((f) => f !== "browser.ts"))(
    "src/%s uses browserApi",
    (file) => {
      const offenders = readFileSync(resolve(srcRoot, file), "utf-8")
        .split("\n")
        .map((line, i) => ({ line, n: i + 1 }))
        .filter(({ line }) => !line.trim().startsWith("//"))
        .filter(({ line }) => /(?<!: )(?<![\w.])chrome\.(?!\/\/)/.test(line));
      expect(offenders.map((o) => `${file}:${o.n}: ${o.line.trim()}`)).toEqual([]);
    },
  );
});

// Each case re-imports the shim after installing its globals. Without resetModules the module is
// cached across cases and whichever namespace existed at first import wins — which is exactly the
// bug these tests exist to catch, so asserting on a stale namespace would prove nothing.
async function loadShim(globals: { chrome?: unknown; browser?: unknown }) {
  vi.resetModules();
  const g = globalThis as unknown as Record<string, unknown>;
  delete g.chrome;
  delete g.browser;
  if (globals.chrome) g.chrome = globals.chrome;
  if (globals.browser) g.browser = globals.browser;
  return import("../src/browser.js");
}

// A stand-in for whichever namespace the shim picks, recording what reached it. storage.local.get
// is the vehicle simply because it's an ordinary promise-returning call — the shim is generic, so
// any API would do.
function fakeNamespace() {
  const calls: string[] = [];
  const ns = { storage: { local: { get: (key: string) => { calls.push(key); return Promise.resolve({}); } } } };
  return { ns, calls };
}

afterEach(() => {
  const g = globalThis as unknown as Record<string, unknown>;
  delete g.chrome;
  delete g.browser;
});

describe("browser shim", () => {
  it("prefers the promise-based `browser` namespace when both exist (Firefox)", async () => {
    // Firefox exposes both, but its `chrome` is the callback-only porting aid: an async call with
    // no callback returns undefined, so `await chrome.storage.local.get(...)` yields undefined.
    const chromeNs = fakeNamespace();
    const browserNs = fakeNamespace();
    const { browserApi, isFirefox } = await loadShim({ chrome: chromeNs.ns, browser: browserNs.ns });

    expect(isFirefox()).toBe(true);
    await browserApi.storage.local.get("settings");

    expect(browserNs.calls).toEqual(["settings"]);
    expect(chromeNs.calls).toEqual([]);
  });

  it("falls back to `chrome` when that is all there is (Chrome)", async () => {
    const chromeNs = fakeNamespace();
    const { browserApi, isFirefox } = await loadShim({ chrome: chromeNs.ns });

    expect(isFirefox()).toBe(false);
    await browserApi.storage.local.get("settings");

    expect(chromeNs.calls).toEqual(["settings"]);
  });

  it("resolves the namespace per access rather than freezing it at import", async () => {
    const first = fakeNamespace();
    const { browserApi } = await loadShim({ chrome: first.ns });
    await browserApi.storage.local.get("one");

    const second = fakeNamespace();
    (globalThis as unknown as Record<string, unknown>).chrome = second.ns;
    await browserApi.storage.local.get("two");

    expect(first.calls).toEqual(["one"]);
    expect(second.calls).toEqual(["two"]);
  });

  it("throws a clear error when neither namespace exists", async () => {
    const { browserApi } = await loadShim({});
    expect(() => browserApi.storage).toThrow(/Neither the browser nor the chrome/);
  });
});
