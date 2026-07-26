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
    expect(firefoxManifest.browser_specific_settings.gecko.strict_min_version).toMatch(/^\d/);
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

function fakeNamespace() {
  const calls: Array<{ world?: string; target?: { tabId: number } }> = [];
  const ns = { scripting: { executeScript: (a: unknown) => { calls.push(a as never); return Promise.resolve([]); } } };
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
    const { executeScriptTarget, isFirefox } = await loadShim({ chrome: chromeNs.ns, browser: browserNs.ns });

    expect(isFirefox()).toBe(true);
    await executeScriptTarget(42, ["pageHook.js"]);

    expect(browserNs.calls).toHaveLength(1);
    expect(chromeNs.calls).toHaveLength(0);
    expect(browserNs.calls[0].world).toBeUndefined(); // MAIN world needs Firefox 128+
  });

  it("falls back to `chrome` and requests the MAIN world (Chrome)", async () => {
    const chromeNs = fakeNamespace();
    const { executeScriptTarget, isFirefox } = await loadShim({ chrome: chromeNs.ns });

    expect(isFirefox()).toBe(false);
    await executeScriptTarget(43, ["pageHook.js"]);

    expect(chromeNs.calls).toHaveLength(1);
    expect(chromeNs.calls[0].world).toBe("MAIN");
    expect(chromeNs.calls[0].target).toEqual({ tabId: 43 });
  });

  it("resolves the namespace per access rather than freezing it at import", async () => {
    const first = fakeNamespace();
    const { executeScriptTarget } = await loadShim({ chrome: first.ns });
    await executeScriptTarget(1, ["pageHook.js"]);

    const second = fakeNamespace();
    (globalThis as unknown as Record<string, unknown>).chrome = second.ns;
    await executeScriptTarget(2, ["pageHook.js"]);

    expect(first.calls).toHaveLength(1);
    expect(second.calls).toHaveLength(1);
  });

  it("throws a clear error when neither namespace exists", async () => {
    const { browserApi } = await loadShim({});
    expect(() => browserApi.storage).toThrow(/Neither the browser nor the chrome/);
  });
});
