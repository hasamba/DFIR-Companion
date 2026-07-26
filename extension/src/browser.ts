// Cross-browser extension-API shim.
//
// Chrome exposes only `chrome`, whose MV3 APIs return a promise when called without a callback.
// Firefox exposes BOTH `browser` and `chrome` — but its `chrome` namespace is only a porting aid
// that speaks callbacks: an async call made without a callback returns `undefined`, so
// `await chrome.storage.local.get("settings")` silently yields `undefined` instead of the stored
// data (see MDN, "Chrome incompatibilities": Firefox "supports `chrome` using callbacks and
// `browser` using promises"). Preferring `browser` therefore gets promise semantics everywhere.
//
// Every module in this extension must go through `browserApi` rather than touching `chrome.*`
// directly — a stray `chrome.*` value reference compiles and passes tests but breaks on Firefox.
// `chrome.*` remains correct in TYPE positions (chrome.tabs.Tab, chrome.runtime.MessageSender, …),
// which come from @types/chrome and have no runtime existence.

// Minimal global declaration so the shim compiles without a full Firefox types package. Always
// read this off `globalThis`: a bare `browser` reference is a ReferenceError on Chrome.
declare const browser: typeof chrome | undefined;

type ExtensionGlobals = typeof globalThis & { chrome?: typeof chrome; browser?: typeof browser };

function globals(): ExtensionGlobals {
  return globalThis as ExtensionGlobals;
}

/** True on runtimes that expose the promise-based `browser` namespace (Firefox, Safari). */
export function isFirefox(): boolean {
  return typeof globals().browser !== "undefined";
}

function resolveApi(): typeof chrome {
  const { browser: browserNs, chrome: chromeNs } = globals();
  const api = browserNs ?? chromeNs;
  if (!api) throw new Error("Neither the browser nor the chrome extension namespace is available");
  return api;
}

// Resolved per property access rather than captured at module load. The namespace is always
// present before any of our code runs in a real extension context, but resolving lazily keeps
// the shim honest under test (where the globals are installed and swapped between cases) instead
// of freezing whichever namespace happened to exist at import time.
export const browserApi: typeof chrome = new Proxy({} as typeof chrome, {
  get(_target, prop: string | symbol) {
    return (resolveApi() as unknown as Record<string | symbol, unknown>)[prop];
  },
  has(_target, prop: string | symbol) {
    return prop in resolveApi();
  },
});

// Firefox only gained `world: "MAIN"` for scripting.executeScript in Firefox 128; manifest-firefox
// .json still admits 121, so the MAIN world is requested on Chrome only. Where it is omitted the
// hook lands in the isolated world and never sees the page's own fetch — the content script's
// DOM-scrape fallback (artifactCapture.ts) is what actually carries those pages.
export function executeScriptTarget(tabId: number, files: string[]): Promise<void> {
  return browserApi.scripting
    .executeScript({
      target: { tabId },
      files,
      ...(isFirefox() ? {} : { world: "MAIN" as const }),
    })
    .then(() => undefined);
}
