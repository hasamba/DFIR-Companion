// Cross-browser namespace shim for the DFIR Companion extension.
// Chrome exposes the `chrome` global; Firefox exposes `browser` (Promise-based) but also supports
// most `chrome.*` APIs in Manifest V3. This module exports the available namespace and a few tiny
// helpers for APIs that differ between the two runtimes.

// Minimal global type declarations so the shim compiles without adding a full Firefox types package.
declare const browser: typeof chrome | undefined;

export const browserApi = (globalThis as typeof globalThis & { chrome?: typeof chrome; browser?: typeof browser }).chrome
  ?? (globalThis as typeof globalThis & { browser?: typeof browser }).browser;

if (!browserApi) {
  throw new Error("Neither chrome nor browser extension namespace is available");
}

// Firefox MV3 does not support scripting.executeScript with world: "MAIN". Chrome requires it to
// inject into the page's world under CSP. Use ISOLATED in Firefox; the content script's DOM-scrape
// fallback already handles pages where the main-world hook can't be installed.
export function executeScriptTarget(tabId: number, files: string[]): Promise<void> {
  const scripting = browserApi.scripting;
  const isFirefox = typeof (globalThis as typeof globalThis & { browser?: typeof browser }).browser !== "undefined";
  return scripting.executeScript({
    target: { tabId },
    files,
    ...(isFirefox ? {} : { world: "MAIN" as const }),
  } as chrome.scripting.InjectTarget & { world?: "MAIN" | "ISOLATED" }).then(() => undefined);
}
