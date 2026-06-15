// MAIN-world fetch / XMLHttpRequest hook (issue #102, "API interception — the cleanest method").
//
// Content scripts run in an ISOLATED world and can't see the overrides the page's own scripts use,
// so to observe the clean JSON a DFIR console already fetches we must run in the PAGE (MAIN) world.
// This file is injected (as a web-accessible resource <script>) ONLY into tabs the content script
// recognized as a known tool — on every other site nothing here ever runs.
//
// It wraps window.fetch and XMLHttpRequest, and for responses whose URL matches one of the
// adapter's API patterns (received via postMessage), forwards a copy of the body text back to the
// content script. It is otherwise transparent: the original response is always returned untouched,
// and a thrown clone/read never disturbs the page. The data stays in-page until the analyst clicks
// the push button — nothing leaves the browser here.
//
// Standalone bundle: these message-source strings MUST match src/adapters/bridge.ts.
const DFIR_READY_MSG = "dfir-companion-hook-ready";
const DFIR_CONFIG_MSG = "dfir-companion-hook-config";
const DFIR_CAPTURE_MSG = "dfir-companion-hook-capture";

// Don't forward absurdly large bodies across the postMessage bridge (the companion can still ingest
// big files via the dashboard; this just keeps the in-page channel sane). ~8 MB of response text.
const MAX_BODY = 8_000_000;

(function installDfirHook(): void {
  const w = window as unknown as { __dfirHookInstalled?: boolean };
  if (w.__dfirHookInstalled) return; // idempotent — survive double injection (SPA re-navigations)
  w.__dfirHookInstalled = true;

  let patterns: RegExp[] = [];

  const matches = (url: string): boolean => {
    if (!url) return false;
    for (const re of patterns) { try { if (re.test(url)) return true; } catch { /* skip */ } }
    return false;
  };

  const forward = (url: string, body: string): void => {
    if (!body || body.length > MAX_BODY) return;
    try { window.postMessage({ source: DFIR_CAPTURE_MSG, url, body }, "*"); } catch { /* ignore */ }
  };

  window.addEventListener("message", (ev: MessageEvent) => {
    if (ev.source !== window) return;
    const d = ev.data as { source?: string; patterns?: unknown } | null;
    if (!d || d.source !== DFIR_CONFIG_MSG || !Array.isArray(d.patterns)) return;
    patterns = (d.patterns as unknown[])
      .map((p) => { try { return new RegExp(String(p), "i"); } catch { return null; } })
      .filter((r): r is RegExp => r !== null);
  });

  // ── fetch ──
  const origFetch = window.fetch;
  if (typeof origFetch === "function") {
    window.fetch = function (this: unknown, ...args: Parameters<typeof fetch>): Promise<Response> {
      const p = origFetch.apply(this, args) as Promise<Response>;
      return p.then((res) => {
        try {
          const reqUrl = typeof args[0] === "string" ? args[0]
            : args[0] instanceof URL ? args[0].href
            : (args[0] as Request | undefined)?.url ?? "";
          const url = res.url || reqUrl;
          if (matches(url)) res.clone().text().then((t) => forward(url, t)).catch(() => {});
        } catch { /* never disturb the page's own flow */ }
        return res;
      });
    } as typeof fetch;
  }

  // ── XMLHttpRequest ──
  const XHR = window.XMLHttpRequest;
  if (XHR && XHR.prototype) {
    const origOpen = XHR.prototype.open;
    const origSend = XHR.prototype.send;
    XHR.prototype.open = function (this: XMLHttpRequest & { __dfirUrl?: string }, method: string, url: string, ...rest: unknown[]) {
      this.__dfirUrl = String(url);
      // eslint-disable-next-line prefer-rest-params
      return (origOpen as (...a: unknown[]) => void).apply(this, [method, url, ...rest]);
    };
    XHR.prototype.send = function (this: XMLHttpRequest & { __dfirUrl?: string }, ...sendArgs: unknown[]) {
      this.addEventListener("load", () => {
        try {
          const url = this.__dfirUrl || this.responseURL || "";
          if (!matches(url)) return;
          let text = "";
          if (this.responseType === "" || this.responseType === "text") {
            text = this.responseText;
          } else if (this.responseType === "json" && this.response != null) {
            text = JSON.stringify(this.response);
          }
          if (text) forward(url, text);
        } catch { /* ignore */ }
      });
      return (origSend as (...a: unknown[]) => void).apply(this, sendArgs);
    };
  }

  // Tell the content script we're live so it (re)sends the URL patterns.
  try { window.postMessage({ source: DFIR_READY_MSG }, "*"); } catch { /* ignore */ }
})();
