// postMessage protocol between the MAIN-world fetch/XHR hook (pageHook.ts) and the isolated-world
// content script (artifactCapture.ts). They live in different JS worlds and can only talk via
// window.postMessage, so the message shapes are shared here.
//
// pageHook.ts is bundled STANDALONE (a web-accessible resource injected into the page) and therefore
// re-declares these same literal strings inline rather than importing this module — keep the two in
// sync. This module is imported only by the content side.

export const DFIR_READY_MSG = "dfir-companion-hook-ready";
export const DFIR_CONFIG_MSG = "dfir-companion-hook-config";
export const DFIR_CAPTURE_MSG = "dfir-companion-hook-capture";

/** content → page: which response URLs to forward (regex sources matched case-insensitively). */
export interface HookConfigMessage {
  source: typeof DFIR_CONFIG_MSG;
  patterns: string[];
}

/** page → content: a captured API response body (raw text) for a matching URL. */
export interface HookCaptureMessage {
  source: typeof DFIR_CAPTURE_MSG;
  url: string;
  body: string;
}
