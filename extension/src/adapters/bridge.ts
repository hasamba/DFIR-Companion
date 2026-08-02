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

/**
 * Largest capture body the content script will accept, in characters.
 *
 * The MAIN-world hook applies the same bound before it forwards anything (pageHook.ts's MAX_BODY,
 * re-declared there for the same standalone-bundle reason the message strings are — keep the two
 * numbers in sync). That is not enough on its own: a script in the page can post a
 * DFIR_CAPTURE_MSG itself and never goes through the hook, so the receiving side has to enforce
 * the bound it relies on rather than assume the sender did (#430).
 */
export const MAX_CAPTURE_BODY = 8_000_000;

/** Whether a DFIR_CAPTURE_MSG body is one the content script will accept at all. */
export function isAcceptableCaptureBody(body: unknown): body is string {
  return typeof body === "string" && body.length <= MAX_CAPTURE_BODY;
}

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
