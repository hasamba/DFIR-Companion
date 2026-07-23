export type TriggerType = "timer" | "navigation" | "tab_switch" | "click";

export interface CapturePayload {
  caseId: string;
  timestamp: string;       // ISO-8601
  url: string;
  tabTitle: string;
  triggerType: TriggerType;
  imageBase64: string;     // base64 without data: prefix
}

export interface Settings {
  caseId: string;
  companionUrl: string;    // default http://127.0.0.1:4773
  intervalSeconds: number; // default 10
  dedupThreshold: number;  // default 5 (informational; dedup runs companion-side)
  running: boolean;
}

export const DEFAULT_SETTINGS: Settings = {
  caseId: "",
  companionUrl: "http://127.0.0.1:4773",
  intervalSeconds: 10,
  dedupThreshold: 5,
  running: false,
};

/** Strip trailing slashes and whitespace; fall back to the default when blank. */
export function normalizeCompanionUrl(raw: string): string {
  const trimmed = raw.trim().replace(/\/+$/, "");
  return trimmed || DEFAULT_SETTINGS.companionUrl;
}

// A capture that had been queued during an outage but which the companion later refused
// permanently — its case was deleted, closed or archived while the capture waited (#215). It is
// removed from the queue so it cannot block the entries behind it, and reported here so its loss
// is visible to the analyst rather than silent.
export interface DroppedCapture {
  payload: CapturePayload;
  status: number;         // the HTTP status that made it unsendable (0 = fetch itself failed)
  errorMessage?: string;  // the companion's explanation, when it gave one
}

export interface ConnectionStatus {
  online: boolean;
  queued: number;
  // HTTP 4xx status when the companion *rejected* the capture (e.g. 404 — the case does
  // not exist). The payload is NOT queued (retrying won't help); the popup surfaces it so
  // the analyst knows to create/select the case in the dashboard.
  rejected?: number;
  rejectedMessage?: string;
  // Previously-queued captures discarded during this drain (see DroppedCapture).
  dropped?: DroppedCapture[];
}

// ── Automated artifact fetching (issue #102) ──────────────────────────────────────────────────
// Body for POST /cases/:id/import — the unified, unauthenticated, localhost import route the
// extension pushes intercepted/scraped tool data through (mirrors the dashboard Import button).
// Exactly one of json/text is populated: json for a table push (stringified row array), text for
// a raw string push (context-menu selection or link URL) — the companion's importDetect.ts
// classifies either shape the same way it classifies an uploaded file.
export interface ImportPayload {
  json?: string;           // stringified array of rows
  text?: string;           // raw text (context-menu selection / link push)
  filename: string;        // synthetic name (adapter id + timestamp) — detection hint + audit label
  minSeverity?: string;
}

// content script → service worker: inject the MAIN-world fetch/XHR hook into this tab. The SW uses
// chrome.scripting.executeScript (world: "MAIN"), which bypasses the page's CSP.
export interface EnsureHookMessage {
  kind: "ensure_hook";
}

// content script → service worker: push a captured artifact to the companion. Exactly one of
// rows/text is populated: rows for a table push (adapter-scraped or context-menu table), text for
// a raw string push (context-menu selection or link URL).
export interface PushArtifactMessage {
  kind: "push_artifact";
  adapterId: string;
  rows?: unknown[];
  text?: string;
  sourceUrl: string;
  sourceLabel?: string;  // artifact / notebook the rows came from (for the evidence filename)
}

// service worker → content script: the outcome, surfaced on the injected page button.
export interface PushArtifactResult {
  ok: boolean;
  status?: number;
  rows?: number;
  caseId?: string;
  error?: string;
}

// ── Context-menu send (#new) ──────────────────────────────────────────────────────────────────
// service worker → content script: Chrome's contextMenus API gives no reference to the element
// under the cursor, so table targeting asks the content script (which remembered the element from
// the native "contextmenu" event) to walk up to its nearest <table> ancestor.
export interface GetContextTableMessage {
  kind: "get_context_table";
}

// content script → service worker: the table rows found (or null when no <table> ancestor, or the
// table had no data rows).
export interface ContextTableResult {
  rows: Record<string, string>[] | null;
}

// service worker → content script: the outcome of a context-menu push, rendered as a toast.
export interface ContextPushResultMessage {
  kind: "context_push_result";
  ok: boolean;
  message: string;
}

// ── Manual adapter override (popup ⇄ content script) ──────────────────────────────────────────
// popup → content script: read the current auto-detected/overridden adapter for this tab.
export interface GetCaptureStatusMessage {
  kind: "get_capture_status";
}

// popup → content script: force (or clear) which adapter is active for this tab. Session-only —
// held in the content script's in-memory state, so it resets on navigation/tab close.
// overrideAdapterId: "" = no override (auto-detect) | OVERRIDE_NONE (adapters/override.ts) =
// force no adapter | else an adapter id.
export interface SetAdapterOverrideMessage {
  kind: "set_adapter_override";
  overrideAdapterId: string;
}

// content script → popup: reply to both messages above.
export interface CaptureStatusResult {
  detectedAdapterId: string | null;
  overrideAdapterId: string;  // mirrors the popup <select> value — see SetAdapterOverrideMessage
  activeLabel: string | null; // the adapter actually in effect (detected, unless overridden)
  rowCount: number;           // rows captured so far under the active adapter
}
