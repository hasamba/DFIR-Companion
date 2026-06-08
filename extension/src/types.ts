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

export interface ConnectionStatus {
  online: boolean;
  queued: number;
  // HTTP 4xx status when the companion *rejected* the capture (e.g. 404 — the case does
  // not exist). The payload is NOT queued (retrying won't help); the popup surfaces it so
  // the analyst knows to create/select the case in the dashboard.
  rejected?: number;
}
