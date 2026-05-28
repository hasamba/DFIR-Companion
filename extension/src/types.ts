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

export interface ConnectionStatus {
  online: boolean;
  queued: number;
}
