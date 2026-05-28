export type TriggerType = "timer" | "navigation" | "tab_switch" | "click";

export interface CaptureMetadata {
  caseId: string;
  sequenceNumber: number;
  timestamp: string;        // ISO-8601
  url: string;
  tabTitle: string;
  triggerType: TriggerType;
  perceptualHash: string;   // hex string
  isDuplicate: boolean;
  screenshotFile: string;   // relative filename within screenshots/, e.g. "000123_<ts>.webp"
}

export interface CaseMeta {
  caseId: string;
  name: string;
  createdAt: string;        // ISO-8601
  investigator: string;
  aiProvider: string | null;
}

// Payload the extension POSTs to the ingest endpoint.
export interface IngestPayload {
  caseId: string;
  timestamp: string;
  url: string;
  tabTitle: string;
  triggerType: TriggerType;
  imageBase64: string;      // base64-encoded screenshot bytes (webp/png)
}
