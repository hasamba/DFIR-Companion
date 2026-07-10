export type TriggerType = "timer" | "navigation" | "tab_switch" | "click";

export interface CaptureMetadata {
  caseId: string;
  sequenceNumber: number;
  timestamp: string;        // ISO-8601
  url: string;
  tabTitle: string;
  triggerType: TriggerType;
  contentHash: string;      // SHA-256 hex of the screenshot bytes (exact-match dedup vs. the previous capture)
  isDuplicate: boolean;
  screenshotFile: string;   // relative filename within screenshots/, e.g. "000123_<ts>_<tab-title>.webp" (title slugified; omitted when empty / no safe chars)
}

export interface CasePasswordHash {
  salt: string; // hex-encoded, from scryptSync
  hash: string; // hex-encoded, from scryptSync
}

export interface CaseMeta {
  caseId: string;
  name: string;
  createdAt: string;        // ISO-8601
  investigator: string;
  aiProvider: string | null;
  status?: "open" | "closed" | "archived"; // lifecycle state; absent means open
  // scrypt hash+salt gating dashboard access to this case (issue: case password protection).
  // NEVER serialize this directly in an API response — always go through
  // analysis/casePassword.ts's sanitizeCaseMeta(), which replaces it with `hasPassword`.
  password?: CasePasswordHash;
}

// Audit record for an uploaded CSV result set (e.g. a Velociraptor export),
// appended to metadata/imports.jsonl before any analysis (evidence-first).
export interface ImportMetadata {
  caseId: string;
  sequenceNumber: number;
  importedAt: string;       // ISO-8601
  filename: string;         // stored filename within imports/
  originalName: string;     // the user's original file name
  rows: number;             // data rows (excluding header)
  bytes: number;            // raw CSV byte length
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
