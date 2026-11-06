// Durable, resumable cloud collection (#2311) — the shapes the engine and its providers share.
//
// The engine is PROVIDER-AGNOSTIC. A provider (AWS #2313, GCP #2314, Microsoft #2315) only knows
// how to open a session with an account and fetch ONE page of ONE source for ONE time window; the
// engine owns everything that makes the result evidence: the page files, the SHA-256 manifest, the
// checkpoint, orphan quarantine, hash validation on resume, cursor expiry, and the import.
//
// Shape follows integrations/iris/irisImportFetch.ts: the network client is injected as a
// structural interface, so the whole engine is unit-testable with a fake provider and no network.

import type { CloudProvider, OpenCloudAccount } from "../cloudAccounts/types.js";
import type { StreamKind } from "../../analysis/ingest/cloudStreamProviders.js";

/** A time window, ISO-8601, `start` inclusive and `end` exclusive. */
export interface CollectWindow {
  start: string;
  end: string;
}

/** One source a provider can collect (e.g. "cloudtrail-s3", "entra-signins", "gcp-audit"). */
export interface CollectSourceInfo {
  /** Stable id, `[a-z0-9-]`, used in file names and the manifest. */
  id: string;
  label: string;
  /** The streaming importer (#2303) that reads this source's saved pages. */
  streamKind: StreamKind;
}

/** What the engine asks a provider for: one page of one sub-window. */
export interface CollectPageRequest {
  source: string;
  subWindowId: string;
  window: CollectWindow;
  /** The token the previous page returned; absent for the first page of a sub-window. */
  pageToken?: string;
  signal?: AbortSignal;
}

/** One page as the cloud returned it. `body` is saved byte for byte as evidence. */
export interface CollectPage {
  body: Uint8Array;
  /** The saved file's extension: what the streaming reader detects (gzip by magic bytes). */
  extension: "json" | "jsonl" | "json.gz";
  recordCount: number;
  /** Absent on the last page of the sub-window. */
  nextPageToken?: string;
  /** The provider's own request id (x-amz-request-id, client-request-id, …), when it sent one. */
  requestId?: string;
  /** The request as sent, minus secrets: filter, page size, bucket/key, API version. */
  requestParams: Record<string, string>;
}

/** Who the session is, for the manifest header. Never a secret. */
export interface CollectIdentity {
  /** The account / tenant / project id the cloud reports. */
  accountRef: string;
  /** The caller identity (role ARN, app id, service account email). */
  caller: string;
  sdkVersions: Record<string, string>;
}

export interface CloudCollectSession {
  identity(signal?: AbortSignal): Promise<CollectIdentity>;
  /**
   * Fetch one page. Throws CursorExpiredError when `pageToken` is no longer accepted (GCP 24 h,
   * Graph query expiry); the engine then restarts the sub-window from its start.
   */
  fetchPage(request: CollectPageRequest): Promise<CollectPage>;
  close?(): void | Promise<void>;
}

/** A provider adapter. #2313–#2315 each register one; none ships with #2311. */
export interface CloudCollectProvider {
  provider: CloudProvider;
  sources: readonly CollectSourceInfo[];
  /** Open a session with an account opened through openCloudAccountForCollect. */
  open(account: OpenCloudAccount): CloudCollectSession;
}

/** The providers this server can collect with, keyed by provider. Empty until #2313–#2315. */
export type CloudCollectProviders = Partial<Record<CloudProvider, CloudCollectProvider>>;

/** A page token the cloud no longer accepts. */
export class CursorExpiredError extends Error {
  constructor(message = "page token expired") {
    super(message);
    this.name = "CursorExpiredError";
  }
}

// ── Manifest lines (manifest.jsonl, append-only) ─────────────────────────────────────────────

export interface ManifestHeader {
  type: "header";
  version: 1;
  collectionId: string;
  provider: CloudProvider;
  accountId: string;
  accountName: string;
  accountRef: string;
  caller: string;
  sources: string[];
  window: CollectWindow;
  filters: Record<string, string>;
  sdkVersions: Record<string, string>;
  companionVersion: string;
  startedAt: string;
}

export interface ManifestPage {
  type: "page";
  seq: number;
  source: string;
  subWindowId: string;
  requestParams: Record<string, string>;
  requestId?: string;
  retrievedAt: string;
  pageTokenIn?: string;
  pageTokenOut?: string;
  file: string;
  bytes: number;
  sha256: string;
  records: number;
}

/** A sub-window started over: its earlier pages stay evidence, its cursor does not. */
export interface ManifestRestart {
  type: "restart";
  subWindowId: string;
  reason: "cursor-expired" | "corrupt-page";
  at: string;
}

/** A file moved to quarantine/ — an orphan page or a committed page whose hash no longer matches. */
export interface ManifestQuarantine {
  type: "quarantine";
  reason: "orphan" | "corrupt" | "missing";
  file: string;
  quarantinedAs?: string;
  sha256?: string;
  expectedSha256?: string;
  bytes?: number;
  at: string;
}

export interface ManifestResume {
  type: "resume";
  at: string;
}

export type ManifestEntry =
  ManifestHeader | ManifestPage | ManifestRestart | ManifestQuarantine | ManifestResume;

// ── Checkpoint and result ─────────────────────────────────────────────────────────────────────

export type SubWindowState = "pending" | "done" | "failed";

export interface SubWindowStatus {
  id: string;
  source: string;
  window: CollectWindow;
  state: SubWindowState;
  pageToken?: string;
  pages: number;
  records: number;
  restarts: number;
  /** Why a failed sub-window is missing. */
  reason?: string;
}

export type CollectionStatus = "running" | "interrupted" | "complete" | "partial" | "failed";

export interface QuarantinedFile {
  file: string;
  reason: ManifestQuarantine["reason"];
  quarantinedAs?: string;
  sha256?: string;
  bytes?: number;
}

export interface MissingWindow {
  source: string;
  subWindowId: string;
  window: CollectWindow;
  reason: string;
}

export interface CollectionCheckpoint {
  version: 1;
  collectionId: string;
  caseId: string;
  accountId: string;
  provider: CloudProvider;
  sources: string[];
  window: CollectWindow;
  jobId?: string;
  status: CollectionStatus;
  stage: "network" | "import" | "done";
  subWindows: SubWindowStatus[];
  /** Page files whose import landed in the case. */
  imported: string[];
  quarantined: QuarantinedFile[];
  missing: MissingWindow[];
  /** A stop that ended the network stage early (disk full, write error). */
  stopReason?: string;
  error?: string;
  startedAt: string;
  updatedAt: string;
}
