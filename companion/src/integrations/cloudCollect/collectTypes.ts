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

/** How long a source keeps its logs (#2312): the retention pre-check and the result's disclosure. */
export interface RetentionSpec {
  /** The shortest retention any licence or configuration gives (Entra Free: 7 days). */
  minDays: number;
  /** The longest (Entra P1/P2: 30 days). Absent when there is one figure. */
  maxDays?: number;
  /** One plain sentence: what decides between the two. */
  note: string;
  /** Set when the log is OFF unless someone enabled it (GCP Data Access): the warning to show. */
  offByDefault?: string;
}

/** A provider's request-rate limit (#2312): `requests` per `perMs`, optionally per partition. */
export interface RateLimitSpec {
  requests: number;
  perMs: number;
  /** One limiter per value of this partition key (CloudTrail LookupEvents: per region). */
  perPartitionKey?: string;
}

/** One source a provider can collect (e.g. "cloudtrail-s3", "entra-signins", "gcp-audit"). */
export interface CollectSourceInfo {
  /** Stable id, `[a-z0-9-]`, used in file names and the manifest. */
  id: string;
  label: string;
  /** The streaming importer (#2303) that reads this source's saved pages. */
  streamKind: StreamKind;
  // ── #2312: every field below is optional; a source without them collects as in #2311. ──
  /** The smallest window a capped sub-window splits down to (Graph 1 min, CloudTrail/GCP 1 s). */
  minWindowMs?: number;
  /** A sub-window that still has a next page after this many pages counts as capped and splits. */
  maxPagesPerWindow?: number;
  /**
   * Partition fallback for a minimum window that is still capped: the key and its values (Graph:
   * record type or service; GCP: logName; AWS: region). `CloudCollectSession.partitionValues`
   * overrides the values at run time (the AWS regions an account uses).
   */
  partition?: { key: string; values?: readonly string[] };
  rateLimit?: RateLimitSpec;
  /** Tenant query submissions each new sub-window query costs (Graph AuditLogQuery: 1). */
  queryCost?: number;
  /** Default ingestion-delay overlap: the newest part of the window that may still be arriving. */
  overlapMs?: number;
  retention?: RetentionSpec;
  /** One sentence the pre-check and the result always show (LookupEvents: 90 days, management only). */
  notice?: string;
}

/** What the engine asks a provider for: one page of one sub-window. */
export interface CollectPageRequest {
  source: string;
  subWindowId: string;
  window: CollectWindow;
  /** The token the previous page returned; absent for the first page of a sub-window. */
  pageToken?: string;
  /** Partition fallback (#2312): only this slice of the source, e.g. `{ region: "eu-west-1" }`. */
  partition?: Record<string, string>;
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
  /**
   * The cloud capped this sub-window's results (#2312): Graph `isRecordCountLimitExceeded`, a result
   * cap. The engine stops paging it and re-collects its whole window as two halves (or partitions).
   */
  capped?: boolean;
  /**
   * The provider's own statement of how far this window's data is settled (a GCS sink's last
   * complete hourly batch). The disclosed cutoff is never later than it.
   */
  acquiredUntil?: string;
  /** One plain sentence for the result's coverage notes (a log sink not used, and why). */
  note?: string;
  /**
   * The cloud gives no completeness guarantee for this page's data (a GCS sink delivers best
   * effort). A source with such a page is never reported "complete" — at best "partial", with `note`.
   */
  unverified?: boolean;
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
  /** The partition values to fall back on for `source` (the regions an AWS account uses). */
  partitionValues?(source: string, signal?: AbortSignal): Promise<readonly string[]>;
  close?(): void | Promise<void>;
}

/** A provider adapter. #2313–#2315 each register one; none ships with #2311. */
export interface CloudCollectProvider {
  provider: CloudProvider;
  sources: readonly CollectSourceInfo[];
  /** Open a session with an account opened through openCloudAccountForCollect. */
  open(account: OpenCloudAccount): CloudCollectSession;
  /**
   * The key a shared daily query quota is counted under (#2312), from the account's NON-secret
   * settings — Microsoft: the tenant id, so two accounts of one tenant share one count. Absent: the
   * provider has no such quota. Only sources with a `queryCost` draw on it.
   */
  quotaScope?(settings: Readonly<Record<string, unknown>>): string | undefined;
  /** Throttle retries one collection run may spend (#2312). Default DEFAULT_RETRY_BUDGET. */
  retryBudget?: number;
}

/** The providers this server can collect with, keyed by provider. Empty until #2313–#2315. */
export type CloudCollectProviders = Partial<Record<CloudProvider, CloudCollectProvider>>;

/**
 * The cloud said slow down (#2312): HTTP 429, ThrottlingException, RESOURCE_EXHAUSTED. Providers
 * throw this with the Retry-After they were given; the engine backs off and retries the same request.
 */
export class RateLimitedError extends Error {
  constructor(
    readonly retryAfterMs?: number,
    message = "rate limited by the cloud",
  ) {
    super(message);
    this.name = "RateLimitedError";
  }
}

/**
 * ONE item of a sub-window the cloud refused (a KMS-denied trail object, a region that rejects the
 * call), #2313. Not a failure of the sub-window: the engine writes a `skip` manifest line, moves on
 * to `nextPageToken` (or finishes the sub-window when there is none) and the result lists the item.
 */
export class SkippedItemError extends Error {
  constructor(
    readonly item: string,
    readonly reason: string,
    readonly nextPageToken?: string,
  ) {
    super(`skipped ${item}: ${reason}`);
    this.name = "SkippedItemError";
  }
}

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
  /** Per source: the ingestion-delay overlap this collection discloses its cutoff with (#2312). */
  overlapMs?: Record<string, number>;
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
  /** #2312: why this page ended its sub-window as capped — the cloud said so, or the page cap. */
  capped?: "provider" | "page-cap";
  acquiredUntil?: string;
  /** #2314: the page's disclosure and its unverified completeness (CollectPage.note/unverified). */
  note?: string;
  unverified?: true;
}

/**
 * A capped sub-window, decided (#2312). Appended BEFORE the first child is fetched, so replay
 * rebuilds the tree. `time`: two halves; `partition`: the same window per partition value;
 * `too-dense`: a minimum window still capped with nothing left to split by — given up, disclosed.
 */
export interface ManifestSplit {
  type: "split";
  subWindowId: string;
  mode: "time" | "partition" | "too-dense";
  children: Array<{ id: string; window: CollectWindow; partition?: Record<string, string> }>;
  at: string;
}

/** A sub-window started over: its earlier pages stay evidence, its cursor does not. */
export interface ManifestRestart {
  type: "restart";
  subWindowId: string;
  /** `skipped-retry` (#2313): a resume re-collects a window that had items the cloud refused. */
  reason: "cursor-expired" | "corrupt-page" | "skipped-retry";
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

/** An item the cloud refused, skipped (#2313). Replay advances the sub-window to `pageTokenOut`. */
export interface ManifestSkip {
  type: "skip";
  source: string;
  subWindowId: string;
  item: string;
  reason: string;
  pageTokenIn?: string;
  pageTokenOut?: string;
  at: string;
}

export interface ManifestResume {
  type: "resume";
  at: string;
}

export type ManifestEntry =
  | ManifestHeader
  | ManifestPage
  | ManifestRestart
  | ManifestQuarantine
  | ManifestResume
  | ManifestSplit
  | ManifestSkip;

// ── Checkpoint and result ─────────────────────────────────────────────────────────────────────

/**
 * `capped`: a capped page is saved but the split is not yet decided (replay re-decides it);
 * `split`: re-collected by its children; `incomplete`: too dense even at the minimum window.
 */
export type SubWindowState = "pending" | "done" | "failed" | "capped" | "split" | "incomplete";

export interface SubWindowStatus {
  id: string;
  source: string;
  window: CollectWindow;
  state: SubWindowState;
  pageToken?: string;
  pages: number;
  records: number;
  restarts: number;
  /** Why a failed or incomplete sub-window is missing. */
  reason?: string;
  /** #2312 split tree: the parent's id, and the slice a partition child collects. */
  parent?: string;
  partition?: Record<string, string>;
  capped?: "provider" | "page-cap";
  /** When its first page came back (the disclosed cutoff is measured from it). */
  firstRetrievedAt?: string;
  acquiredUntil?: string;
  /** #2313: items the cloud refused and the engine skipped, and the first few of them. */
  skipped?: number;
  skippedItems?: string[];
  /** #2314: the notes its pages disclosed, and whether any page's completeness is unverified. */
  notes?: string[];
  unverified?: boolean;
}

/** Per source, how far the collection really got (#2312): never "complete" past this. */
export interface SourceCoverage {
  source: string;
  requested: CollectWindow;
  overlapMs: number;
  /** The newest time this collection's results are settled up to; absent when the end is missing. */
  acquiredCutoff?: string;
  notes: string[];
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
  /** A stop that ended the network stage early (disk full, write error, budget used). */
  stopReason?: string;
  /** #2312: the acquired cutoff and retention notes per source, written at the end of a run. */
  coverage?: SourceCoverage[];
  error?: string;
  startedAt: string;
  updatedAt: string;
}
