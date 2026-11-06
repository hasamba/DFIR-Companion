// The documented cloud limits the AWS, GCP and Microsoft collectors (#2313–#2315) declare on their
// sources (#2312). One table, so a figure that changes upstream changes in one place.
//
// The overlaps are DEFAULTS for ingestion delay, not completeness guarantees; the result discloses
// the cutoff it actually reached. GCS sinks write hourly batches with late shards (#2314): a sink
// source states its own cutoff per page (`CollectPage.acquiredUntil`) instead.

import type { RateLimitSpec, RetentionSpec } from "./collectTypes.js";

const MINUTE = 60_000;

/** Smallest window a capped sub-window splits down to. */
export const MIN_WINDOW_MS = {
  graph: MINUTE,
  cloudTrail: 1000,
  gcp: 1000,
} as const;

/** Request-rate limits. */
export const RATE_LIMITS = {
  /** Graph sign-in logs: 5 requests per 10 seconds. */
  graphSignIns: { requests: 5, perMs: 10_000 },
  /** CloudTrail LookupEvents: 2 requests per second, per region. */
  cloudTrailLookupEvents: { requests: 2, perMs: 1000, perPartitionKey: "region" },
  /** Cloud Logging entries.list: 60 calls per minute. */
  gcpLogging: { requests: 60, perMs: MINUTE },
} as const satisfies Record<string, RateLimitSpec>;

/** Default ingestion-delay overlap per provider. */
export const DEFAULT_OVERLAP_MS = {
  aws: 15 * MINUTE,
  microsoft: 60 * MINUTE,
  gcp: 5 * MINUTE,
} as const;

/** Partition fallback keys. */
export const PARTITION_KEYS = {
  aws: "region",
  gcp: "logName",
  graph: "recordType",
} as const;

/** GCP audit log names the partition fallback walks. */
export const GCP_AUDIT_LOG_NAMES = ["activity", "data_access", "system_event", "policy"] as const;

/** Retention, for the pre-check and the result's disclosure. */
export const RETENTION = {
  entra: {
    minDays: 7,
    maxDays: 30,
    note: "Entra keeps sign-in and audit logs 7 days on the Free licence and 30 days with P1 or P2.",
  },
  unifiedAuditLog: {
    minDays: 180,
    maxDays: 365,
    note: "The unified audit log keeps 180 days by default and 365 days with Audit (Premium).",
  },
  cloudTrailLookupEvents: {
    minDays: 90,
    note: "LookupEvents returns the last 90 days of management events only; the S3 trail keeps more.",
  },
  guardDutyFindings: {
    minDays: 90,
    note: "GuardDuty keeps findings for 90 days after their last update, archived findings included.",
  },
  azureActivity: {
    minDays: 90,
    note: "The Azure Activity log keeps 90 days unless it is exported to a workspace or storage.",
  },
  gcpDataAccess: {
    minDays: 30,
    note: "The _Default bucket keeps Data Access audit logs 30 days unless it was configured longer.",
    offByDefault:
      "GCP Data Access audit logs are OFF by default: only the services someone enabled have any.",
  },
} as const satisfies Record<string, RetentionSpec>;
