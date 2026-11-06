// Cloud account read check (#2309): the sources a check can test, per provider, and what it reports.
//
// A check calls ONE read API per source (a page of one entry, or a listing and one object) and says
// which reads worked. It never claims the identity is read-only: no write probe is ever made and no
// policy simulator is asked, so whether the identity can also write stays untested by design.

import type { CloudProvider } from "../cloudAccounts/types.js";

export type AwsCheckSource = "cloudtrail-lookup" | "s3-trail";
export type MicrosoftCheckSource = "entra-signins" | "entra-directory-audits";
export type GcpCheckSource = "audit-logs" | "data-access-logs";
export type CloudCheckSource = AwsCheckSource | MicrosoftCheckSource | GcpCheckSource;

/** Every source a check can test, per provider, in the order a report lists them. */
export const CHECK_SOURCES: Readonly<Record<CloudProvider, readonly CloudCheckSource[]>> = {
  aws: ["cloudtrail-lookup", "s3-trail"],
  microsoft: ["entra-signins", "entra-directory-audits"],
  gcp: ["audit-logs", "data-access-logs"],
};

/** The plain-English name a report and the dashboard use for each source. */
export const CHECK_SOURCE_LABELS: Readonly<Record<CloudCheckSource, string>> = {
  "cloudtrail-lookup": "CloudTrail event history",
  "s3-trail": "CloudTrail S3 bucket",
  "entra-signins": "Entra sign-in logs",
  "entra-directory-audits": "Entra directory audit logs",
  "audit-logs": "GCP Admin Activity, System Event and Policy audit logs",
  "data-access-logs": "GCP Data Access audit logs",
};

/** One source's outcome. `detail` is short, fixed or scrubbed text — never a secret. */
export interface SourceCheckResult {
  id: CloudCheckSource;
  label: string;
  status: "succeeded" | "failed" | "not-tested";
  detail?: string;
}

/** What the analyst asked to test. An empty `sources` means every source of the provider. */
export interface CloudCheckRequest {
  sources: CloudCheckSource[];
  /** AWS S3 source: the trail's bucket. Without it the S3 source is reported as not tested. */
  s3Bucket?: string;
  /** AWS S3 source: the key prefix the trail writes under. Default "AWSLogs/". */
  s3Prefix?: string;
}

export interface CloudCheckReport {
  provider: CloudProvider;
  results: SourceCheckResult[];
  /** The identity the cloud reported, when the provider tells it (AWS GetCallerIdentity). */
  signedInAs?: string;
  /** The fixed-form sentence: what succeeded, what failed, and that writes were not tested. */
  summary: string;
  checkedAt: string;
}

/** A source result built with its label. */
export function sourceResult(
  id: CloudCheckSource,
  status: SourceCheckResult["status"],
  detail?: string,
): SourceCheckResult {
  return { id, label: CHECK_SOURCE_LABELS[id], status, ...(detail ? { detail } : {}) };
}

/** Every call of a check gets this long before it is abandoned, so a dead proxy cannot hang it. */
export const CHECK_CALL_TIMEOUT_MS = 20_000;
