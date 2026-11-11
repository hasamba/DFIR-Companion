// Two CloudTrail grading rules that only LOWER the generic floors, never a table or decoder grade
// (#2542). Kept beside the importer, which is at its size bound.
//
// 1. An AWS service acting on its own (`userIdentity.type: AWSService` — written by AWS, not by the
//    caller) is not graded by the generic floors: an unknown write is Info rather than Low, and a
//    failed call is not a "probe". Log delivery retrying a PutObject into a bucket that refuses it
//    is the service's plumbing, not an attacker testing permissions; on one public lab it was ten
//    thousand Medium rows. The importer's own table, its decoders (IAM, SSM, logging, issuance,
//    exposure) and the bundled rules still grade a service call — only the floors are skipped.
//    `Unknown` is NOT included: it is the absence of an identification, not a positive one.
//
// 2. A READ-ONLY call answered "not found / not configured" is an answer, not a probe:
//    `NoSuchBucketPolicy`, `ObjectLockConfigurationNotFoundError`, `NoSuchWebsiteConfiguration`,
//    `DashboardNotFoundError`, `InsightNotEnabledException`. A console page checks every one of them
//    on every bucket it opens. A read-only denial (AccessDenied, UnauthorizedOperation) and ANY
//    failed mutating call are still raised.

import type { Severity } from "./stateTypes.js";

/** The identity kind AWS writes for a service acting on its own behalf. */
const AWS_SERVICE_KIND = "AWSService";

/**
 * Error codes that positively say the thing asked about does not exist or is not enabled. Matched
 * as a whole code: `NoSuch…`, `…NotFound…` (NotFound, NotFoundException, NotFoundError,
 * ConfigurationNotFoundError), `…NotEnabled…`.
 */
const NOT_FOUND_CODE = /^NoSuch|NotFound|NotEnabled/i;

/** The generic floor for a call no table entry grades: Info for a read or for an AWS service, else Low. */
export function genericFloor(readOnly: boolean, identityKind: string): Severity {
  return readOnly || identityKind === AWS_SERVICE_KIND ? "Info" : "Low";
}

/** True when a read-only call's error code is a positive "not found / not configured" answer. */
export function isNotFoundRead(errorCode: string, readOnly: boolean): boolean {
  return readOnly && NOT_FOUND_CODE.test(errorCode.trim());
}

/**
 * Whether a failed call earns the importer's "probe" bump to Medium: never for an AWS service acting
 * on its own, never for a read-only not-found answer; otherwise whenever there is an error code.
 */
export function failedCallIsProbe(errorCode: string, readOnly: boolean, identityKind: string): boolean {
  if (!errorCode.trim()) return false;
  if (identityKind === AWS_SERVICE_KIND) return false;
  return !isNotFoundRead(errorCode, readOnly);
}
