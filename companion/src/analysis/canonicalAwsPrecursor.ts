// The envelope block a CloudTrail row carries when it is one half of the S3 ransomware-precursor
// join (#2542, #2563): a successful privileged change by an access key (a policy grant to the caller
// itself, or CreateAccessKey), or a bucket recovery check (GetBucketVersioning,
// GetBucketObjectLockConfiguration, PutBucketVersioning set to Suspended). Stamped by the importer
// from the raw record, so the case-wide join (cloudPrecursorMerge.ts) never re-reads a description:
// the policy and user names in it are attacker-controlled. Kept beside canonicalEvent.ts so the
// envelope schema stays within its size bound.

import { z } from "zod";

export const awsPrecursorBlockSchema = z.object({
  role: z.enum(["change", "check"]),
  /** The call as the join names it, e.g. "iam CreateAccessKey" or "s3 PutBucketVersioning (Suspended)". */
  call: z.string().max(160),
});

export type AwsPrecursorBlock = z.infer<typeof awsPrecursorBlockSchema>;
