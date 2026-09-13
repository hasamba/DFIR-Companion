// The envelope block an AWS credential-lineage summary row carries (#931 item 5, chain half —
// #979): the credential the records are joined through (the access key id, never a session or
// role name), the account that owns it, the issuance that minted it when one record of the upload
// exposes the key, every source the key was used from with the first use per source, the shapes
// beside the uses (enumeration, a privileged change, remote execution — exact calls, successful
// only), the chaining to other keys, and the upload's own coverage the absence line rests on.
// Kept beside canonicalEvent.ts so the envelope schema stays within its size bound.

import { z } from "zod";

const cited = z.object({ time: z.string(), locator: z.string() });

export const awsLineageIssuanceSchema = z.object({
  action: z.string(),
  time: z.string(),
  locator: z.string(),
  role: z.string().optional(),
  sessionName: z.string().optional(),
  sourceIdentity: z.string().optional(),
  mfa: z.string().optional(),
  /** Who called the issuance — the record's own identity words. */
  by: z.string().optional(),
});

export const awsLineageSourceSchema = z.object({
  address: z.string(),
  agent: z.string(),
  firstUse: cited,
  records: z.number().int().nonnegative(),
});

export const awsLineageShapeSchema = z.object({
  kind: z.enum(["enumeration", "privileged-change", "remote-execution"]),
  time: z.string(),
  locator: z.string(),
  call: z.string(),
  /** True when the shape's record follows the first use from a second source. */
  afterSecondSource: z.boolean(),
});

export const awsLineageBlockSchema = z.object({
  credentialId: z.string(),
  account: z.string().optional(),
  issuance: awsLineageIssuanceSchema.optional(),
  /** The workload the records say delivered the credential — "EC2 instance role" / the inScopeOf issuer — or "". */
  workload: z.string(),
  uses: z.object({ records: z.number().int().nonnegative(), first: cited, last: cited }),
  sources: z.array(awsLineageSourceSchema),
  sourcesBeyond: z.number().int().nonnegative(),
  shapes: z.array(awsLineageShapeSchema),
  attempts: z.number().int().nonnegative(),
  chained: z.array(
    z.object({ credentialId: z.string(), direction: z.enum(["issued", "issued-from"]), locator: z.string() }),
  ),
  /** How many contributing records are not individually cited in evidence.rawRecords. */
  notCited: z.number().int().nonnegative(),
  coverage: z.object({ records: z.number().int().nonnegative(), first: z.string(), last: z.string() }),
  basis: z.literal(
    "records of this upload only; joined through the access key id; the workload's addresses are not in this evidence",
  ),
});

export type AwsLineageBlock = z.infer<typeof awsLineageBlockSchema>;
export type AwsLineageShape = z.infer<typeof awsLineageShapeSchema>;
