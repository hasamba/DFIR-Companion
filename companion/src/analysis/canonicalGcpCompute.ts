// The envelope block a GCP compute-lifecycle summary row carries (#931 item 8 second half, #1066):
// the instance the records are joined through (project, zone, instance name), the launch facts as
// the `instances.insert` request states them, every later recorded operation that names it, a
// metadata-replaced fact (presence only — content never read, the same discipline AWS's userData
// gets), a service-account-attachment fact reusing #1065's own decode, the calls recorded from
// that attached account while it was recorded as attached, the recorded facts the grade counts,
// and the upload's own coverage the absence lines rest on. Kept beside canonicalEvent.ts so the
// envelope schema stays within its size bound.
//
// Narrower than the AWS envelope by design. No attribution stronger than "recorded from the
// attached email" for the service-account session (#1066's own design-round-1 review — a GCP
// service-account email is not bound to one instance the way an AWS instance-role session ARN is;
// the same email may be attached elsewhere this upload cannot see). The firewall join (#1073) is
// deliberately narrow: only an insert/update rule naming NEITHER target tags NOR target service
// accounts (GCP's own documented "applies to every instance on the network" default) joins, by
// EXACT literal network-string match — never a `firewalls.patch` (a partial update whose absent
// fields this stateless decoder cannot read as "confirmed absent"), never a tag- or
// service-account-targeted rule (that correlation needs an instance-identity match this join does
// not attempt), and never a cross-project Shared-VPC match (a mismatched project token in the two
// records' own network strings simply does not join). The instance side only ever considers its
// FIRST network interface (#1066's own launch capture); a second interface on a different network
// is not covered.

import { z } from "zod";

const cited = z.object({ time: z.string(), locator: z.string() });

export const gcpComputeLaunchSchema = z.object({
  time: z.string(),
  locators: z.array(z.string()).max(8),
  by: z.string(),
  machineType: z.string().optional(),
  sourceImage: z.string().optional(),
  network: z.string().optional(),
  subnetwork: z.string().optional(),
  /** Metadata keys the launch request named — never values. */
  metadataKeys: z.array(z.string()).max(16),
});

export const gcpComputeOperationKinds = ["start", "stop", "delete", "metadata-replaced"] as const;

export const gcpComputeOperationSchema = z.object({
  kind: z.enum(gcpComputeOperationKinds),
  /** The methodName, as recorded. */
  call: z.string(),
  time: z.string(),
  locator: z.string(),
  by: z.string(),
});

/** One "this email was the instance's recorded service account" statement — open-ended until closed. */
export const gcpComputeAttachmentSchema = z.object({
  email: z.string(),
  from: z.string(),
  /** Absent while the interval is still open at the end of this upload's records. */
  to: z.string().optional(),
  locator: z.string(),
});

export const gcpComputeSessionSchema = z.object({
  email: z.string(),
  /** The attachment interval's own start time — disambiguates two sessions for a re-attached email. */
  attachmentFrom: z.string(),
  records: z.number().int().nonnegative(),
  first: cited,
  last: cited,
  /** A bounded, earliest-kept citation list of the calls this session tallies. */
  cited: z.array(z.object({ call: z.string(), time: z.string(), locator: z.string() })).max(8),
});

export const gcpComputeFactKinds = [
  "metadata-replaced",
  "service-account-attached",
  "session-privileged-change",
  "any-address-firewall-rule",
] as const;

export const gcpComputeBlockSchema = z.object({
  instanceName: z.string(),
  project: z.string(),
  zone: z.string(),
  launch: gcpComputeLaunchSchema.optional(),
  operations: z.array(gcpComputeOperationSchema).max(32),
  operationsBeyond: z.number().int().nonnegative(),
  attachments: z.array(gcpComputeAttachmentSchema).max(16),
  attachmentsBeyond: z.number().int().nonnegative(),
  sessions: z.array(gcpComputeSessionSchema).max(8),
  /** Distinct attachment intervals with recorded calls beyond the tracked bound — counted, never dropped silently. */
  sessionsBeyond: z.number().int().nonnegative(),
  attempts: z.object({ notSucceeded: z.number().int().nonnegative() }),
  /** The distinct recorded-fact kinds the grade counts: two or more → High, one → Medium, none → Low. */
  facts: z.array(z.enum(gcpComputeFactKinds)),
  notCited: z.number().int().nonnegative(),
  coverage: z.object({ records: z.number().int().nonnegative(), first: z.string(), last: z.string() }),
  basis: z.literal(
    "records of this upload only; joined through the instance's resource name; what ran on the instance and its network egress are not in this case's GCP Cloud Audit Log exports; the firewall join covers only the network-wide (no target tags or service accounts) case, by exact network-string match on the instance's first network interface, and an attached email is never claimed unique to this instance — see #1073, #1077, #1078",
  ),
});

export type GcpComputeBlock = z.infer<typeof gcpComputeBlockSchema>;
export type GcpComputeLaunch = z.infer<typeof gcpComputeLaunchSchema>;
export type GcpComputeOperation = z.infer<typeof gcpComputeOperationSchema>;
export type GcpComputeAttachment = z.infer<typeof gcpComputeAttachmentSchema>;
export type GcpComputeSession = z.infer<typeof gcpComputeSessionSchema>;
export type GcpComputeFact = (typeof gcpComputeFactKinds)[number];
export type GcpComputeCited = z.infer<typeof cited>;
