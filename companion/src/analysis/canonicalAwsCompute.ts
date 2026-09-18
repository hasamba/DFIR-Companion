// The envelope block an AWS compute-lifecycle summary row carries (#931 item 8, awsCompute.ts):
// the instance the records are joined through (account, region, instance id), the launch facts
// as the RunInstances response states them, every later record that names the instance (typed
// kinds and allow-listed scalars — never a request or response object, never a startup
// configuration's content), the ingress rules recorded on the groups the instance holds, the
// address associations its records name, the calls signed with its own instance-role credentials,
// the remote-access requests to it, the recorded facts the grade counts, and the upload's own
// coverage the absence lines rest on. Kept beside canonicalEvent.ts so the envelope schema stays
// within its size bound.

import { z } from "zod";
import { awsLineageShapeSchema, awsLineageSourceSchema } from "./canonicalAwsLineage.js";

const cited = z.object({ time: z.string(), locator: z.string() });

/** An EC2 instance id as AWS writes it; shared so every pass that keys on one tests the same shape. */
export const INSTANCE_ID = /^i-[0-9a-f]{8,17}$/i;

export const awsComputeLaunchSchema = z.object({
  time: z.string(),
  /** Every replica record of the launch is cited. */
  locators: z.array(z.string()),
  /** The signing principal — the record's own identity words. */
  by: z.string(),
  credentialId: z.string().optional(),
  address: z.string().optional(),
  agent: z.string().optional(),
  /** `userIdentity.invokedBy` — an AWS service made the request; said literally, never "on behalf of". */
  invokedBy: z.string().optional(),
  /** `responseElements.requesterId` — a distinct requester field, rendered literally. */
  requesterId: z.string().optional(),
  image: z.string().optional(),
  type: z.string().optional(),
  keyName: z.string().optional(),
  profile: z.string().optional(),
  groups: z.array(z.object({ id: z.string(), name: z.string().optional() })),
  subnet: z.string().optional(),
  vpc: z.string().optional(),
  privateAddress: z.string().optional(),
  availabilityZone: z.string().optional(),
  /** Whether the request carried a startup configuration — a launch template can carry one the record does not expose, so absence is never "none". */
  startupConfig: z.enum(["supplied", "removed-by-cloudtrail", "not-in-record"]),
});

export const awsComputeLifecycleKinds = [
  "start",
  "stop",
  "reboot",
  "terminate",
  "startup-config-replaced",
  "groups-set",
  "termination-protection",
  "type-changed",
  "attribute-modified",
  "profile-associated",
  "profile-replaced",
  "profile-disassociated",
] as const;

export const awsComputeLifecycleSchema = z.object({
  kind: z.enum(awsComputeLifecycleKinds),
  /** The eventName, as recorded. */
  call: z.string(),
  time: z.string(),
  locator: z.string(),
  by: z.string(),
  /** The record's own state transition (StopInstances: running → stopping); absent on a request-only call. */
  transition: z.object({ from: z.string(), to: z.string() }).optional(),
  /** The instance profile named (an ARN or a name) — never called a role. */
  profile: z.string().optional(),
  /** The association state the response returned (associating / disassociating). */
  associationState: z.string().optional(),
  /** The group ids a groups-set call named. */
  groups: z.array(z.string()).optional(),
  /** The attribute name of a generic ModifyInstanceAttribute — from the allow-list only. */
  attribute: z.string().optional(),
  /** Strictly ordered against the launch; "same" at an equal recorded time; absent without a launch. */
  order: z.enum(["before", "after", "same"]).optional(),
});

export const awsComputeRuleSchema = z.object({
  groupId: z.string(),
  action: z.enum(["authorize", "revoke"]),
  /** The rule as recorded: protocol, ports, source. */
  protocol: z.string(),
  ports: z.string(),
  source: z.string(),
  /** The source is 0.0.0.0/0 or ::/0. */
  anySource: z.boolean(),
  time: z.string(),
  locator: z.string(),
  by: z.string(),
  order: z.enum(["before", "after", "same"]).optional(),
});

export const awsComputeAddressSchema = z.object({
  action: z.enum(["associate", "disassociate"]),
  allocationId: z.string().optional(),
  address: z.string().optional(),
  associationId: z.string().optional(),
  time: z.string(),
  locator: z.string(),
  by: z.string(),
});

export const awsComputeRemoteSchema = z.object({
  /** `ssm SendCommand` / `ssm StartSession` / `ec2-instance-connect SendSSHPublicKey`. */
  call: z.string(),
  document: z.string().optional(),
  time: z.string(),
  locator: z.string(),
  by: z.string(),
});

export const awsComputeFactKinds = [
  "startup-config-replaced",
  "profile-changed",
  "any-address-rule",
  "session-privileged-change",
  "session-remote-execution",
  "session-enumeration",
  "remote-access-request",
] as const;

export const awsComputeBlockSchema = z.object({
  instanceId: z.string(),
  account: z.string(),
  region: z.string(),
  launch: awsComputeLaunchSchema.optional(),
  lifecycle: z.array(awsComputeLifecycleSchema),
  /** Lifecycle records past the retained earliest and latest. */
  lifecycleBeyond: z.number().int().nonnegative(),
  rules: z.array(awsComputeRuleSchema),
  rulesBeyond: z.number().int().nonnegative(),
  addresses: z.array(awsComputeAddressSchema),
  session: z
    .object({
      records: z.number().int().nonnegative(),
      first: cited,
      last: cited,
      sources: z.array(awsLineageSourceSchema),
      sourcesBeyond: z.number().int().nonnegative(),
      shapes: z.array(awsLineageShapeSchema.omit({ afterSecondSource: true })),
      attempts: z.number().int().nonnegative(),
    })
    .optional(),
  remote: z.array(awsComputeRemoteSchema),
  remoteBeyond: z.number().int().nonnegative(),
  attempts: z.object({ denied: z.number().int().nonnegative(), failed: z.number().int().nonnegative() }),
  /** The distinct recorded-fact kinds the grade counts: two or more → High, one → Medium, none → Low. */
  facts: z.array(z.enum(awsComputeFactKinds)),
  terminated: z.boolean(),
  /** How many contributing records are not individually cited in evidence.rawRecords. */
  notCited: z.number().int().nonnegative(),
  coverage: z.object({ records: z.number().int().nonnegative(), first: z.string(), last: z.string() }),
  basis: z.literal(
    "records of this upload only; joined through the instance id; what ran on the instance and its network egress are not in CloudTrail",
  ),
});

export type AwsComputeBlock = z.infer<typeof awsComputeBlockSchema>;
export type AwsComputeLaunch = z.infer<typeof awsComputeLaunchSchema>;
export type AwsComputeLifecycle = z.infer<typeof awsComputeLifecycleSchema>;
export type AwsComputeRule = z.infer<typeof awsComputeRuleSchema>;
export type AwsComputeAddress = z.infer<typeof awsComputeAddressSchema>;
export type AwsComputeRemote = z.infer<typeof awsComputeRemoteSchema>;
export type AwsComputeFact = (typeof awsComputeFactKinds)[number];
