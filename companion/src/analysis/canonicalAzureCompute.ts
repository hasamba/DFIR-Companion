// The envelope block an Azure compute-lifecycle summary row carries (#931 item 8 second half,
// #1066): the VM the records are joined through (subscription, resource group, VM name), the
// launch/update facts as the `virtualMachines/write` request body states them, every later
// recorded operation that names it (typed kinds and allow-listed scalars only — never a request
// body, never a startup script's content), the managed-identity assignment if one is recorded,
// the remote-access requests to it, an optional network-security-group observation (#1077), the
// recorded facts the grade counts, and the upload's own coverage the absence lines rest on. Kept
// beside canonicalEvent.ts so the envelope schema stays within its size bound.
//
// Narrower than the AWS envelope by design. The network-security-group join (#1077) covers only a
// direct NIC attachment or its subnet's own attachment, resolved AS OF the rule-write's own time
// (never the VM's launch time or the record's own present) — see this file's own basis sentence
// and RECOMMENDATION-1077.md for the full design.
//
// VM-scale-set (VMSS) members (#1078) get their OWN block, `azureVmssComputeBlockSchema` — a
// member's identity is a 4-tuple (subscription, resource group, set name, instance id), never the
// standalone 3-tuple above, and each row is one OBSERVED LIFECYCLE EPOCH (bounded at a successful
// delete), never a claim of one proven distinct physical machine — Uniform-mode instance ids are
// reused after deletion. Flexible-orchestration members (their own record carries
// `virtualMachineResourceId`, aliasing the same machine under the STANDALONE resource type above)
// are out of scope entirely — see RECOMMENDATION-1078.md's design-round-1 section.

import { z } from "zod";

export const azureComputeLaunchSchema = z.object({
  time: z.string(),
  locators: z.array(z.string()).max(8),
  /** The record's own caller identity, as recorded — never resolved further. */
  by: z.string(),
  address: z.string().optional(),
  vmSize: z.string().optional(),
  image: z.string().optional(),
  adminUsername: z.string().optional(),
  /** NIC resource ids the request body named — a fact only; no further join reads these. */
  networkInterfaces: z.array(z.string()).max(8),
  /** Whether the write recorded a managed identity — content (userAssignedIdentities) never read beyond presence. */
  identityAssigned: z.boolean(),
});

export const azureComputeOperationKinds = ["start", "deallocate", "delete"] as const;

export const azureComputeOperationSchema = z.object({
  kind: z.enum(azureComputeOperationKinds),
  /** The operationName, as recorded. */
  call: z.string(),
  time: z.string(),
  locator: z.string(),
  by: z.string(),
});

export const azureComputeRemoteSchema = z.object({
  call: z.string(),
  time: z.string(),
  locator: z.string(),
  by: z.string(),
});

export const azureComputeFactKinds = [
  "identity-assigned",
  "remote-access-request",
  "any-address-nsg-rule",
] as const;

/**
 * One network-security-group observation (#1077) — the earliest qualifying match only, per VM.
 * `path` states which of the two NSGs Azure evaluates for inbound traffic matched (never both at
 * once, and a match on one is never itself a reachability claim — the row's own wording says so).
 * `token` is the EXACT source category the rule named — kept distinct, never collapsed into one
 * generic "any source" phrase (Azure's `*`/`0.0.0.0/0`/`::/0`/`Internet` are four different things).
 */
export const azureNsgObservationSchema = z.object({
  time: z.string(),
  path: z.enum(["direct", "via-subnet"]),
  token: z.enum(["*", "0.0.0.0/0", "::/0", "internet"]),
  nsgId: z.string(),
  ruleLocator: z.string(),
  nicId: z.string(),
  nicLocator: z.string(),
  subnetId: z.string().optional(),
  subnetLocator: z.string().optional(),
});

export const azureComputeBlockSchema = z.object({
  vmName: z.string(),
  subscriptionId: z.string(),
  resourceGroup: z.string(),
  launch: azureComputeLaunchSchema.optional(),
  operations: z.array(azureComputeOperationSchema).max(32),
  operationsBeyond: z.number().int().nonnegative(),
  remote: z.array(azureComputeRemoteSchema).max(8),
  remoteBeyond: z.number().int().nonnegative(),
  nsgObservation: azureNsgObservationSchema.optional(),
  attempts: z.object({ notSucceeded: z.number().int().nonnegative() }),
  /** The distinct recorded-fact kinds the grade counts: two or more → High, one → Medium, none → Low. */
  facts: z.array(z.enum(azureComputeFactKinds)),
  notCited: z.number().int().nonnegative(),
  coverage: z.object({ records: z.number().int().nonnegative(), first: z.string(), last: z.string() }),
  basis: z.literal(
    "records of this upload only; joined through the VM's resource id; what ran on the VM and its network egress are not in this case's Azure Activity Log exports; the network-security-group join covers only a direct NIC attachment or its subnet's own attachment, resolved as of the rule-write's own time, matched by exact resourceId — a match on one of the two NSGs Azure evaluates never by itself establishes that traffic reaches the VM — see #1077, #1078",
  ),
});

export type AzureComputeBlock = z.infer<typeof azureComputeBlockSchema>;
export type AzureComputeLaunch = z.infer<typeof azureComputeLaunchSchema>;
export type AzureComputeOperation = z.infer<typeof azureComputeOperationSchema>;
export type AzureComputeRemote = z.infer<typeof azureComputeRemoteSchema>;
export type AzureComputeFact = (typeof azureComputeFactKinds)[number];
export type AzureNsgObservation = z.infer<typeof azureNsgObservationSchema>;

// ───────────────────────────── #1078: VM scale-set (VMSS) members ─────────────────────────────

export const azureVmssComputeFactKinds = ["identity-assigned", "remote-access-request"] as const;

export const azureVmssComputeBlockSchema = z.object({
  instanceId: z.string(),
  subscriptionId: z.string(),
  resourceGroup: z.string(),
  setName: z.string(),
  /** 1-based — which OBSERVED lifecycle epoch this row is, never a claim of a proven physical
   * generation count (#1078, design-round-1 finding H1). */
  epoch: z.number().int().positive(),
  launch: azureComputeLaunchSchema.optional(),
  operations: z.array(azureComputeOperationSchema).max(32),
  operationsBeyond: z.number().int().nonnegative(),
  remote: z.array(azureComputeRemoteSchema).max(8),
  remoteBeyond: z.number().int().nonnegative(),
  attempts: z.object({ notSucceeded: z.number().int().nonnegative() }),
  facts: z.array(z.enum(azureVmssComputeFactKinds)),
  notCited: z.number().int().nonnegative(),
  coverage: z.object({ records: z.number().int().nonnegative(), first: z.string(), last: z.string() }),
  basis: z.literal(
    "records of this upload only; joined through the VMSS member's resource id (subscription, resource group, scale-set name, instance id); what ran on the member and its network egress are not in this case's Azure Activity Log exports; Flexible-orchestration members (identified by their own record's virtualMachineResourceId field) are out of scope — only Uniform-mode members are tracked; per-member operations coverage is opportunistic, and an absent member row is never evidence that no scale-set activity occurred; each row is one OBSERVED lifecycle epoch, bounded at a successful delete, never a claim of one proven distinct physical machine — see #1078",
  ),
});

export type AzureVmssComputeBlock = z.infer<typeof azureVmssComputeBlockSchema>;
export type AzureVmssComputeFact = (typeof azureVmssComputeFactKinds)[number];
