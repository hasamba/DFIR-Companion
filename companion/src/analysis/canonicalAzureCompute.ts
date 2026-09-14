// The envelope block an Azure compute-lifecycle summary row carries (#931 item 8 second half,
// #1066): the VM the records are joined through (subscription, resource group, VM name), the
// launch/update facts as the `virtualMachines/write` request body states them, every later
// recorded operation that names it (typed kinds and allow-listed scalars only — never a request
// body, never a startup script's content), the managed-identity assignment if one is recorded,
// the remote-access requests to it, the recorded facts the grade counts, and the upload's own
// coverage the absence lines rest on. Kept beside canonicalEvent.ts so the envelope schema stays
// within its size bound.
//
// Narrower than the AWS envelope by design (#1066's own design-round-1 review): no network-rule
// join (Azure associates an NSG with a NIC/subnet, never directly with a VM, and this codebase
// does not track NIC/subnet resources — see #1073) and no VM-scale-set support (a VMSS member can
// be platform-created with no per-member write record — also #1073).

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

export const azureComputeFactKinds = ["identity-assigned", "remote-access-request"] as const;

export const azureComputeBlockSchema = z.object({
  vmName: z.string(),
  subscriptionId: z.string(),
  resourceGroup: z.string(),
  launch: azureComputeLaunchSchema.optional(),
  operations: z.array(azureComputeOperationSchema).max(32),
  operationsBeyond: z.number().int().nonnegative(),
  remote: z.array(azureComputeRemoteSchema).max(8),
  remoteBeyond: z.number().int().nonnegative(),
  attempts: z.object({ notSucceeded: z.number().int().nonnegative() }),
  /** The distinct recorded-fact kinds the grade counts: two or more → High, one → Medium, none → Low. */
  facts: z.array(z.enum(azureComputeFactKinds)),
  notCited: z.number().int().nonnegative(),
  coverage: z.object({ records: z.number().int().nonnegative(), first: z.string(), last: z.string() }),
  basis: z.literal(
    "records of this upload only; joined through the VM's resource id; what ran on the VM and its network egress are not in this case's Azure Activity Log exports; no network-security-group join is made — see #1073",
  ),
});

export type AzureComputeBlock = z.infer<typeof azureComputeBlockSchema>;
export type AzureComputeLaunch = z.infer<typeof azureComputeLaunchSchema>;
export type AzureComputeOperation = z.infer<typeof azureComputeOperationSchema>;
export type AzureComputeRemote = z.infer<typeof azureComputeRemoteSchema>;
export type AzureComputeFact = (typeof azureComputeFactKinds)[number];
