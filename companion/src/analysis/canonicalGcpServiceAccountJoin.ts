// The envelope block a GCP per-service-account join row carries (#931 item 12, second half —
// #1065): every fact this export states about one service account, joined by unique id when
// present, else email — access granted to it as a member, authority granted over it as a
// resource, credentials minted, keys created, workloads it is attached to, and calls
// authenticated as it. A parent-scope binding is counted on the account's own project only, never
// attributed to it. No effective permission is ever emitted. Kept beside canonicalEvent.ts so the
// envelope schema stays within its size bound.

import { z } from "zod";
import { gcpProjectRefSchema } from "./canonicalGcp.js";

const cited = z.object({ time: z.string(), locator: z.string() });

export const gcpSaBindingFactSchema = cited.extend({
  role: z.string(),
  member: z.string().optional(),
  action: z.string(),
  denied: z.boolean(),
});

export const gcpSaCredentialFactSchema = cited.extend({ fact: z.string(), denied: z.boolean() });

export const gcpSaKeyFactSchema = cited.extend({ action: z.string(), denied: z.boolean() });

export const gcpSaAttachmentFactSchema = cited.extend({
  workloadKind: z.string(),
  workloadVersion: z.string().optional(),
  workloadName: z.string().optional(),
  identityRole: z.string(),
});

export const gcpSaCallFactSchema = cited.extend({
  keyName: z.string().optional(),
  /** The record's own delegation chain, whole — never a single "impersonator". */
  delegation: z.array(z.string()),
});

export const gcpServiceAccountJoinBlockSchema = z.object({
  /** The uniqueId this row is keyed on when the export ever states one; the email otherwise. */
  identity: z.string(),
  emails: z.array(z.string()),
  uniqueIds: z.array(z.string()),
  homeProject: gcpProjectRefSchema.optional(),
  bindingsAsMember: z.array(gcpSaBindingFactSchema),
  bindingsAsMemberBeyond: z.number().int().nonnegative(),
  bindingsAsResource: z.array(gcpSaBindingFactSchema),
  bindingsAsResourceBeyond: z.number().int().nonnegative(),
  /** Parent-scope bindings recorded on this account's OWN project only; never on a folder or org (ancestry is not derivable from these records), and never individually joined. */
  parentScopeCount: z.number().int().nonnegative(),
  credentials: z.array(gcpSaCredentialFactSchema),
  credentialsBeyond: z.number().int().nonnegative(),
  keys: z.array(gcpSaKeyFactSchema),
  keysBeyond: z.number().int().nonnegative(),
  attachments: z.array(gcpSaAttachmentFactSchema),
  attachmentsBeyond: z.number().int().nonnegative(),
  callsAsPrincipal: z.array(gcpSaCallFactSchema),
  callsAsPrincipalBeyond: z.number().int().nonnegative(),
  projectsTouched: z.array(gcpProjectRefSchema),
  /** The control-grant -> later-use pair that upgraded the grade, when one exists. */
  upgrade: z.object({ controlLocator: z.string(), useLocator: z.string() }).optional(),
  /** 3 = a credential/key/attachment fact; 2 = a binding fact only; 1 = calls as principal only. */
  admissionTier: z.union([z.literal(1), z.literal(2), z.literal(3)]),
  coverage: z.object({ records: z.number().int().nonnegative(), first: z.string(), last: z.string() }),
  basis: z.literal(
    "records of this export only; joined by unique id when present, else email; no effective permission is evaluated; a parent-scope binding is counted on this account's own project only, never attributed",
  ),
});

export type GcpSaBindingFact = z.infer<typeof gcpSaBindingFactSchema>;
export type GcpSaCredentialFact = z.infer<typeof gcpSaCredentialFactSchema>;
export type GcpSaKeyFact = z.infer<typeof gcpSaKeyFactSchema>;
export type GcpSaAttachmentFact = z.infer<typeof gcpSaAttachmentFactSchema>;
export type GcpSaCallFact = z.infer<typeof gcpSaCallFactSchema>;
export type GcpServiceAccountJoinBlock = z.infer<typeof gcpServiceAccountJoinBlockSchema>;
