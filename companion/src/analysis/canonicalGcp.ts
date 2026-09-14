// The envelope block a GCP Cloud Audit Log row carries (#931 item 12, record half): the
// principal as the record states it (typed only by a documented service-account address), the
// delegation chain whole and in order, the key the credentials derived from, the typed projects,
// and — when the record is one — the IAM binding delta as Google wrote it, the IAM Credentials
// fact, or the service-account key lifecycle step. Every capability is nominal. Kept beside
// canonicalEvent.ts so the envelope schema stays within its size bound.

import { z } from "zod";

export const gcpProjectRefSchema = z.object({
  /** `projects` / `folders` / `organizations` / `billingAccounts` — the namespace the id sits in. */
  namespace: z.string(),
  /** An id (letters and dashes) or a number — never compared across kinds. */
  kind: z.enum(["id", "number"]),
  value: z.string(),
});

export const gcpPrincipalSchema = z.object({
  email: z.string().optional(),
  /** Typed only by a documented address shape; anything else is user-or-unknown. */
  kind: z.enum(["service-account", "service-agent", "user-or-unknown", "none"]),
  homeProject: gcpProjectRefSchema.optional(),
  subject: z
    .object({
      value: z.string(),
      kind: z.enum(["principal", "principal-set", "service-account", "user", "opaque"]),
    })
    .optional(),
  /** `serviceAccountKeyName` — the key the credentials derived from; the holder is not identified. */
  keyName: z.string().optional(),
  userAgent: z.string().optional(),
});

export const gcpDelegationSchema = z.object({
  kind: z.enum(["first-party", "third-party", "subject"]),
  /** The first-party principal's email or the subject; a third-party entry has none. */
  value: z.string().optional(),
});

export const gcpBindingDirections = [
  "authority-over-service-account",
  "access-to-member",
  "parent-scope",
  "other-resource",
] as const;

export const gcpBindingSchema = z.object({
  action: z.string(),
  role: z.string(),
  member: z.string(),
  memberKind: z.enum([
    "user",
    "service-account",
    "group",
    "domain",
    "public",
    "deleted",
    "principal",
    "principal-set",
    "other",
  ]),
  resource: z.string(),
  resourceKind: z.enum(["service-account", "project", "folder", "organization", "bucket", "other"]),
  direction: z.enum(gcpBindingDirections),
  /** The documented permissions of a classified predefined role, as words; absent for a custom or unclassified role. */
  documented: z.string().optional(),
  roleClass: z.enum(["classified", "custom", "unclassified"]),
  condition: z.object({ title: z.string().optional(), expression: z.string().optional() }).optional(),
  /** Always true — no effective permission is ever emitted. */
  nominal: z.literal(true),
  /** The two delta copies (serviceData / metadata) of this record differ. */
  copiesDiffer: z.boolean(),
  /** Deltas of the record past the per-record cap, counted on the last row. */
  furtherDeltas: z.number().int().nonnegative(),
  denied: z.boolean(),
});

export const gcpCredentialFacts = [
  "access-token-generated",
  "id-token-generated",
  "blob-signed",
  "jwt-signed",
] as const;

export const gcpCredentialSchema = z.object({
  fact: z.enum(gcpCredentialFacts),
  serviceAccount: z.string().optional(),
  uniqueId: z.string().optional(),
  scopes: z.array(z.string()),
  delegates: z.array(z.string()),
  lifetime: z.string().optional(),
  audience: z.string().optional(),
  denied: z.boolean(),
});

export const gcpKeySchema = z.object({
  action: z.enum(["created", "uploaded", "deleted", "disabled", "enabled"]),
  name: z.string().optional(),
  serviceAccount: z.string().optional(),
  keyType: z.string().optional(),
  keyOrigin: z.string().optional(),
  denied: z.boolean(),
});

export const gcpBlockSchema = z.object({
  principal: gcpPrincipalSchema,
  delegation: z.array(gcpDelegationSchema),
  projects: z.object({
    log: gcpProjectRefSchema.optional(),
    resource: gcpProjectRefSchema.optional(),
    /** Said only for two ids or two numbers that differ. */
    differ: z.boolean(),
  }),
  binding: gcpBindingSchema.optional(),
  credential: gcpCredentialSchema.optional(),
  key: gcpKeySchema.optional(),
  basis: z.literal(
    "this record only; capabilities are the role's documented permissions, nominal; no effective permission is evaluated",
  ),
});

export type GcpBlock = z.infer<typeof gcpBlockSchema>;
export type GcpPrincipal = z.infer<typeof gcpPrincipalSchema>;
export type GcpProjectRef = z.infer<typeof gcpProjectRefSchema>;
export type GcpDelegation = z.infer<typeof gcpDelegationSchema>;
export type GcpBinding = z.infer<typeof gcpBindingSchema>;
export type GcpCredential = z.infer<typeof gcpCredentialSchema>;
export type GcpKey = z.infer<typeof gcpKeySchema>;
