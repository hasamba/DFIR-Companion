// The schema for a "mobile backup generation" record (#1132, 932.17's own mobile prerequisite).
// See RECOMMENDATION-1132.md for the full design rationale, including the 6 High findings a Codex
// adversarial design review round found in the first draft and how each was fixed.
//
// A sibling of #1108's own canonicalCollectionGeneration.ts, never a generalization of it: the
// evidence shape (installed-app presence, keyed by Bundle ID) has nothing in common with
// persistence's technique/path/value shape, and Codex's own review of #1128 was explicit that
// forcing one generic inventory schema across both domains would be premature. `generationOrderSchema`
// and `actorSchema` ARE reused unchanged — those two are genuinely domain-blind already.
//
// THE BINDING IS AN ATTESTATION, NEVER A VERIFICATION (Codex finding H1). A header check on two
// re-parsed TSVs can confirm each file's own ARTIFACT TYPE; it cannot prove both came from the
// same physical Info.plist. The record therefore requires an explicit `attestedSameBackup: true`
// from a human actor, and stores both full references (importSeq + artifactHash + originalName +
// importedAt) so the attestation's own basis is auditable, never assumed.

import { z } from "zod";
import { generationOrderSchema, actorSchema } from "./canonicalCollectionGeneration.js";

export const mobileBackupDomains = ["mobile-app-presence"] as const;
export type MobileBackupDomain = (typeof mobileBackupDomains)[number];

/** Device identity is EXTRACTED from the backup-info artifact's own Property/Property Value rows
 * (Serial Number, falling back to Unique Identifier) — never free-typed by the examiner (Codex
 * finding H3: the original draft called it "the examiner's own words" in one place and "extracted"
 * in another, two different trust models). The `kind` travels with the value so a Serial Number
 * and a Unique Identifier can never collide in the same string namespace, and a backup exposing
 * only one of the two is never silently assumed to match a backup exposing the other. */
export const deviceIdentityKinds = ["serial-number", "unique-identifier"] as const;
export type DeviceIdentityKind = (typeof deviceIdentityKinds)[number];
export const deviceIdentitySchema = z.object({
  kind: z.enum(deviceIdentityKinds),
  value: z.string().min(1),
});
export type DeviceIdentity = z.infer<typeof deviceIdentitySchema>;

export const mobileAppPresenceFactSchema = z.object({
  bundleId: z.string().min(1), // the stable identity — never reused across apps in one export
  itemName: z.string(),
  version: z.string(),
});
export type MobileAppPresenceFact = z.infer<typeof mobileAppPresenceFactSchema>;

/** One artifact reference an attestation names — its own importSeq/hash PLUS the original filename
 * and import time, so the attestation's own basis (which two uploads, by what names, when) is
 * fully auditable rather than reducible to two bare numbers (Codex finding H1). */
export const attestedArtifactRefSchema = z.object({
  importSeq: z.number().int().positive(),
  artifactHash: z.string().regex(/^[0-9a-f]{64}$/),
  originalName: z.string().min(1),
  importedAt: z.string().datetime({ offset: true }),
});
export type AttestedArtifactRef = z.infer<typeof attestedArtifactRefSchema>;

export const completenessStates = ["complete", "partial", "unknown"] as const;
export type CompletenessState = (typeof completenessStates)[number];

export const mobileBackupGenerationSchema = z
  .object({
    generationId: z.string().uuid(),
    deviceIdentity: deviceIdentitySchema,
    domain: z.enum(mobileBackupDomains),
    completenessState: z.enum(completenessStates),
    /** No known mobile-specific filter exists yet (unlike persistence's severity-floor/event-cap/
     * partial-hive) — kept as an open string array rather than inventing an enum with no real
     * member, per the design doc's own explicit call. */
    filtersApplied: z.array(z.string()).default([]),
    order: generationOrderSchema,
    /** Required, and only meaningful, when `order.kind === "declared"` — the examiner's own reason
     * the backup's real `Last Backup Date` could not drive `capturedAt` instead (Codex finding H3:
     * a single timestamp-authority rule, never a silent default). Checked in code, not by the
     * schema alone, since it is conditional on a sibling field. */
    dateUnavailableReason: z.string().min(1).optional(),
    backupInfoRef: attestedArtifactRefSchema,
    installedAppsRef: attestedArtifactRefSchema,
    /** The examiner's own explicit attestation that both references name the SAME physical
     * backup. The API layer rejects a request missing this or setting it false — it is typed as a
     * literal so a stored record can never silently mean anything else (Codex finding H1). */
    attestedSameBackup: z.literal(true),
    inventory: z.array(mobileAppPresenceFactSchema).min(1),
    checked: z.string().optional(),
    gaps: z.string().optional(),
    recordedBy: actorSchema,
    recordedAt: z.string().datetime({ offset: true }),
    revokedBy: actorSchema.optional(),
    revokedAt: z.string().datetime({ offset: true }).optional(),
  })
  .refine((g) => g.backupInfoRef.importSeq !== g.installedAppsRef.importSeq, {
    message: "backupInfoRef and installedAppsRef must name two different imports",
  })
  .refine((g) => g.order.kind !== "declared" || !!g.dateUnavailableReason, {
    message: "dateUnavailableReason is required when order.kind is 'declared'",
  });
export type MobileBackupGeneration = z.infer<typeof mobileBackupGenerationSchema>;

/** One generation's own eligibility for ANY comparison — mirrors #1108's own
 * `generationEligible()` exactly (same rule, same reasoning), defined here since this ledger's own
 * `CompletenessState` type, though identically shaped, is its own domain-scoped type. */
export function generationEligible(g: MobileBackupGeneration): boolean {
  return g.completenessState === "complete" && g.filtersApplied.length === 0;
}
