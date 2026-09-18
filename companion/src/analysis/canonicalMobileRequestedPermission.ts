// The envelope block one MobSF static-analysis "permissions" dict entry carries (#932 item 9,
// "932.15", widened to iOS by #1136): a declared REQUEST for a capability — never a claim it was
// granted by the user/OS, and never a claim it was ever actually invoked. Deliberately the
// requested-capability third only of the spec's own three-way ask (requested/granted/used); the
// Android granted/used cross-source correlation needs a new ALEAPP artifact this codebase's
// registry doesn't carry yet (AppOps/usagestats — see #1136's own landed-comment disposition).
// Kept beside canonicalEvent.ts so the envelope schema stays within its size bound (mirrors
// canonicalOlevbaFinding.ts's own sibling-file pattern, #932 item 7).

import { z } from "zod";
import { sampleHashSchema, MAX_PRODUCER_VERSION_LEN } from "./canonicalMalwareSample.js";

export const mobileRequestedPermissionTools = ["mobsf"] as const;
export type MobileRequestedPermissionTool = (typeof mobileRequestedPermissionTools)[number];

export const mobileRequestedPermissionPlatforms = ["android", "ios"] as const;
export type MobileRequestedPermissionPlatform = (typeof mobileRequestedPermissionPlatforms)[number];

/** Real, confirmed `status` values. Android values fetched live against MobSF's own
 * dvm_permissions.py entries plus manifest_utils.py's own "unknown" fallback for an unrecognized
 * permission string. iOS's own check_permissions() (kb/permission_analysis.py) reports the same
 * two base risk tiers, "normal" and "dangerous" — both already present below, so no enum change
 * was needed to add iOS; "signature"/"signatureOrSystem"/"internal" are Android-signature-scheme
 * concepts iOS will simply never emit. */
export const mobilePermissionStatuses = [
  "dangerous",
  "normal",
  "signature",
  "signatureOrSystem",
  "internal",
  "unknown",
] as const;
export type MobilePermissionStatus = (typeof mobilePermissionStatuses)[number];

export const MAX_FIELD_LEN = 300;
export const MAX_DESCRIPTION_LEN = 600;

export const MOBILE_REQUESTED_PERMISSION_BASIS =
  "a declared REQUEST for a capability, never a claim it was granted by the user/OS or ever " +
  "actually invoked; the status names MobSF's own reported knowledge-base classification of the " +
  "permission's sensitivity, never a verdict on this specific app; requested-but-never-granted " +
  "and requested-but-never-used are both common and legitimate";

export const mobileRequestedPermissionBlockSchema = z.object({
  tool: z.enum(mobileRequestedPermissionTools),
  platform: z.enum(mobileRequestedPermissionPlatforms),
  permission: z.string().min(1).max(MAX_FIELD_LEN),
  permissionTruncated: z.boolean(),
  status: z.enum(mobilePermissionStatuses),
  /** The RAW status string MobSF reported, even when it didn't match a known value (normalized
   * to "unknown" above) — nothing is silently discarded, only the structured enum falls back. */
  rawStatus: z.string().max(MAX_FIELD_LEN),
  info: z.string().max(MAX_FIELD_LEN),
  permissionDescription: z.string().max(MAX_DESCRIPTION_LEN),
  /** An Android package name for an android row, an iOS bundle id for an ios row — a bundle id is
   * the direct iOS analog of a package name (both are the app's own stable, dotted reverse-DNS
   * identifier), so this field is deliberately not split into two near-duplicate identifiers. */
  packageName: z.string().max(MAX_FIELD_LEN),
  appName: z.string().max(MAX_FIELD_LEN),
  sampleHash: sampleHashSchema,
  reportFingerprint: z.string().length(64),
  producerVersion: z.string().max(MAX_PRODUCER_VERSION_LEN),
  /** Bumped from v1 (Android-only, "manifest-declared" wording) to v2 when #1136 widened this
   * envelope to iOS — no consumer anywhere branches on this string today (verified), the bump is
   * purely an honest version marker for any future consumer. */
  mappingVersion: z.literal("mobile-requested-permission-v2"),
  basis: z.literal(MOBILE_REQUESTED_PERMISSION_BASIS),
});
export type MobileRequestedPermissionBlock = z.infer<typeof mobileRequestedPermissionBlockSchema>;
