// The envelope block one MobSF Android static-analysis "permissions" dict entry carries (#932
// item 9, "932.15"): a manifest-declared REQUEST for a capability — never a claim it was granted
// by the user/OS, and never a claim it was ever actually invoked. Deliberately the
// requested-capability third only of the spec's own three-way ask (requested/granted/used); the
// granted/used cross-source correlation is a separate, larger follow-up. Kept beside
// canonicalEvent.ts so the envelope schema stays within its size bound (mirrors
// canonicalOlevbaFinding.ts's own sibling-file pattern, #932 item 7).

import { z } from "zod";
import { sampleHashSchema, MAX_PRODUCER_VERSION_LEN } from "./canonicalMalwareSample.js";

export const mobileRequestedPermissionTools = ["mobsf"] as const;
export type MobileRequestedPermissionTool = (typeof mobileRequestedPermissionTools)[number];

/** Real, confirmed `status` values, fetched live against MobSF's own dvm_permissions.py entries
 * plus manifest_utils.py's own "unknown" fallback for an unrecognized permission string. */
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
  "a manifest-declared REQUEST for a capability, never a claim it was granted by the user/OS or " +
  "ever actually invoked; the status names MobSF's own reported knowledge-base classification of " +
  "the permission's sensitivity, never a verdict on this specific app; requested-but-never-granted " +
  "and requested-but-never-used are both common and legitimate";

export const mobileRequestedPermissionBlockSchema = z.object({
  tool: z.enum(mobileRequestedPermissionTools),
  platform: z.literal("android"),
  permission: z.string().min(1).max(MAX_FIELD_LEN),
  permissionTruncated: z.boolean(),
  status: z.enum(mobilePermissionStatuses),
  /** The RAW status string MobSF reported, even when it didn't match a known value (normalized
   * to "unknown" above) — nothing is silently discarded, only the structured enum falls back. */
  rawStatus: z.string().max(MAX_FIELD_LEN),
  info: z.string().max(MAX_FIELD_LEN),
  permissionDescription: z.string().max(MAX_DESCRIPTION_LEN),
  packageName: z.string().max(MAX_FIELD_LEN),
  appName: z.string().max(MAX_FIELD_LEN),
  sampleHash: sampleHashSchema,
  reportFingerprint: z.string().length(64),
  producerVersion: z.string().max(MAX_PRODUCER_VERSION_LEN),
  mappingVersion: z.literal("mobile-requested-permission-v1"),
  basis: z.literal(MOBILE_REQUESTED_PERMISSION_BASIS),
});
export type MobileRequestedPermissionBlock = z.infer<typeof mobileRequestedPermissionBlockSchema>;
