// The envelope blocks the Google Drive and Takeout rows carry (#931 item 11): a sharing change
// as the record states it — the permission direction along the documented chain, Google's own
// overall-visibility direction, the resulting visibility, the target as recorded; an access
// record's meaning; a Takeout record's stage and literal fields; and the per-job lifecycle
// joined by tenant + TAKEOUT_ID. Kept beside canonicalEvent.ts so the envelope schema stays
// within its size bound.

import { z } from "zod";

const cited = z.object({ time: z.string(), locator: z.string() });

export const driveDirections = ["broadens", "narrows", "same", "not-established"] as const;

export const driveSharingBlockSchema = z.object({
  docId: z.string().optional(),
  docTitle: z.string().optional(),
  docType: z.string().optional(),
  owner: z.string().optional(),
  ownerIsSharedDrive: z.boolean(),
  sharedDriveId: z.string().optional(),
  /** The permission / visibility direction along the documented chain — never from the event name. */
  direction: z.enum(driveDirections),
  from: z.string().optional(),
  to: z.string().optional(),
  /** `target_user` as recorded — may be a user, a group or a domain; the record does not say which. */
  target: z.string().optional(),
  /** `target_domain` of a link-scope change (`all` = every domain with visibility). */
  targetDomain: z.string().optional(),
  /** The recorded address domains of target and owner differ — a fact, not externality. */
  targetDomainDiffers: z.boolean(),
  /** Google's own `visibility_change`: external / internal / none — the only source of "newly external". */
  visibilityChange: z.string().optional(),
  /** The resulting `visibility`, quoted. */
  visibility: z.string().optional(),
  oldVisibility: z.string().optional(),
  membershipChange: z.string().optional(),
  addedRole: z.string().optional(),
  removedRole: z.string().optional(),
  primary: z.boolean(),
  /** A `*_hierarchy_reconciled` side effect of a parent-folder change — not an action on this item. */
  reconciled: z.boolean(),
  /** `originating_app_id` — the Google Cloud project number of the application that performed the action. */
  originatingApp: z.string().optional(),
  collaboratorAccount: z.boolean(),
});

export const driveAccessBlockSchema = z.object({
  docId: z.string().optional(),
  docTitle: z.string().optional(),
  docType: z.string().optional(),
  owner: z.string().optional(),
  /** What the event means, in the row's words (`download recorded`, `previewed`, `item content synced`, …). */
  meaning: z.string(),
  /** The `visibility` recorded at the time of the access. */
  visibility: z.string().optional(),
  originatingApp: z.string().optional(),
  apiMethod: z.string().optional(),
  actorIdentified: z.boolean(),
  primary: z.boolean(),
});

export const takeoutStages = ["requested", "scheduled", "completed", "downloaded"] as const;

export const takeoutBlockSchema = z.object({
  stage: z.enum(takeoutStages),
  jobId: z.string().optional(),
  userEmail: z.string().optional(),
  /** The literal `INITIATED_BY` value — not compared with the target user or the actor. */
  initiatedBy: z.string().optional(),
  products: z.array(z.string()),
  destination: z.string().optional(),
  status: z.string().optional(),
  /** Integer times as recorded — no epoch or unit is assumed. */
  startTime: z.string().optional(),
  completionTime: z.string().optional(),
  downloadTime: z.string().optional(),
  intervalValue: z.string().optional(),
  intervalUnits: z.string().optional(),
  scheduleExpiration: z.string().optional(),
});

export const takeoutLifecycleBlockSchema = z.object({
  jobId: z.string(),
  tenant: z.string(),
  userEmail: z.string().optional(),
  initiatedBy: z.string().optional(),
  products: z.array(z.string()),
  destination: z.string().optional(),
  requested: cited.extend({ by: z.string() }).optional(),
  completion: cited.extend({ status: z.string() }).optional(),
  downloaded: cited.extend({ by: z.string() }).optional(),
  /** Records of this job beyond the three retained stages (a repeated stage), counted. */
  furtherRecords: z.number().int().nonnegative(),
  coverage: z.object({ records: z.number().int().nonnegative(), first: z.string(), last: z.string() }),
  basis: z.literal(
    "records of this export only; joined through the tenant and the Takeout job id; delivery to the destination is not evidenced by these records",
  ),
});

export type DriveSharingBlock = z.infer<typeof driveSharingBlockSchema>;
export type DriveAccessBlock = z.infer<typeof driveAccessBlockSchema>;
export type TakeoutBlock = z.infer<typeof takeoutBlockSchema>;
export type TakeoutLifecycleBlock = z.infer<typeof takeoutLifecycleBlockSchema>;
export type DriveDirection = (typeof driveDirections)[number];
