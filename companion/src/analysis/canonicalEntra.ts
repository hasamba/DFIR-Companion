// The envelope block an Entra privilege-path summary row carries (#931 item 1, second half —
// #973): the application the steps are joined through (by app id, never a name), the stages the
// export's records establish in order, each step's record locator, the window, and the export's
// own coverage the absence lines rest on. `basis` says the one thing every reader must keep: an
// action is CONSISTENT with a grant; the authorization a token carried is not in any record.
// Kept beside canonicalEvent.ts so the envelope schema stays within its size bound.

import { z } from "zod";

export const entraPathStepSchema = z.object({
  stage: z.enum(["credential", "grant", "sign-in", "action"]),
  time: z.string(),
  locator: z.string(),
  keyId: z.string().optional(),
  permission: z.string().optional(),
  /** sign-in: the credential key matched; action: the operation is consistent with a grant. */
  matched: z.boolean().optional(),
  initiatorIsApp: z.boolean().optional(),
});

const coverageSchema = z.object({
  records: z.number().int().nonnegative(),
  first: z.string(),
  last: z.string(),
});

export const entraPathBlockSchema = z.object({
  appId: z.string(),
  tenant: z.string().optional(),
  windowDays: z.number().int().positive(),
  stages: z.number().int().min(1).max(4),
  steps: z.array(entraPathStepSchema),
  outsideWindow: z.number().int().nonnegative(),
  otherEpisodes: z.number().int().nonnegative(),
  coverage: z.object({ signIns: coverageSchema.optional(), audits: coverageSchema.optional() }),
  basis: z.literal(
    "records of this export only; joined through the application id; consistency, not authorization",
  ),
});

export type EntraPathBlock = z.infer<typeof entraPathBlockSchema>;
export type EntraPathStep = z.infer<typeof entraPathStepSchema>;
