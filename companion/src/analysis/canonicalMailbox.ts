// The envelope block a mailbox-chain summary row carries (#931 item 2, chain half — #975): the
// mailbox the steps are joined through (by GUID or UPN, never a name), the join that grouped them
// (a session id, or actor + address inside a window — said, never assumed), the stages the export's
// records establish in order, each step's record locator and how it joined, the counts summed from
// the items the records LIST, and the export's own record counts the absence lines rest on.
// Kept beside canonicalEvent.ts so the envelope schema stays within its size bound.

import { z } from "zod";

export const mailboxChainStepSchema = z.object({
  stage: z.enum(["sign-in", "access", "persistence", "consequence"]),
  time: z.string(),
  locator: z.string(),
  session: z.string().optional(),
  /** How this record joined the chain. */
  joinedBy: z.enum(["session", "actor-address"]),
  itemsListed: z.number().int().nonnegative().optional(),
  operations: z.number().int().nonnegative().optional(),
});

const coverageSchema = z.object({
  records: z.number().int().nonnegative(),
  earliest: z.string(),
  latest: z.string(),
});

export const mailboxChainBlockSchema = z.object({
  mailbox: z.string(),
  mailboxIdKind: z.enum(["guid", "upn"]),
  tenant: z.string().optional(),
  join: z.object({ kind: z.enum(["session", "actor-address"]), key: z.string() }),
  windowHours: z.number().int().positive(),
  stages: z.number().int().min(1).max(4),
  steps: z.array(mailboxChainStepSchema),
  /** Items summed from the joined records that list them; operations stated by records that list none. */
  itemsListed: z.number().int().nonnegative(),
  operationsUnlisted: z.number().int().nonnegative(),
  /** Records that share the mailbox, actor and address with two or more sessions — joined to none. */
  ambiguous: z.number().int().nonnegative(),
  /** Records with no time, or no actor and address to join by — joined to none. */
  incomplete: z.number().int().nonnegative(),
  coverage: z.object({
    mailboxAudit: coverageSchema.optional(),
    logons: coverageSchema.optional(),
    signIns: coverageSchema.optional(),
  }),
  basis: z.literal(
    "records of this export only; joined through the mailbox and the stated join; configured, not delivered; accessed, not read",
  ),
});

export type MailboxChainBlock = z.infer<typeof mailboxChainBlockSchema>;
export type MailboxChainStep = z.infer<typeof mailboxChainStepSchema>;
