// The canonical `smb` block: one SMB operation as Suricata's `eve.json` logged it, plus the join
// state to its file's CREATE and to a matching `fileinfo` transfer record (importer half of #933
// item 4, #1085 / #1010).
//
// `outcome` states only what the CREATE's disposition and status TOGETHER establish —
// `FILE_OPEN`/`FILE_CREATE`/`FILE_OVERWRITE` each have exactly one success meaning; the `_IF`
// variants and `FILE_SUPERSEDE` do not (MS-SMB2's `CreateAction` would settle it, but Suricata's
// eve.json does not export that field), so those stay "requested-ambiguous" rather than a guess.

import { z } from "zod";

export const smbOutcomeSchema = z.enum([
  "opened-existing",
  "created-new",
  "overwritten-existing",
  "requested-ambiguous",
  "denied",
  "unknown",
]);

export const smbFileinfoJoinSchema = z.enum(["matched", "no match", "conflict", "not applicable"]);

export const smbBlockSchema = z.object({
  command: z.string(),
  status: z.string().optional(),
  statusCode: z.string().optional(),
  dialect: z.string().optional(),
  disposition: z.string().optional(),
  share: z.string().optional(),
  shareType: z.string().optional(),
  filename: z.string().optional(),
  access: z.string().optional(),
  fuid: z.string().optional(),
  sessionId: z.string().optional(),
  treeId: z.string().optional(),
  outcome: smbOutcomeSchema.optional(),
  fileinfoJoin: smbFileinfoJoinSchema,
  requestedSize: z.number().int().nonnegative().optional(),
  clientGuid: z.string().optional(),
  ntlmDomain: z.string().optional(),
  ntlmUser: z.string().optional(),
  krbRealm: z.string().optional(),
  krbService: z.string().optional(),
  /** Which chain-level fact backs this row's file identity — absent means "joined" (the default). */
  createJoinState: z
    .enum(["no fuid on this record", "no flow id on this record", "no matching file record in this upload"])
    .optional(),
  /** Operations on this file beyond SMB_BUCKET_MAX, kept but not individually shown. */
  operationsOmitted: z.number().int().nonnegative().optional(),
});

export type SmbBlock = z.infer<typeof smbBlockSchema>;
export type SmbOutcome = z.infer<typeof smbOutcomeSchema>;
export type SmbFileinfoJoin = z.infer<typeof smbFileinfoJoinSchema>;
