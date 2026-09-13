// The envelope blocks a macOS quarantine row carries (#933 item 7). The database row's block
// (`quarantine`) is the record's own reading (quarantineRecord.ts, #1009) and, since #1037, what
// the same upload's file-attribute records establish about the local file — joined only through
// the event identifier. The attribute row's block (`quarantineAttribute`) is the file, the decoded
// `com.apple.quarantine` value, and what the same upload's database record says about the download
// event. Every join state names what the records do NOT establish; an empty attribute cell is never
// "no attribute". Kept beside canonicalEvent.ts so the envelope schema stays within its size bound.

import { z } from "zod";

const timeEncodingSchema = z.enum(["cocoa-seconds", "iso", "unix-seconds", "unix-ms", "unreadable"]);

/** What the upload's attribute records establish about the database record's local file. */
export const quarantineLocalFileSchema = z.union([
  z.literal("not in this record"),
  z.object({
    state: z.literal("joined"),
    paths: z.array(z.string()),
    count: z.number().int().nonnegative(),
    atLeast: z.boolean().optional(),
  }),
  z.object({ state: z.literal("no attribute record carries this identifier in this upload") }),
  z.object({ state: z.literal("database records with this identifier disagree — not joined") }),
  z.object({ state: z.literal("the file carries two attribute values — not joined") }),
  z.object({ state: z.literal("host not established — not joined") }),
]);

export const quarantineBlockSchema = z.object({
  kind: z.string(),
  typeNumber: z.number().int().nonnegative().optional(),
  typeRaw: z.string().optional(),
  agent: z.string().optional(),
  bundleId: z.string().optional(),
  dataUrl: z.string().optional(),
  originUrl: z.string().optional(),
  originTitle: z.string().optional(),
  originAliasDigest: z.string().optional(),
  senderName: z.string().optional(),
  senderAddress: z.string().optional(),
  eventId: z.string().optional(),
  eventIdRaw: z.string().optional(),
  timeEncoding: timeEncodingSchema,
  timeRaw: z.string().optional(),
  urlIndicator: z.string().optional(),
  localFile: quarantineLocalFileSchema,
  /** The host column the record carries, that none did, or that two disagreed. */
  host: hostSchema().optional(),
  agentAgreement: z.enum(["agrees", "differs", "not compared"]).optional(),
  timeAgreement: quarantineTimeAgreementSchema().optional(),
  downloadFlag: z.boolean().optional(),
  sandboxOnly: z.boolean().optional(),
  folded: z.boolean().optional(),
});

function hostSchema() {
  return z.union([
    z.object({ name: z.string() }),
    z.object({ state: z.literal("not named") }),
    z.object({ state: z.literal("2 values in this record") }),
  ]);
}

function quarantineTimeAgreementSchema() {
  return z.union([
    z.object({
      state: z.enum(["same second", "marked after the record", "marked before the record"]),
      band: z.string().optional(),
      attributeEncoding: z.literal("unix-hex-seconds"),
      databaseEncoding: timeEncodingSchema,
    }),
    z.object({ state: z.literal("not compared"), reason: z.string() }),
  ]);
}

export const quarantineAttributeBlockSchema = z.object({
  path: z.string().optional(),
  pathState: z.enum(["not in this record", "2 values in this record", "clipped"]).optional(),
  mark: z
    .union([
      z.object({
        flags: z.number().int().nonnegative(),
        named: z.array(z.string()),
        unnamed: z.string().optional(),
        time: z.string(),
        encoding: z.literal("unix-hex-seconds"),
        agent: z.string(),
        eventId: z.string().optional(),
      }),
      z.object({ state: z.literal("not decodable"), raw: z.string() }),
      z.object({ state: z.literal("empty or not reported") }),
      z.object({ state: z.literal("2 values in this record") }),
      z.object({ state: z.literal("clipped") }),
    ])
    .optional(),
  host: hostSchema(),
  sha256: z.string().optional(),
  md5: z.string().optional(),
  size: z.number().int().nonnegative().optional(),
  /** The database record's download facts, when joined. */
  download: z
    .object({
      kind: z.string().optional(),
      agent: z.string().optional(),
      bundleId: z.string().optional(),
      dataUrl: z.string().optional(),
      originUrl: z.string().optional(),
      originTitle: z.string().optional(),
    })
    .optional(),
  join: z.object({
    state: z.enum([
      "joined",
      "no database record in this upload",
      "database records disagree",
      "two attribute values for one path",
      "no identifier",
      "path not established",
      "host not established",
    ]),
    agentAgreement: z.enum(["agrees", "differs", "not compared"]).optional(),
    timeAgreement: quarantineTimeAgreementSchema().optional(),
    downloadFlag: z.boolean().optional(),
    /** The flag word is exactly the sandbox bit. */
    sandboxOnly: z.boolean().optional(),
  }),
  folded: z.boolean().optional(),
  records: z.number().int().positive().optional(),
});

export type QuarantineLocalFile = z.infer<typeof quarantineLocalFileSchema>;
export type QuarantineBlock = z.infer<typeof quarantineBlockSchema>;
export type QuarantineTimeAgreement = z.infer<ReturnType<typeof quarantineTimeAgreementSchema>>;
export type QuarantineAttributeBlock = z.infer<typeof quarantineAttributeBlockSchema>;
