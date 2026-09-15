// The envelope blocks a web request row and a transfer row carry (webChainRows.ts, #993 — the
// second half of #933 item 1). Kept beside canonicalEvent.ts so the envelope schema stays within
// its size bound; the shapes are the envelope's, not an importer's.
//
// A `web` block is one request/response pair as the sensor logged it, plus the hops the SAME
// upload establishes through a shared identity: the bodies its `resp_fuids` / `orig_fuids` name
// (Zeek) or its `flow_id` + `tx_id` name (Suricata), and — on a 3xx — what the record says about
// the redirect. A `transfer` block is one file the sensor reassembled, with the sensor's own
// completeness counters read as coverage, and the request records that carry its identifier.
//
// Every `state` value spells what the record does NOT establish: "not in this record" is a fact
// about the format, "not in this upload" a fact about what was imported, never "did not happen".

import { z } from "zod";

const locatorSchema = z.object({
  uid: z.string().optional(),
  depth: z.number().int().nonnegative().optional(),
  streamId: z.string().optional(),
  flowId: z.string().optional(),
  txId: z.string().optional(),
  fuid: z.string().optional(),
});

// What the sensor's counters establish about the bytes a digest was computed over. A digest is a
// FILE identity (`file.sha256`, a hash indicator) only under `whole` or `unsized`; the others keep
// it on the transfer as a partial digest that joins nothing.
export const coverageKindSchema = z.enum([
  "whole", // seen == total, nothing missing, not timed out (Suricata: CLOSED, no gaps, offset 0)
  "unsized", // no size recorded by the peer; nothing missing, not timed out — delivered to EOF
  "partial", // seen < total (Zeek) / TRUNCATED (Suricata)
  "gapped", // bytes missing in the middle — Zeek computes no digest; Suricata `gaps: true`
  "range", // a 206 response or a non-zero start offset: the object was never the target
  "timed-out", // the sensor gave up waiting
  "not-recorded", // no counters at all (Suricata with no `state`)
]);

const digestSchema = z.object({
  alg: z.enum(["sha256", "sha1", "md5"]),
  value: z.string(),
});

const transferFactsSchema = z.object({
  over: z.string().optional(), // Zeek `source` / Suricata `app_proto`: HTTP, SMTP, FTP, SMB …
  mime: z.string().optional(),
  filename: z.string().optional(),
  seenBytes: z.number().int().nonnegative().optional(),
  totalBytes: z.number().int().nonnegative().optional(),
  missingBytes: z.number().int().nonnegative().optional(),
  timedOut: z.boolean().optional(),
  sensorState: z.string().optional(), // Suricata `fileinfo.state` verbatim
  coverage: coverageKindSchema,
  // The digests the sensor computed, as it computed them. They are a FILE identity (`file.sha256`,
  // a hash indicator) only under a `whole` / `unsized` coverage; otherwise they are digests over
  // the bytes seen and identify nothing on an endpoint.
  digests: z.array(digestSchema).optional(),
  direction: z
    .object({
      tx: z.array(z.string()).optional(),
      rx: z.array(z.string()).optional(),
      fromOriginator: z.boolean().optional(),
    })
    .optional(),
});

const requestFactsSchema = z.object({
  method: z.string(),
  host: z.string().optional(),
  target: z.string().optional(),
  targetForm: z.string(),
  version: z.string().optional(),
  statusCode: z.number().int().nonnegative().optional(),
  locator: locatorSchema.optional(),
});

export const webBodyHopSchema = z.object({
  direction: z.enum(["response", "request", "not recorded"]),
  /** The shared identifier both records carry: a Zeek fuid, or Suricata's `flow_id|tx_id`. */
  id: z.string(),
  state: z.enum([
    "observed",
    "no files record in this upload",
    "not among the records read",
    "identifier conflict — not joined",
    "conflicting files records",
  ]),
  transfer: transferFactsSchema.optional(),
});

export const webBlockSchema = requestFactsSchema.extend({
  responseState: z.enum(["recorded", "not recorded"]),
  user: z.string().optional(),
  referrer: z.string().optional(),
  userAgent: z.string().optional(),
  requestBodyLen: z.number().int().nonnegative().optional(),
  responseBodyLen: z.number().int().nonnegative().optional(),
  proxied: z.array(z.string()).optional(),
  redirect: z
    .object({
      // Zeek's http.log carries no Location; Suricata's `http.redirect` is the server's stated
      // target — a claim in the response, never an observed follow.
      target: z.string().optional(),
      targetState: z.enum(["stated by the server", "not in this record"]),
      // The next transaction on the same connection (uid, depth + 1) — order on the connection,
      // never the redirect target. Absent on HTTP/2 rows, where depth orders nothing.
      next: requestFactsSchema.optional(),
      nextState: z.enum([
        "observed",
        "not in this upload",
        "not among the records read",
        "later transaction only",
        "not read (HTTP/2 stream)",
        "no transaction identity",
      ]),
      laterDepth: z.number().int().nonnegative().optional(),
    })
    .optional(),
  bodies: z.array(webBodyHopSchema),
  bodiesTotal: z.number().int().nonnegative(),
  identifiersDropped: z.number().int().nonnegative().optional(),
  records: z.number().int().positive(),
  // An overflow row: shapes beyond the bound folded here; no fact is representative.
  folded: z.boolean().optional(),
});

export const transferBlockSchema = transferFactsSchema.extend({
  requests: z.array(requestFactsSchema),
  requestsTotal: z.number().int().nonnegative(),
  requestState: z.enum([
    "observed",
    "inline on this record",
    "not in this upload",
    "not among the records read",
    "identifier conflict — not joined",
    "no request identity",
  ]),
  // A Suricata fileinfo carries its request on the same record; kept apart from `requests`,
  // which are OTHER records joined by identifier.
  inlineRequest: z
    .object({
      method: z.string(),
      host: z.string().optional(),
      target: z.string().optional(),
      statusCode: z.number().int().nonnegative().optional(),
    })
    .optional(),
  locator: locatorSchema.optional(),
  identifiersDropped: z.number().int().nonnegative().optional(),
  records: z.number().int().positive(),
  folded: z.boolean().optional(),
});

export type CoverageKind = z.infer<typeof coverageKindSchema>;
export type WebBlock = z.infer<typeof webBlockSchema>;
export type TransferBlock = z.infer<typeof transferBlockSchema>;
export type WebBodyHop = z.infer<typeof webBodyHopSchema>;
export type RequestFacts = z.infer<typeof requestFactsSchema>;

// One SMB operation as Suricata's `smb` event logged it (smbChainRows.ts, #1085, importer half of
// #933 item 4). `outcome` states only what a CREATE's disposition and status TOGETHER establish —
// FILE_OPEN/FILE_CREATE/FILE_OVERWRITE each have exactly one success meaning; the `_IF` variants
// and FILE_SUPERSEDE do not (MS-SMB2's CreateAction would settle it, but Suricata's eve.json does
// not export that field), so those stay "requested-ambiguous" rather than a guess.
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
  shareType: z.string().optional(), // FILE / PIPE / PRINT / unknown, verbatim
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
  // Which chain-level fact backs this row's file identity — absent means "joined" (the default).
  createJoinState: z
    .enum(["no fuid on this record", "no flow id on this record", "no matching file record in this upload"])
    .optional(),
  // Operations on this file beyond SMB_BUCKET_MAX, kept but not individually shown.
  operationsOmitted: z.number().int().nonnegative().optional(),
});

export type SmbBlock = z.infer<typeof smbBlockSchema>;
export type SmbOutcome = z.infer<typeof smbOutcomeSchema>;
export type SmbFileinfoJoin = z.infer<typeof smbFileinfoJoinSchema>;
export type TransferFacts = z.infer<typeof transferFactsSchema>;
