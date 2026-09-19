// The envelope block a TLS relationship row carries (#933 item 6, second half — #997). One row per
// node one upload establishes on ONE sensor's records: a server certificate identity, a name (SNI),
// a client certificate identity, or a JA3 hash — with the values observed beside it (names, server
// endpoints, client addresses, certificate identities), the observation range, and the leads a
// cluster suggests. Every count is a count of what the retained records show — addresses, never
// clients or devices; a range of observations, never a service period; a string equality, never a
// verified signature — and `coverage` says how much of the upload the graph was computed over.
// Kept beside canonicalEvent.ts so the envelope schema stays within its size bound.

import { z } from "zod";

/**
 * Where a certificate's identity and facts came from, on a TLS session or certificate row (the
 * `tls.certificate` / `tls.clientCertificate` blocks in canonicalEvent.ts): filled from the
 * upload's x509 record by FUID (tlsGraphJoin.ts), or why that join was not made; read from the
 * certificate's own DER bytes (tlsDerRead.ts), and which stated fields differ from them.
 */
export const tlsCertificateProvenanceFields = {
  identityFrom: z.literal("x509 record").optional(),
  x509Join: z
    .enum(["records disagree", "disagrees with this record", "not among those read", "subject/issuer differ"])
    .optional(),
  decoded: z.literal("der").optional(),
  decodedDiffers: z.array(z.string()).optional(),
};

/** A set of distinct values: every one counted, up to 8 listed, `atLeast` when tracking stopped at 256. */
export const tlsGraphEdgeSchema = z.object({
  count: z.number().int().nonnegative(),
  listed: z.array(z.string()),
  atLeast: z.boolean().optional(),
});

export const tlsGraphLeadKindSchema = z.enum([
  "many-names",
  "name-not-listed",
  "certificates-alternate",
  "ja3-concentrated",
]);

export const tlsGraphLeadSchema = z.object({
  kind: tlsGraphLeadKindSchema,
  words: z.string(),
});

export const tlsGraphNodeKindSchema = z.enum(["certificate", "name", "client-certificate", "ja3", "ja3s"]);

/** One certificate identity a name was served with, and when the sensor saw it. */
export const tlsGraphSpanSchema = z.object({
  identity: z.string(),
  alg: z.enum(["sha1", "sha256"]).optional(),
  first: z.string().optional(),
  last: z.string().optional(),
  sessions: z.number().int().positive(),
});

export const tlsGraphBlockSchema = z.object({
  node: z.object({
    kind: tlsGraphNodeKindSchema,
    id: z.string(),
    alg: z.enum(["sha1", "sha256"]).optional(),
  }),
  sensor: z.union([z.object({ name: z.string() }), z.object({ state: z.literal("not named") })]),
  names: tlsGraphEdgeSchema.optional(),
  servers: tlsGraphEdgeSchema.optional(),
  clientAddresses: tlsGraphEdgeSchema.optional(),
  certificates: tlsGraphEdgeSchema.optional(),
  spans: z.array(tlsGraphSpanSchema).optional(),
  /** Sessions with no SNI (certificate node). */
  noSni: z.number().int().nonnegative().optional(),
  /** The sensor's chain-check strings as written, distinct. */
  chainChecks: z.array(z.string()).optional(),
  /** Sessions Zeek marked `sni_matches_cert: false`. */
  sniMismatches: z.number().int().nonnegative().optional(),
  /** Sessions whose certificate identity was unavailable (name node). */
  identityUnavailable: z.number().int().nonnegative().optional(),
  /** What the identities' ranges establish about their order (name node): a sequence, or nothing. */
  order: z.enum(["sequence", "not established"]).optional(),
  /** In sequence, and the earliest and latest certificate records list the same DNS names. */
  sameNames: z.boolean().optional(),
  certificate: z
    .object({
      records: z.number().int().nonnegative(),
      subject: z.string().optional(),
      issuer: z.string().optional(),
      notBefore: z.string().optional(),
      notAfter: z.string().optional(),
      dnsNamesListed: z.number().int().nonnegative().optional(),
      dnsNamesTotal: z.number().int().nonnegative().optional(),
      /** Fields the certificate records for this identity disagree on. */
      disagree: z.array(z.string()).optional(),
    })
    .optional(),
  notListed: z
    .union([
      z.object({ count: z.number().int().nonnegative(), listed: z.array(z.string()) }),
      z.object({ state: z.literal("not compared"), reason: z.string() }),
    ])
    .optional(),
  /** Distinct server-certificate identities in the upload carrying the same issuer string. */
  issuerString: z.number().int().nonnegative().optional(),
  first: z.string().optional(),
  last: z.string().optional(),
  /** Sessions with no readable time, excluded from the range. */
  untimed: z.number().int().nonnegative().optional(),
  sessions: z.number().int().nonnegative(),
  leads: z.array(tlsGraphLeadSchema),
  coverage: z.object({
    sessionsRead: z.number().int().nonnegative(),
    sessionsTotal: z.number().int().nonnegative(),
    certificatesRead: z.number().int().nonnegative(),
    certificatesTotal: z.number().int().nonnegative(),
  }),
  basis: z.literal("records in this upload only; no contact with any observed infrastructure"),
  /** An overflow row: nodes beyond the retained bound folded; nothing shown. */
  folded: z.boolean().optional(),
  records: z.number().int().positive().optional(),
});

export type TlsGraphBlock = z.infer<typeof tlsGraphBlockSchema>;
export type TlsGraphEdge = z.infer<typeof tlsGraphEdgeSchema>;
export type TlsGraphLead = z.infer<typeof tlsGraphLeadSchema>;
export type TlsGraphNodeKind = z.infer<typeof tlsGraphNodeKindSchema>;
