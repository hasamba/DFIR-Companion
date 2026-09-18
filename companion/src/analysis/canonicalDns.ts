// The envelope block a DNS row carries (#933 item 2). Two vantages share it: the endpoint's own
// stub-resolver records (Sysmon 22, DNS-Client 3006/3008/3020 — dnsRecord.ts, #1009) and a
// network sensor's view of one query/answer exchange (Zeek `dns.log`, Suricata `dns` —
// dnsWireRows.ts, #996). Kept beside canonicalEvent.ts so the envelope schema stays within its
// size bound; the shapes are the envelope's, not an importer's.
//
// The values a record carries are `returned` — what the answering server sent back — and the
// block says whether the record keeps their OWNER (Suricata answers name `rrname`; Zeek and the
// Windows records do not). A sensor row may also carry `leads`: per returned address, what the
// SAME upload's connection records say about the client contacting it, inside a window whose
// basis is stated (`ttl` / `fixed`). Every `state` names what the records do NOT establish; none
// of them is a verdict.

import { z } from "zod";

export const dnsReturnedValueSchema = z.object({
  type: z.number().int().nonnegative().optional(),
  value: z.string(),
  kind: z.enum(["address", "name", "other"]),
  // The owner name the record states for this value (Suricata `answers[].rrname`); absent when
  // the record keeps none.
  owner: z.string().optional(),
});

export const dnsLeadStateSchema = z.enum([
  // The first connection record at or after the answer arrived falls inside the window.
  "connected inside the window",
  // A connection record exists after the answer arrived; none inside the window.
  "first connection after the window",
  // A connection record started in [query, answer arrival) — the client did not wait for this answer.
  "began before this answer arrived",
  // A connection record that started before the answer and was still open when it arrived.
  "open at the time of this answer",
  // Connection records to the address exist only before this query.
  "earlier connections only",
  // The client never contacted the address in this upload; the client forwards (it is also
  // observed as a queried server) and other clients contacted the address inside the window.
  "other clients connected inside the window",
  "no connection in this upload",
  // The upload carried more connection records than the index reads.
  "connection records exceed the index",
]);

export const dnsReplySchema = z.enum([
  "answered by the peer",
  "no reply from the peer",
  "reply not in this record",
]);

export const dnsGapBandSchema = z.enum(["≤1 s", "≤10 s", "≤60 s", "≤10 min", "≤1 h", "≤24 h", ">24 h"]);

export const dnsLeadSchema = z.object({
  address: z.string(),
  state: dnsLeadStateSchema,
  band: dnsGapBandSchema.optional(),
  reply: dnsReplySchema.optional(),
  // The window this lead was read against: the answer's own TTL, or a fixed window when the
  // record carries none. `seconds` is the FIRST folded observation's; the row's `ttl` carries the
  // range across all of them.
  window: z
    .object({
      basis: z.enum(["ttl", "fixed"]),
      seconds: z.number().nonnegative(),
      slackSeconds: z.number().nonnegative(),
    })
    .optional(),
  // The same client was returned this address for another name inside the window.
  sharedWithOtherNames: z.boolean().optional(),
  // Beside an in-window / after-window lead: an earlier record also began before the answer
  // arrived, or was open at that time — the client did not wait for this answer.
  alsoBefore: z.enum(["began before this answer arrived", "open at the time of this answer"]).optional(),
});

export const dnsBlockSchema = z.object({
  query: z.string(),
  queryValid: z.boolean(),
  indicator: z.boolean(),
  queryType: z.number().int().nonnegative().optional(),
  // The Windows records' status code (dnsRecord.ts); a sensor row carries `rcode` instead.
  status: z.number().int().nonnegative().optional(),
  state: z.string().min(1),
  networkQuery: z.boolean().optional(),
  returned: z.array(dnsReturnedValueSchema),
  ownership: z.enum(["not in this record", "stated in the record"]),
  vantage: z.enum(["endpoint", "sensor", "resolver"]),
  // An overflow row (dnsRecord.ts boundDnsVariants / dnsWireRows.ts): distinct shapes beyond the
  // budget were folded here; `returned` is empty on purpose and no set is representative.
  folded: z.boolean().optional(),
  // ── sensor and resolver rows only ──
  client: z.string().optional(),
  // The server the client asked — a recursive resolver or, when the client is itself a
  // resolver, an authority. The record does not say which.
  server: z.string().optional(),
  rcode: z.string().optional(),
  // The DNS transaction id (resolver rows only — dnsServerRecord.ts, #996).
  xid: z.string().optional(),
  flags: z
    .object({ aa: z.boolean().optional(), ra: z.boolean().optional(), rejected: z.boolean().optional() })
    .optional(),
  // What the record's own time is: a Zeek `ts` is the query (its `rtt` moves the answer later);
  // a Suricata answer event's timestamp is the answer.
  anchor: z.enum(["query", "answer"]).optional(),
  // The TTL range across the folded observations (a cached answer counts down on re-query).
  ttl: z.object({ min: z.number().nonnegative(), max: z.number().nonnegative() }).optional(),
  returnedTotal: z.number().int().nonnegative().optional(),
  // The sensor that wrote the record (a shipper's observer field, or Suricata's own `host`).
  sensor: z.string().optional(),
  joinState: z
    .enum([
      "joined",
      "no connection records in this upload",
      "answered with no address",
      // A loopback, link-local or multicast client, or one the record does not name: nothing a
      // sensor's connection records can be matched to.
      "client not joinable",
      "connection records exceed the index",
      // The upload's connection records carry no start time (a Suricata flow without `flow.start`).
      "connection records not placeable",
    ])
    .optional(),
  leads: z.array(dnsLeadSchema).optional(),
  records: z.number().int().positive().optional(),
});

export type DnsBlock = z.infer<typeof dnsBlockSchema>;
export type DnsLead = z.infer<typeof dnsLeadSchema>;
export type DnsLeadState = z.infer<typeof dnsLeadStateSchema>;
export type DnsReply = z.infer<typeof dnsReplySchema>;
export type DnsGapBand = z.infer<typeof dnsGapBandSchema>;

// Shared window vocabulary for every DNS-answer-to-connection join (#996) — same-upload
// (dnsConnJoin.ts, which re-exports these unchanged for its own existing importers) and
// cross-upload (dnsCrossUploadConnJoin.ts) alike. Homed here, not in either join module, so
// `analysis/timeline` (cross-upload) can reach them without importing `analysis/ingest`
// (same-upload) — a layering violation neither module's own domain should need to cross for three
// pure, upload-agnostic constants/one pure function.

/** Seconds added to every window for the client's resolve-to-connect latency. */
export const DNS_WINDOW_SLACK_S = 1;
/** The window when the record carries no TTL — worded as fixed, never as a TTL. */
export const DNS_FIXED_WINDOW_S = 300;

const GAP_BAND_S = 1000;

export function gapBand(gapMs: number): DnsGapBand {
  if (gapMs <= 1 * GAP_BAND_S) return "≤1 s";
  if (gapMs <= 10 * GAP_BAND_S) return "≤10 s";
  if (gapMs <= 60 * GAP_BAND_S) return "≤60 s";
  if (gapMs <= 600 * GAP_BAND_S) return "≤10 min";
  if (gapMs <= 3600 * GAP_BAND_S) return "≤1 h";
  if (gapMs <= 86_400 * GAP_BAND_S) return "≤24 h";
  return ">24 h";
}
export type DnsReturnedValue = z.infer<typeof dnsReturnedValueSchema>;
