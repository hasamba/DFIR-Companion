// A Windows DNS record, read for what it establishes (#933 item 2, prerequisite phase).
//
// Three records carry a query and what the host's resolver answered: Sysmon 22 (`QueryName`,
// `QueryStatus`, `QueryResults`, the querying `Image`), DNS-Client 3008 (the same three plus
// `QueryType`), and DNS-Client 3020 (`QueryName`, `QueryType`, `Status`, `QueryResults`). Each used
// to read as `QueryName=…` and nothing else, so a name that never resolved and the same name
// answered with a new address the next day were ONE row, and the returned addresses were invisible.
//
// One record establishes: that a process on this host asked its configured resolver for a name (and
// a type, when the record says one); the status the resolver client reported; and the VALUES the
// resolver returned. It does not establish that any returned value belongs to the queried name —
// the results are flattened with no owner and no section, so an ADDITIONAL-section address sits
// beside the answers — nor that the host connected to any of them, nor which resolver answered or
// whether it answered from cache. So the words say `returned`, never `resolves to`; a returned
// address is no indicator (nothing observed a connection); the queried name is an indicator only
// when it is a real name; and the vantage is the endpoint's own stub resolver, said once in the
// envelope. The join to a connection is a spec, over un-aggregated records.

import { isIP } from "node:net";
import { domainToASCII } from "node:url";
import { breakHashRuns, identityMark, keyDigest, packTags, showToken } from "./recordIdentity.js";

/** Win32 DNS status codes, from WinError.h — nothing outside this table is read as success or failure. */
const STATUS_TABLE: Record<number, { state: DnsState; words: string }> = {
  0: { state: "success", words: "" },
  123: { state: "invalid-name", words: "invalid name (ERROR_INVALID_NAME)" },
  1460: { state: "timeout", words: "timed out — no answer" },
  9001: { state: "format-error", words: "format error (RCODE 1)" },
  9002: { state: "server-failure", words: "server failure (RCODE 2)" },
  9003: { state: "nxdomain", words: "NXDOMAIN — the name does not exist at this resolver" },
  9004: { state: "not-implemented", words: "not implemented (RCODE 4)" },
  9005: { state: "refused", words: "refused (RCODE 5)" },
  9501: { state: "no-records", words: "no records of the queried type" },
  9560: { state: "invalid-name-char", words: "invalid character in the name (DNS_ERROR_INVALID_NAME_CHAR)" },
  9701: { state: "record-missing", words: "the record does not exist (DNS_ERROR_RECORD_DOES_NOT_EXIST)" },
};

/** Query types named in the words; every other type is `type N` — reused by dnsServerRecord.ts (#996). */
export const TYPE_NAMES: Record<number, string> = {
  1: "A",
  2: "NS",
  5: "CNAME",
  6: "SOA",
  12: "PTR",
  15: "MX",
  16: "TXT",
  28: "AAAA",
  33: "SRV",
  65: "HTTPS",
  255: "ANY",
};
// RR types whose data Windows writes as one owner name: NS, CNAME, SOA (the primary), PTR, MX (the
// exchange), SRV (the target), DNAME. TXT (16) stays case-sensitive data.
const NAME_TYPES = new Set([2, 5, 6, 12, 15, 33, 39]);
const ADDRESS_TYPES = new Set([1, 28]);

/** What a present-but-not-text field reads as: never a number, never a name, never empty. */
const UNREADABLE = "(unreadable)";
export const RESULTS_SHOWN_MAX = 8;
export const RESULTS_KEPT_MAX = 64;
const VALUE_SHOWN_MAX = 60;
const VALUE_KEPT_MAX = 512;
const NAME_SHOWN_MAX = 120;
/** Reused by siemDnsConnJoin.ts (#996) when it appends its own tags to an already-built row. */
export const DESCRIPTION_MAX = 600;

export type DnsState =
  | "success"
  | "nxdomain"
  | "no-records"
  | "server-failure"
  | "refused"
  | "timeout"
  | "invalid-name"
  | "invalid-name-char"
  | "format-error"
  | "not-implemented"
  | "record-missing"
  | "other"
  | "absent"
  | "unreadable";

export interface StatusReading {
  code?: number;
  state: DnsState;
  words: string;
}

/** The status the resolver client reported. Absent and unreadable are their own states. */
export function readQueryStatus(raw: string | undefined): StatusReading {
  const text = (raw ?? "").trim();
  if (!text) return { state: "absent", words: "outcome not in this record" };
  if (!/^\d{1,10}$/.test(text)) return { state: "unreadable", words: "status not readable" };
  const code = Number(text);
  const known = STATUS_TABLE[code];
  return known ? { code, ...known } : { code, state: "other", words: `status ${code} (not in the table)` };
}

export interface ReturnedValue {
  /** The RR type the record names for this value; undefined when it names none (Sysmon's bare form). */
  type: number | undefined;
  value: string;
  kind: "address" | "name" | "other";
}

export interface ResultsReading {
  /** Every value, in record order, at most RESULTS_KEPT_MAX. */
  values: ReturnedValue[];
  /** The identity of EVERY parsed value — sorted, typed, length-framed — including those past the kept bound. */
  identity: string;
  /** Any value's display is not its own text: clipped or neutralised. */
  clipped: boolean;
  /** The bounded display: at most RESULTS_SHOWN_MAX values, neutralised, then `+n more`. */
  shown: string;
  total: number;
}

// A DNS OWNER name, not a hostname: underscores are legal anywhere in a label (RFC 2782 service
// labels, `beacon_01.attacker.example`). A name outside ASCII is a U-label: it is converted to its
// A-label (IDNA ToASCII, `xn--…`) and validated and keyed in THAT form, so a combining mark or a
// case variant of one name is one name, and the 63-octet label limit is measured on the wire form.
// What is rejected is what no resolver answers and no report should carry bare: a hyphen at an
// edge, a bracket, a slash, whitespace, punctuation other than `-` and `_`.
const LABEL = /^[A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?$/;

/** The wire form of a query name: A-labels for a U-label name, "" when it cannot be converted. */
export function asciiName(raw: string): string {
  // The IDNA label separators (U+3002, U+FF0E, U+FF61) are dots on the wire.
  const name = raw.replace(/[\u3002\uff0e\uff61]/g, ".").replace(/\.$/, "");
  if (/^[\x00-\x7f]*$/.test(name)) return name;
  // Converted LABEL BY LABEL, never as one string: WHATWG domainToASCII parses a whole value as a
  // URL host and stops at `/`, `?`, `#` or `\`, so `safe.example/bücher.attacker` would come back
  // as `safe.example` — a valid name the record never queried. A label that does not convert whole
  // (empty, or anything the converter dropped) fails the name.
  const labels = name.split(".").map((l) => {
    if (/^[\x00-\x7f]*$/.test(l)) return l;
    if (/[/?#\\:@\s]/.test(l)) return "";
    const a = domainToASCII(l);
    return a && !a.includes(".") ? a : "";
  });
  return labels.some((l) => !l) ? "" : labels.join(".");
}

/**
 * A name a resolver would answer: 1–253 characters of valid labels. One label (`wpad`, a NetBIOS-
 * style name) is a valid QUERY — whether it is an indicator is a separate rule (isIndicatorName).
 */
export function isValidQueryName(raw: string): boolean {
  const name = asciiName(raw);
  if (!name || name.length > 253) return false;
  // A wildcard is a valid FIRST label of a multi-label name (DnsNameWildcard) and nowhere else.
  const labels = name.split(".");
  return labels.every(
    (l, i) =>
      (i === 0 && l === "*" && labels.length > 1) || (l.length >= 1 && l.length <= 63 && LABEL.test(l)),
  );
}

/** The indicator rule the mapper always had: a valid name with at least one dot. */
export const isIndicatorName = (raw: string): boolean =>
  isValidQueryName(raw) && asciiName(raw).includes(".");

const V4_MAPPED = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i;

function classify(type: number | undefined, value: string): ReturnedValue {
  const mapped = V4_MAPPED.exec(value);
  const address = mapped ? mapped[1] : value;
  if (isIP(address) && (type === undefined || ADDRESS_TYPES.has(type)))
    return { type, value: address, kind: "address" };
  // A name compares case-insensitively (RFC 4343): canonical lowercase, or an authority could mint
  // one row per capitalisation of one answer. The value is kept WHOLE here — the identity is built
  // from it — and bounded only in the envelope (boundForEnvelope).
  if (type !== undefined && NAME_TYPES.has(type) && isValidQueryName(value))
    return { type, value: asciiName(value).toLowerCase(), kind: "name" };
  return { type, value, kind: "other" };
}

/** How many values at the head are CNAME steps — the one run Windows writes in order. */
function leadingCnames(values: readonly ReturnedValue[]): number {
  let n = 0;
  while (n < values.length && values[n].type === 5 && values[n].kind === "name") n++;
  return n;
}

const boundForEnvelope = (v: ReturnedValue): ReturnedValue =>
  v.value.length > VALUE_KEPT_MAX ? { ...v, value: v.value.slice(0, VALUE_KEPT_MAX) } : v;

function showValue(v: ReturnedValue): string {
  if (!v.value) return `type ${v.type} (value not in this record)`;
  const text = breakHashRuns(showToken(v.value));
  const clipped = text.length > VALUE_SHOWN_MAX ? `${text.slice(0, VALUE_SHOWN_MAX - 1)}…` : text;
  // A typed address shows its RR type: an A and an AAAA that carry the same address are two facts.
  if (v.kind === "address")
    return v.type === undefined ? clipped : `${TYPE_NAMES[v.type] ?? `type ${v.type}`} ${clipped}`;
  if (v.kind === "name") return `${(TYPE_NAMES[v.type ?? -1] ?? `type ${v.type}`).toLowerCase()} ${clipped}`;
  return v.type === undefined ? clipped : `type ${v.type} ${clipped}`;
}

/** The resolver's returned values: `type: N value;` and bare `value;` entries, typed and validated. */
export function readQueryResults(raw: string | undefined): ResultsReading {
  // A whole value of `-` is the Windows placeholder for "none", not a returned value; a typed
  // `type: 16 -` is data.
  const entries = ((raw ?? "").trim() === "-" ? "" : (raw ?? ""))
    .split(";")
    .map((e) => e.trim())
    .filter(Boolean);
  const all = entries.map((e) => {
    // `type: 16 ` with nothing after it is a type marker whose data the record did not keep — not
    // the literal string "type: 16" returned.
    const typed = /^type:\s*(\d{1,5})(?:\s+(.*))?$/s.exec(e);
    return typed ? classify(Number(typed[1]), (typed[2] ?? "").trim()) : classify(undefined, e);
  });
  const values = all.slice(0, RESULTS_KEPT_MAX).map(boundForEnvelope);
  // The identity covers every parsed value WHOLE, not only the kept ones or their bounded form: two
  // records that agree on the first 64 values, or on a value's first 512 characters, and differ
  // after are two rows, even though the envelope keeps 64 values of 512.
  // The leading CNAME run is ORDERED evidence (the chain the display shows), so its order is in the
  // identity; every value after it is an unordered set, sorted.
  const frame = (v: ReturnedValue): string => `${v.type ?? "-"}:${v.value.length}:${v.value}`;
  const lead = leadingCnames(all);
  // The two sections are framed with the run's length, so a CNAME that sorts to the front of the
  // unordered section can never read as a longer chain.
  const identity = `chain${lead}:${all.slice(0, lead).map(frame).join("|")}|set:${all.slice(lead).map(frame).sort().join("|")}`;
  // An empty value is shown as words that a literal value could spell — so it counts as lossy and
  // the row carries the mark, keeping `type: 16;` apart from `type: 16 (value not in this record);`.
  // …and so does ANY `other` value: free data can spell the renderer's own separators (`a, type
  // 16 b`), so only addresses and names — whose characters cannot — render injectively.
  const clipped = all.some(
    (v) =>
      v.kind === "other" || v.value.length > VALUE_SHOWN_MAX || breakHashRuns(showToken(v.value)) !== v.value,
  );
  const head = values.slice(0, RESULTS_SHOWN_MAX);
  // Only a run of LEADING CNAME steps is arrow-linked — that is the one chain Windows writes in
  // order. Every other value (an NS, an MX, an address) stays in record order, comma-separated: the
  // owner-less field establishes no relationship between them.
  const steps = leadingCnames(head);
  const chain = head.slice(0, steps).map(showValue);
  const rest = head.slice(steps).map(showValue).join(", ");
  // The chain's steps are arrow-linked to each other only; the rest follows after a semicolon — an
  // arrow into it would say the last CNAME targets the next value, which the record never says.
  const parts = [chain.join(" → "), rest].filter(Boolean).join("; ");
  const more = all.length > RESULTS_SHOWN_MAX ? ` +${all.length - RESULTS_SHOWN_MAX} more` : "";
  return { values, identity, clipped, shown: all.length ? `${parts}${more}` : "", total: all.length };
}

/**
 * What THIS event defines, per the provider manifest — the only fields the overlay reads. A field
 * the event does not define is SIEM decoration, never evidence: a `QueryResults` beside a 3006, an
 * `IsNetworkQuery` beside a 3008, a `QueryType` beside a Sysmon 22 would otherwise forge returned
 * values, a transmission, a type — and enter the identity.
 */
export interface DnsEventSchema {
  status: "QueryStatus" | "Status" | "";
  type: boolean;
  results: boolean;
  networkQuery: boolean;
}
export const SYSMON_22_DNS: DnsEventSchema = {
  status: "QueryStatus",
  type: false,
  results: true,
  networkQuery: false,
};
const DNS_CLIENT_3006: DnsEventSchema = { status: "", type: true, results: false, networkQuery: true };
const DNS_CLIENT_3008: DnsEventSchema = {
  status: "QueryStatus",
  type: true,
  results: true,
  networkQuery: false,
};
const DNS_CLIENT_3020: DnsEventSchema = { status: "Status", type: true, results: true, networkQuery: false };

// Microsoft-Windows-DNS-Client/Operational — channel-keyed by the Windows mapper like its PowerShell
// table. The shape is the mapper's WinEventDef, spelled here to avoid a cycle.
export const DNS_CLIENT_EVENTS: Record<
  number,
  { label: string; severity: "Info" | "Low"; kind: "dns"; dns: DnsEventSchema }
> = {
  3006: { label: "DNS query called", severity: "Info", kind: "dns", dns: DNS_CLIENT_3006 },
  3008: { label: "DNS query completed", severity: "Low", kind: "dns", dns: DNS_CLIENT_3008 },
  3020: { label: "DNS query result", severity: "Info", kind: "dns", dns: DNS_CLIENT_3020 },
};

interface DnsOverlayInput {
  field: (key: string) => string;
  has: (key: string) => boolean;
  schema: DnsEventSchema;
  description: string;
}

export interface DnsEnvelope {
  query: string;
  queryValid: boolean;
  /** queryValid AND at least one dot — the mapper's indicator rule. */
  indicator: boolean;
  queryType?: number;
  status?: number;
  state: DnsState;
  /** 3006 only: whether the call went to a server (`IsNetworkQuery`). */
  networkQuery?: boolean;
  returned: ReturnedValue[];
  ownership: "not in this record";
  vantage: "endpoint";
}

export interface DnsOverlay {
  description: string;
  /** `|dns:q<len>:<name digest>:t<type>:s<code>:r<results digest>` — see the design note. */
  identity: string;
  dns: DnsEnvelope;
}

function typeWords(raw: string, present: boolean): { words: string; key: string; type?: number } {
  if (!present) return { words: "type not in this record", key: "-" };
  const text = raw.trim();
  if (!/^\d{1,5}$/.test(text)) return { words: "type not readable", key: "?" };
  const type = Number(text);
  return { words: `${TYPE_NAMES[type] ?? `type ${type}`} query`, key: String(type), type };
}

/** 3006's `IsNetworkQuery`: 1 = a query went to a server; 0 = answered locally; absent on the other events. */
function networkQuery(input: DnsOverlayInput): { value?: boolean; words: string; key: string } {
  if (!input.schema.networkQuery || !input.has("IsNetworkQuery")) return { words: "", key: "-" };
  const raw = input.field("IsNetworkQuery").trim();
  if (raw === "1") return { value: true, words: "network query", key: "1" };
  // Said literally: the flag does not establish that the call was answered, only that no query
  // went to a server; 3006 carries no status and no results.
  if (raw === "0") return { value: false, words: "not a network query", key: "0" };
  return { words: "IsNetworkQuery not readable", key: "?" };
}

/**
 * The status field the EVENT defines, and only that one: 3008 and Sysmon 22 write `QueryStatus`,
 * 3020 writes `Status`, 3006 none. The other spelling is never read — on a flattened export it is
 * SIEM metadata (`status: 9003`), and reading it forged a "fields disagree" outcome.
 */
function statusOf(input: DnsOverlayInput): { reading: StatusReading; key: string } {
  const reading = readQueryStatus(input.schema.status ? input.field(input.schema.status) : undefined);
  const key = reading.code !== undefined ? String(reading.code) : reading.state === "absent" ? "-" : "?";
  return { reading, key };
}

/** The overlay for a DNS record over the Windows mapper's description; severity is never graded here. */
export function dnsOverlay(
  read: (key: string) => unknown,
  schema: DnsEventSchema,
  description: string,
): DnsOverlay {
  // A SIEM export may carry a multi-valued field as an ARRAY: its elements are the record's entries
  // (joined with the grammar's own `;`), never String()-joined into one comma value. An object is
  // the mapper's `{"#text": …}` shape or it is UNREADABLE — present but not text — which must never
  // read as absent: a status the record carries but this reader cannot read is `s?`, not `s-`.
  const text = (v: unknown): string => {
    if (typeof v === "string") return v;
    if (v == null) return "";
    if (Array.isArray(v)) return v.map(text).filter(Boolean).join(";");
    if (typeof v === "object") {
      const inner = (v as Record<string, unknown>)["#text"];
      return typeof inner === "string" ? inner : UNREADABLE;
    }
    return String(v);
  };
  return overlayOf({
    field: (k) => text(read(k)),
    has: (k) => read(k) !== undefined,
    schema,
    description,
  });
}

function overlayOf(input: DnsOverlayInput): DnsOverlay {
  // The EXACT recorded string is validated — not a trimmed one: `good.example ` is not the name
  // `good.example`, and only a valid name is canonicalised (case, the root dot). An invalid string
  // keeps its exact text as its identity, so two malformed queries never fold.
  const rawName = input.field("QueryName");
  const queryValid = isValidQueryName(rawName);
  const canonical = queryValid ? asciiName(rawName).toLowerCase() : rawName;
  const shownName = breakHashRuns(showToken(rawName));
  const nameClipped = shownName.length > NAME_SHOWN_MAX;
  const name = nameClipped ? `${shownName.slice(0, NAME_SHOWN_MAX - 1)}…` : shownName;
  const type = typeWords(input.field("QueryType"), input.schema.type && input.has("QueryType"));
  const status = statusOf(input);
  const results = readQueryResults(input.schema.results ? input.field("QueryResults") : undefined);

  const tags = [`query: ${name}`];
  if (!queryValid) tags.push("query name is not a valid name");
  tags.push(type.words);
  // 3006 writes IsNetworkQuery: 0 means the call was answered without a network query (cache, hosts
  // file, a local name) — the record then establishes a call, not a transmission.
  const net = networkQuery(input);
  if (net.words) tags.push(net.words);
  if (status.reading.state === "success") {
    tags.push(
      results.total ? `returned: ${results.shown}` : "resolved; the returned values are not in this record",
    );
  } else {
    tags.push(status.reading.words);
    // A failure status beside returned values is the record's contradiction — shown, not resolved.
    if (results.total) tags.push(`the record also carries returned values: ${results.shown}`);
  }

  // Identity: the FULL canonical name, the type, the code, and a sorted typed multiset of every kept
  // value — record order is display only, so a rotated A set is one row, not one row per order.
  const identity = `|dns:q${canonical.length}:${keyDigest(canonical)}:t${type.key}:s${status.key}:n${net.key}:r${
    results.total ? keyDigest(results.identity) : "-"
  }`;

  // Lossy when anything shown is not the record's own text: a neutralised or clipped name, a value
  // omitted past the shown bound, clipped past the value bound, or neutralised.
  // A U-label is shown as written and keyed as its A-label, so the shown text is not the identity.
  const converted = queryValid && asciiName(rawName) !== rawName.replace(/\.$/, "");
  const lossy =
    shownName !== rawName || nameClipped || converted || results.total > RESULTS_SHOWN_MAX || results.clipped;
  // …or a tag packTags had to drop: a dropped `[returned: …]` is evidence the row no longer shows.
  // The mapper's own prefix (`Image=…`) is record text too: a bracket in it would forge one of the
  // tags appended here, so it is neutralised — and the mark then covers the raw prefix as well,
  // or two Images that neutralise alike would read alike after import.
  const prefix = showToken(input.description);
  const mark = identityMark(`${input.description}${identity}`);
  const full = packTags(tags, Number.POSITIVE_INFINITY);
  const fits = prefix.length + full.length <= DESCRIPTION_MAX;
  if (!lossy && fits && prefix === input.description)
    return { description: `${prefix}${full}`, identity, dns: envelope() };
  const packed = packTags(tags, DESCRIPTION_MAX - mark.length - prefix.length);
  return { description: `${prefix}${packed}${mark}`, identity, dns: envelope() };

  function envelope(): DnsEnvelope {
    return {
      query: canonical,
      queryValid,
      indicator: isIndicatorName(rawName),
      ...(type.type !== undefined ? { queryType: type.type } : {}),
      ...(status.reading.code !== undefined ? { status: status.reading.code } : {}),
      state: status.reading.state,
      ...(net.value !== undefined ? { networkQuery: net.value } : {}),
      returned: results.values,
      ownership: "not in this record",
      vantage: "endpoint",
    };
  }
}

/** Distinct returned-value sets one query keeps as separate rows before the rest fold into one. */
export const DNS_VARIANTS_MAX = 64;
const DNS_RESULT_SEGMENT = /:r[0-9a-f]{32}$/;
const DNS_OVERFLOW = ":r-overflow";
const RETURNED_TAG =
  / \[returned: [^\]]*\]| \[the record also carries returned values: [^\]]*\]| #[A-Za-z0-9_-]{22}$/g;

/**
 * Bound the returned-value VARIANTS one query may keep (#933 item 2): an authority that answers a
 * TXT query with a new value every time would otherwise be one group per response, and the
 * aggregator's global cap would then drop unrelated evidence. The first DNS_VARIANTS_MAX distinct
 * sets per base identity (host, channel, event, process, query, type, status) stay verbatim; every
 * later distinct set is rewritten onto ONE overflow key per base, with words that say sets were
 * folded and show none of them as representative. Rewrites in place; IOC provenance recorded under
 * a rewritten key follows the row.
 */
export function boundDnsVariants(
  mapped: Array<{ aggKey: string; description: string; canonical?: { dns?: Record<string, unknown> } }>,
  sink: Map<string, { sourceAggKeys?: string[] }>,
): void {
  const seen = new Map<string, Set<string>>();
  const rewritten = new Map<string, string>();
  for (const row of mapped) {
    const m = DNS_RESULT_SEGMENT.exec(row.aggKey);
    if (!m) continue;
    const base = row.aggKey.slice(0, m.index);
    const digests = seen.get(base) ?? new Set<string>();
    seen.set(base, digests);
    if (digests.has(m[0]) || digests.size < DNS_VARIANTS_MAX) {
      digests.add(m[0]);
      continue;
    }
    const overflowKey = `${base}${DNS_OVERFLOW}`;
    rewritten.set(row.aggKey, overflowKey);
    row.aggKey = overflowKey;
    // The row's own mark went with its returned tag; the overflow row carries a mark of ITS key, or
    // two queries whose shown names clip alike would read alike after import.
    row.description =
      `${row.description.replace(RETURNED_TAG, "")} [overflow: distinct returned-value sets beyond ${DNS_VARIANTS_MAX} for this query folded; none shown]` +
      identityMark(overflowKey);
    // The envelope must not present one folded set as the row's: it shows none, and says so.
    if (row.canonical?.dns) row.canonical.dns = { ...row.canonical.dns, returned: [], folded: true };
  }
  rewriteAggKeySink(sink, rewritten);
}

/**
 * Follow an IOC's provenance when the row that sourced it gets its `aggKey` rewritten in place
 * (`boundDnsVariants` above, and the Windows DNS→connection join in `siemDnsConnJoin.ts` /
 * `siemImport.ts`) — an IOC's `sourceAggKeys` must keep pointing at the row's CURRENT key, or
 * provenance silently stops resolving after the rewrite.
 */
export function rewriteAggKeySink(
  sink: Map<string, { sourceAggKeys?: string[] }>,
  rewritten: Map<string, string>,
): void {
  if (!rewritten.size) return;
  for (const [key, ioc] of sink) {
    if (!ioc.sourceAggKeys?.some((k) => rewritten.has(k))) continue;
    sink.set(key, {
      ...ioc,
      sourceAggKeys: [...new Set(ioc.sourceAggKeys.map((k) => rewritten.get(k) ?? k))],
    });
  }
}
