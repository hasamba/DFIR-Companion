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

/** Query types named in the words; every other type is `type N`. */
const TYPE_NAMES: Record<number, string> = {
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
const NAME_TYPES = new Set([2, 5, 12]);
const ADDRESS_TYPES = new Set([1, 28]);

export const RESULTS_SHOWN_MAX = 8;
export const RESULTS_KEPT_MAX = 64;
const VALUE_SHOWN_MAX = 60;
const VALUE_KEPT_MAX = 512;
const NAME_SHOWN_MAX = 120;
const DESCRIPTION_MAX = 600;

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
  | "unreadable"
  | "conflict";

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

// A DNS OWNER name, not a hostname: RFC 2782 service labels lead with an underscore
// (`_ldap._tcp.dc._msdcs.example`), and Windows issues exactly those for DC discovery.
const LABEL = /^_?[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$/;

/** A name a resolver would answer: 1–253 characters of valid labels, at least two of them. */
export function isValidQueryName(raw: string): boolean {
  const name = raw.replace(/\.$/, "");
  if (!name || name.length > 253) return false;
  const labels = name.split(".");
  return labels.length >= 2 && labels.every((l) => l.length >= 1 && l.length <= 63 && LABEL.test(l));
}

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
    return { type, value: value.replace(/\.$/, "").toLowerCase(), kind: "name" };
  return { type, value, kind: "other" };
}

const boundForEnvelope = (v: ReturnedValue): ReturnedValue =>
  v.value.length > VALUE_KEPT_MAX ? { ...v, value: v.value.slice(0, VALUE_KEPT_MAX) } : v;

function showValue(v: ReturnedValue): string {
  const text = breakHashRuns(showToken(v.value));
  const clipped = text.length > VALUE_SHOWN_MAX ? `${text.slice(0, VALUE_SHOWN_MAX - 1)}…` : text;
  if (v.kind === "address") return clipped;
  if (v.kind === "name") return `${(TYPE_NAMES[v.type ?? -1] ?? `type ${v.type}`).toLowerCase()} ${clipped}`;
  return v.type === undefined ? clipped : `type ${v.type} ${clipped}`;
}

/** The resolver's returned values: `type: N value;` and bare `value;` entries, typed and validated. */
export function readQueryResults(raw: string | undefined): ResultsReading {
  const entries = (raw ?? "")
    .split(";")
    .map((e) => e.trim())
    .filter(Boolean);
  const all = entries.map((e) => {
    const typed = /^type:\s*(\d{1,5})\s+(.*)$/s.exec(e);
    return typed ? classify(Number(typed[1]), typed[2].trim()) : classify(undefined, e);
  });
  const values = all.slice(0, RESULTS_KEPT_MAX).map(boundForEnvelope);
  // The identity covers every parsed value WHOLE, not only the kept ones or their bounded form: two
  // records that agree on the first 64 values, or on a value's first 512 characters, and differ
  // after are two rows, even though the envelope keeps 64 values of 512.
  const identity = all
    .map((v) => `${v.type ?? "-"}:${v.value.length}:${v.value}`)
    .sort()
    .join("|");
  const clipped = all.some(
    (v) => v.value.length > VALUE_SHOWN_MAX || breakHashRuns(showToken(v.value)) !== v.value,
  );
  const head = values.slice(0, RESULTS_SHOWN_MAX);
  // CNAME steps lead with an arrow between them; everything else follows, comma-separated.
  const names = head.filter((v) => v.kind === "name").map(showValue);
  const rest = head.filter((v) => v.kind !== "name").map(showValue);
  const parts = [...names, rest.join(", ")].filter(Boolean).join(" → ");
  const more = all.length > RESULTS_SHOWN_MAX ? ` +${all.length - RESULTS_SHOWN_MAX} more` : "";
  return { values, identity, clipped, shown: all.length ? `${parts}${more}` : "", total: all.length };
}

/** The status field THIS event defines: `QueryStatus` (Sysmon 22, 3008), `Status` (3020), "" (3006). */
export type DnsStatusField = "QueryStatus" | "Status" | "";

// Microsoft-Windows-DNS-Client/Operational — channel-keyed by the Windows mapper like its PowerShell
// table. Each event's own status field per the provider manifest (3020 writes `Status`, 3008
// `QueryStatus`, 3006 none). The shape is the mapper's WinEventDef, spelled here to avoid a cycle.
export const DNS_CLIENT_EVENTS: Record<
  number,
  { label: string; severity: "Info" | "Low"; kind: "dns"; statusField?: "QueryStatus" | "Status" }
> = {
  3006: { label: "DNS query sent", severity: "Info", kind: "dns" },
  3008: { label: "DNS query completed", severity: "Low", kind: "dns", statusField: "QueryStatus" },
  3020: { label: "DNS query result", severity: "Info", kind: "dns", statusField: "Status" },
};

interface DnsOverlayInput {
  field: (key: string) => string;
  has: (key: string) => boolean;
  statusField: DnsStatusField;
  description: string;
}

export interface DnsEnvelope {
  query: string;
  queryValid: boolean;
  queryType?: number;
  status?: number;
  state: DnsState;
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

/** The status the event defines, and the other field when the record carries both and they disagree. */
function statusOf(input: DnsOverlayInput): { reading: StatusReading; key: string; conflict: string } {
  const primary = readQueryStatus(input.statusField ? input.field(input.statusField) : undefined);
  const otherName =
    input.statusField === "Status" ? "QueryStatus" : input.statusField === "QueryStatus" ? "Status" : "";
  const other = otherName && input.has(otherName) ? readQueryStatus(input.field(otherName)) : null;
  const key = primary.code !== undefined ? String(primary.code) : primary.state === "absent" ? "-" : "?";
  if (other?.code !== undefined && primary.code !== undefined && other.code !== primary.code)
    return {
      reading: {
        state: "conflict",
        words: `status fields disagree: ${input.statusField}=${primary.code}, ${otherName}=${other.code}`,
      },
      key: `${primary.code}/${other.code}`,
      conflict: otherName,
    };
  return { reading: primary, key, conflict: "" };
}

/** The overlay for a DNS record over the Windows mapper's description; severity is never graded here. */
export function dnsOverlay(
  read: (key: string) => unknown,
  statusField: DnsStatusField,
  description: string,
): DnsOverlay {
  const text = (v: unknown): string => (typeof v === "string" ? v : v == null ? "" : String(v));
  return overlayOf({
    field: (k) => text(read(k)),
    has: (k) => read(k) !== undefined,
    statusField,
    description,
  });
}

function overlayOf(input: DnsOverlayInput): DnsOverlay {
  const rawName = input.field("QueryName").trim();
  const canonical = rawName.replace(/\.$/, "").toLowerCase();
  const queryValid = isValidQueryName(rawName);
  const shownName = breakHashRuns(showToken(rawName));
  const nameClipped = shownName.length > NAME_SHOWN_MAX;
  const name = nameClipped ? `${shownName.slice(0, NAME_SHOWN_MAX - 1)}…` : shownName;
  const type = typeWords(input.field("QueryType"), input.has("QueryType"));
  const status = statusOf(input);
  const results = readQueryResults(input.field("QueryResults"));

  const tags = [`query: ${name}`];
  if (!queryValid) tags.push("query name is not a valid name");
  tags.push(type.words);
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
  const identity = `|dns:q${canonical.length}:${keyDigest(canonical)}:t${type.key}:s${status.key}:r${
    results.total ? keyDigest(results.identity) : "-"
  }`;

  // Lossy when anything shown is not the record's own text: a neutralised or clipped name, a value
  // omitted past the shown bound, clipped past the value bound, or neutralised.
  const lossy = shownName !== rawName || nameClipped || results.total > RESULTS_SHOWN_MAX || results.clipped;
  // …or a tag packTags had to drop: a dropped `[returned: …]` is evidence the row no longer shows.
  const mark = identityMark(identity);
  const full = packTags(tags, Number.POSITIVE_INFINITY);
  const fits = input.description.length + full.length <= DESCRIPTION_MAX;
  if (!lossy && fits) return { description: `${input.description}${full}`, identity, dns: envelope() };
  const packed = packTags(tags, DESCRIPTION_MAX - mark.length - input.description.length);
  return { description: `${input.description}${packed}${mark}`, identity, dns: envelope() };

  function envelope(): DnsEnvelope {
    return {
      query: canonical,
      queryValid,
      ...(type.type !== undefined ? { queryType: type.type } : {}),
      ...(status.reading.code !== undefined ? { status: status.reading.code } : {}),
      state: status.reading.state,
      returned: results.values,
      ownership: "not in this record",
      vantage: "endpoint",
    };
  }
}
