// The words of a sensor-side DNS row (#996). Every record-written text — the query, a returned
// value, an owner name, an unknown response code — is shown inside its own named span through
// showToken, so no field can spell a tag beside the row's own, and correlate.ts skips the spans
// when it scrapes free text for a hash or a path. A lead is worded as what the connection records
// establish: order and address, a reply or its absence — never "resolved", never "C2".

import type { AlsoBefore, DnsChain, Lead } from "./dnsConnJoin.js";
import { DNS_WINDOW_SLACK_S } from "./dnsConnJoin.js";
import type { DnsObservation, ReturnedWire } from "./dnsWireRead.js";
import { breakHashRuns, showToken } from "./recordIdentity.js";

const RETURNED_SHOWN_MAX = 8;
const VALUE_SHOWN_MAX = 60;
const NAME_SHOWN_MAX = 120;
const SHORT_MAX = 80;

const show = (v: string, max: number): string => {
  const shown = breakHashRuns(showToken(v));
  return shown.length > max ? `${shown.slice(0, max - 1)}…` : shown;
};

// ───────────────────────────── head ─────────────────────────────

/** What the response code establishes, in the record's own words where the code is not in the table. */
export function outcomeWords(d: DnsObservation): string {
  if (d.rejected) return "rejected by the server";
  // A Zeek line with no rcode saw no response; a Suricata answer event IS the response.
  if (!d.rcode) return d.anchor === "answer" ? "response code not in this record" : "no response recorded";
  switch (d.rcode) {
    case "NOERROR":
      return d.returnedTotal ? "answered" : "NOERROR — no records of the queried type";
    case "NXDOMAIN":
      return "NXDOMAIN — the name does not exist at this server";
    case "SERVFAIL":
      return "SERVFAIL — server failure";
    case "REFUSED":
      return "REFUSED";
    default:
      return `[rcode: ${d.rcode}]`;
  }
}

/** The state word the envelope carries for the outcome. */
export function outcomeState(d: DnsObservation): string {
  if (d.rejected) return "rejected";
  if (!d.rcode) return d.anchor === "answer" ? "rcode-not-in-record" : "no-response";
  if (d.rcode === "NOERROR") return d.returnedTotal ? "answered" : "no-records";
  return d.rcode.toLowerCase();
}

// The two ends as the record names them: `a → b` when the record says which end asked, `a ↔ b
// (direction not in this record)` when it does not, and what is missing when an end is.
function endsWords(d: DnsObservation): string {
  if (d.ends)
    return d.ends.direction === "client → server"
      ? `${d.ends.a} → ${d.ends.b}`
      : `${d.ends.a} ↔ ${d.ends.b} (direction not in this record)`;
  return `${d.client ?? "client not in this record"} → ${d.server ?? "server not in this record"}`;
}

export function dnsHead(d: DnsObservation): string {
  const query = d.query ? show(d.query, NAME_SHOWN_MAX) : "(not in this record)";
  const type = d.queryTypeName ?? (d.queryType !== undefined ? `type ${d.queryType}` : "");
  return `DNS ${endsWords(d)}: [query: ${query}]${type ? ` ${type}` : ""} → ${outcomeWords(d)}`;
}

/** ` @ sensor` when the record names one — the sensor is identity, so it is shown. */
export const sensorWords = (d: DnsObservation): string =>
  d.observer ? ` @ ${show(d.observer.name, SHORT_MAX)}` : "";

// ───────────────────────────── returned values ─────────────────────────────

function valueWords(v: ReturnedWire, owners: boolean): string {
  const type = v.typeName ?? (v.type !== undefined ? `type ${v.type}` : "");
  const shown = v.kind === "other" ? show(v.value, VALUE_SHOWN_MAX) : show(v.value, NAME_SHOWN_MAX);
  const owner = owners && v.owner ? `${show(v.owner, NAME_SHOWN_MAX)} ` : "";
  return `${owner}${type ? `${type} ` : ""}${shown}`;
}

/** `[returned: …]` (owner-less) or `[answers: owner TYPE value; …]` (owners stated), bounded. */
export function returnedTag(d: DnsObservation): string | undefined {
  if (!d.returnedTotal) return undefined;
  const owners = d.ownership === "stated in the record";
  const shown = d.returned.slice(0, RETURNED_SHOWN_MAX).map((v) => valueWords(v, owners));
  const more = d.returnedTotal - shown.length;
  const tail = more > 0 ? ` +${more} more${d.returnedTotal > d.returned.length ? " (not read)" : ""}` : "";
  return `${owners ? "answers" : "returned"}: ${shown.join(owners ? "; " : ", ")}${tail}`;
}

// ───────────────────────────── leads ─────────────────────────────

const replyWords = (l: Lead): string =>
  l.reply && l.reply !== "reply not in this record" ? ` — ${l.reply}` : "";

const alsoWords = (a: AlsoBefore | undefined): string =>
  a === "began before this answer arrived"
    ? "; a record also began before this answer arrived"
    : a === "open at the time of this answer"
      ? "; a connection was also open at the time of this answer"
      : "";

export function leadTag(l: Lead, client: string): string {
  const shared =
    (l.sharedWithOtherNames ? " — also returned for other names to this client inside the window" : "") +
    alsoWords(l.alsoBefore);
  let words: string;
  switch (l.state) {
    case "connected inside the window":
      words = `connection record ${l.band} after the answer arrived, inside the window${replyWords(l)}`;
      break;
    case "first connection after the window":
      words = `first connection record ${l.band} after the answer arrived — after the window${replyWords(l)}`;
      break;
    case "began before this answer arrived":
      words = `a connection record began before this answer arrived${replyWords(l)}`;
      break;
    case "open at the time of this answer":
      words = `a connection open at the time of this answer — started before it${replyWords(l)}`;
      break;
    case "earlier connections only":
      words = "earlier connection records only — none after this answer";
      break;
    case "other clients connected inside the window":
      words = `no connection from ${client}; other clients connected inside the window — the record does not say they used this answer`;
      break;
    default:
      words = `no connection from ${client} in this upload`;
  }
  return `${l.address}: ${words}${shared}`;
}

/** The lead tags split: in-window leads (packed first of all), then the rest in address order. */
export function leadTags(c: DnsChain): { inWindow: string[]; rest: string[] } {
  const client = c.dns.client ?? "the client";
  const tag = (l: Lead): string => leadTag(l, client);
  return {
    inWindow: c.leads.filter((l) => l.state === "connected inside the window").map(tag),
    rest: c.leads.filter((l) => l.state !== "connected inside the window").map(tag),
  };
}

/**
 * The window every lead was read against, with its basis; a range when the row folded TTLs.
 * Narrowed to the two fields actually read (not the full `DnsChain`) so the Windows/endpoint join
 * (siemDnsConnJoin.ts, #996) can reuse this wording without fabricating a Zeek `DnsObservation`.
 */
export function windowTag(
  c: Pick<DnsChain, "joinState" | "leads">,
  ttl: { min: number; max: number } | undefined,
): string | undefined {
  if (c.joinState !== "joined" || !c.leads.length) return undefined;
  const bases = new Set(c.leads.map((l) => l.window.basis));
  const range = ttl ? (ttl.min === ttl.max ? `${ttl.min} s` : `${ttl.min}–${ttl.max} s`) : "";
  if (bases.size === 1 && bases.has("ttl")) return `window: TTL ${range} +${DNS_WINDOW_SLACK_S} s`;
  const fixed = c.leads.find((l) => l.window.basis === "fixed")!.window.seconds;
  if (bases.size === 1) return `window: fixed ${fixed} s — no TTL in this record`;
  return `window: TTL ${range} +${DNS_WINDOW_SLACK_S} s where the record carries one, else fixed ${fixed} s`;
}

/** Narrowed to `joinState` alone — same reuse reason as `windowTag` above. */
export function joinTag(c: Pick<DnsChain, "joinState">): string | undefined {
  switch (c.joinState) {
    case "no connection records in this upload":
      return "connection join: no connection records in this upload";
    case "connection records exceed the index":
      return "connection join: connection records exceed the index — not joined";
    case "answered with no address":
      return "no address returned — no connection can be matched";
    case "client not joinable":
      return "connection join: the asking address is not one a sensor's connection records can be matched to (loopback, link-local, multicast, or not in the record)";
    case "connection records not placeable":
      return "connection join: the upload's connection records carry no start time — not joined";
    default:
      return undefined;
  }
}

/**
 * Every tag of the row: the in-window leads first (the fact the row ranks on can never be the
 * one the length bound drops), then the values, the other leads, the window, the flags.
 */
export function dnsTags(c: DnsChain, ttl: { min: number; max: number } | undefined): string[] {
  const d = c.dns;
  const leads = leadTags(c);
  const tags: string[] = [...leads.inWindow];
  if (d.query && !d.queryValid) tags.push("query name is not a valid name");
  const returned = returnedTag(d);
  if (returned) tags.push(returned);
  tags.push(...leads.rest);
  const window = windowTag(c, ttl);
  if (window) tags.push(window);
  const join = joinTag(c);
  if (join) tags.push(join);
  if (d.aa) tags.push("authoritative answer");
  return tags;
}
