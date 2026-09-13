// The words of a sensor-side DNS row (#996). Every record-written text — the query, a returned
// value, an owner name, an unknown response code — is shown inside its own named span through
// showToken, so no field can spell a tag beside the row's own, and correlate.ts skips the spans
// when it scrapes free text for a hash or a path. A lead is worded as what the connection records
// establish: order and address, a reply or its absence — never "resolved", never "C2".

import type { DnsChain, Lead } from "./dnsConnJoin.js";
import { DNS_WINDOW_SLACK_S } from "./dnsConnJoin.js";
import type { DnsObservation, ReturnedWire } from "./dnsWireRead.js";
import { breakHashRuns, showToken } from "./recordIdentity.js";

const RETURNED_SHOWN_MAX = 8;
const VALUE_SHOWN_MAX = 60;
const NAME_SHOWN_MAX = 120;

const show = (v: string, max: number): string => {
  const shown = breakHashRuns(showToken(v));
  return shown.length > max ? `${shown.slice(0, max - 1)}…` : shown;
};

// ───────────────────────────── head ─────────────────────────────

/** What the response code establishes, in the record's own words where the code is not in the table. */
export function outcomeWords(d: DnsObservation): string {
  if (d.rejected) return "rejected by the server";
  if (!d.rcode) return "no response recorded";
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
  if (!d.rcode) return "no-response";
  if (d.rcode === "NOERROR") return d.returnedTotal ? "answered" : "no-records";
  return d.rcode.toLowerCase();
}

export function dnsHead(d: DnsObservation): string {
  const query = d.query ? show(d.query, NAME_SHOWN_MAX) : "(not in this record)";
  const type = d.queryTypeName ?? (d.queryType !== undefined ? `type ${d.queryType}` : "");
  return `DNS ${d.client ?? "client not in this record"} → ${d.server ?? "server not in this record"}: [query: ${query}]${type ? ` ${type}` : ""} → ${outcomeWords(d)}`;
}

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

export function leadTag(l: Lead, client: string): string {
  const shared = l.sharedWithOtherNames
    ? " — also returned for other names to this client inside the window"
    : "";
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
    case "connection records exceed the index":
      words = "connection records exceed the index — not joined";
      break;
    default:
      words = `no connection from ${client} in this upload`;
  }
  return `${l.address}: ${words}${shared}`;
}

/** In-window leads first, then the rest in address order. */
export function leadTags(c: DnsChain): string[] {
  const client = c.dns.client ?? "the client";
  const inWindow = c.leads.filter((l) => l.state === "connected inside the window");
  const rest = c.leads.filter((l) => l.state !== "connected inside the window");
  return [...inWindow, ...rest].map((l) => leadTag(l, client));
}

/** The window every lead was read against, with its basis; a range when the row folded TTLs. */
export function windowTag(c: DnsChain, ttl: { min: number; max: number } | undefined): string | undefined {
  if (c.joinState !== "joined" || !c.leads.length) return undefined;
  const bases = new Set(c.leads.map((l) => l.window.basis));
  const range = ttl ? (ttl.min === ttl.max ? `${ttl.min} s` : `${ttl.min}–${ttl.max} s`) : "";
  if (bases.size === 1 && bases.has("ttl")) return `window: TTL ${range} +${DNS_WINDOW_SLACK_S} s`;
  const fixed = c.leads.find((l) => l.window.basis === "fixed")!.window.seconds;
  if (bases.size === 1) return `window: fixed ${fixed} s — no TTL in this record`;
  return `window: TTL ${range} +${DNS_WINDOW_SLACK_S} s where the record carries one, else fixed ${fixed} s`;
}

export function joinTag(c: DnsChain): string | undefined {
  switch (c.joinState) {
    case "no connection records in this upload":
      return "connection join: no connection records in this upload";
    case "connection records exceed the index":
      return "connection join: connection records exceed the index — not joined";
    case "answered with no address":
      return "no address returned — no connection can be matched";
    default:
      return undefined;
  }
}

/** Every tag of the row, in evidence order: the values, the leads, the window, the flags. */
export function dnsTags(c: DnsChain, ttl: { min: number; max: number } | undefined): string[] {
  const d = c.dns;
  const tags: string[] = [];
  if (d.query && !d.queryValid) tags.push("query name is not a valid name");
  const returned = returnedTag(d);
  if (returned) tags.push(returned);
  tags.push(...leadTags(c));
  const window = windowTag(c, ttl);
  if (window) tags.push(window);
  const join = joinTag(c);
  if (join) tags.push(join);
  if (d.aa) tags.push("authoritative answer");
  return tags;
}
