// Windows DNS Server Analytical log (channel `Microsoft-Windows-DNSServer/Analytical`), events
// 257/258/259 — the resolver's OWN record of a query it answered, failed, or ignored (#996,
// import only this pass: no join to any endpoint-side stub-resolver record — that needs
// cross-upload host-identity infrastructure this pass does not build). Confirmed against
// Microsoft's own published event-text templates, not recalled:
// https://learn.microsoft.com/windows-server/networking/dns/dns-logging-and-diagnostics
// Event 256 is NOT in that table (it starts at 257) and is not read here.
//
// A manifest event's `%N` message-template ordinals map 1:1 to the raw EventData's `Data`
// elements in the SAME order — standard Windows ETW behaviour. Whether the DNS Server provider's
// manifest also NAMES each Data element (`Name="QNAME"`, mirroring the template's own tokens, the
// way Sysmon's manifest does) is unverified against a real capture — no sample was available.
// Every field is read by name first, falling back to the documented ordinal position, so either
// export shape is handled — but which one a real DNS Server actually emits stays unconfirmed.

import { asciiName, isIndicatorName, isValidQueryName, TYPE_NAMES } from "./dnsRecord.js";
import { breakHashRuns, identityMark, keyDigest, packTags, showToken } from "./recordIdentity.js";
import type { DnsBlock } from "./canonicalDns.js";

const NAME_SHOWN_MAX = 180;
const DESCRIPTION_MAX = 600;

/** RFC 1035 §4.1.1 response codes — a different enumeration from dnsRecord.ts's Win32 DNS_STATUS table. */
const RCODE_NAMES: Record<number, string> = {
  0: "NOERROR",
  1: "FORMERR",
  2: "SERVFAIL",
  3: "NXDOMAIN",
  4: "NOTIMP",
  5: "REFUSED",
};

export type DnsServerEid = 257 | 258 | 259;

/** Field → ordinal EventData position, per event, from Microsoft's own message templates above. */
const FIELD_ORDINALS: Record<DnsServerEid, Record<string, number>> = {
  257: { Destination: 3, QNAME: 6, QTYPE: 7, XID: 8, RCODE: 10 },
  258: { Reason: 3, Destination: 4, QNAME: 5, QTYPE: 6, XID: 7, RCODE: 8 },
  259: { Reason: 3, QNAME: 4, QTYPE: 5, XID: 6 }, // no Destination in this template — no client here
};

export function isDnsServerAnalyticEid(eid: number): eid is DnsServerEid {
  return eid === 257 || eid === 258 || eid === 259;
}

export interface DnsServerOverlay {
  description: string;
  identity: string;
  dns: DnsBlock;
}

/** The overlay for a DNS Server Analytical record (257/258/259) over the Windows mapper's description. */
export function dnsServerOverlay(
  read: (key: string) => unknown,
  eid: DnsServerEid,
  description: string,
): DnsServerOverlay {
  const text = (v: unknown): string => {
    if (typeof v === "string") return v;
    if (v == null) return "";
    if (Array.isArray(v)) return v.map(text).filter(Boolean).join(";");
    return String(v);
  };
  const has = (k: string) => read(k) !== undefined;
  const field = (name: string): string => {
    if (has(name)) return text(read(name)).trim();
    const ord = FIELD_ORDINALS[eid][name];
    const posKey = ord ? `Data${ord}` : undefined;
    return posKey && has(posKey) ? text(read(posKey)).trim() : "";
  };

  const rawName = field("QNAME");
  const queryValid = isValidQueryName(rawName);
  const canonical = queryValid ? asciiName(rawName).toLowerCase() : rawName;
  const shownName = breakHashRuns(showToken(rawName));
  const name = shownName.length > NAME_SHOWN_MAX ? `${shownName.slice(0, NAME_SHOWN_MAX - 1)}…` : shownName;

  const qtypeRaw = field("QTYPE");
  const queryType = /^\d{1,5}$/.test(qtypeRaw) ? Number(qtypeRaw) : undefined;
  const typeWords =
    queryType !== undefined
      ? `${TYPE_NAMES[queryType] ?? `type ${queryType}`} query`
      : "type not in this record";

  const client = field("Destination");
  const xid = field("XID");
  const rcodeRaw = field("RCODE");
  const rcodeNum = /^\d{1,3}$/.test(rcodeRaw) ? Number(rcodeRaw) : undefined;
  const rcode = rcodeNum !== undefined ? (RCODE_NAMES[rcodeNum] ?? `RCODE ${rcodeNum}`) : undefined;
  const reason = field("Reason");

  const tags = [`query: ${name}`, typeWords];
  if (!queryValid && rawName) tags.push("query name is not a valid name");
  if (client) tags.push(`asked by ${client}`);

  let state: string;
  if (eid === 257) {
    state = "answered";
    tags.push(`answered${rcode ? ` (${rcode})` : ""} — the returned values are not read by this importer`);
  } else if (eid === 258) {
    state = "response failure";
    tags.push(`response failed${rcode ? ` (${rcode})` : ""}${reason ? ` — ${reason}` : ""}`);
  } else {
    state = "ignored";
    tags.push(`ignored by the server${reason ? ` — ${reason}` : ""}`, "no client address in this record");
  }

  const identity = `|dnssrv:e${eid}:q${canonical.length}:${keyDigest(canonical)}:t${queryType ?? "-"}:x${xid || "-"}`;
  const prefix = showToken(description);
  const mark = identityMark(`${description}${identity}`);
  const full = packTags(tags, Number.POSITIVE_INFINITY);
  const fits = prefix.length + full.length <= DESCRIPTION_MAX;
  const lossy = shownName !== rawName || name !== shownName;
  const renderedDescription =
    !lossy && fits && prefix === description
      ? `${prefix}${full}`
      : `${prefix}${packTags(tags, DESCRIPTION_MAX - mark.length - prefix.length)}${mark}`;

  const dns: DnsBlock = {
    query: canonical,
    queryValid,
    indicator: isIndicatorName(rawName),
    ...(queryType !== undefined ? { queryType } : {}),
    state,
    returned: [],
    ownership: "not in this record",
    vantage: "resolver",
    ...(client ? { client } : {}),
    ...(rcode ? { rcode } : {}),
    ...(xid ? { xid } : {}),
  };

  return { description: renderedDescription, identity, dns };
}
