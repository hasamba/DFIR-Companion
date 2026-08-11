// Per-type IOC value hygiene (#177). An indicator's `value` must be the BARE indicator and nothing
// else: any consumer that validates the field (MISP rejects `10.10.20.15 (DC01)` with "IP address
// has an invalid format"), every exact-match correlation against other tooling, and the value-keyed
// dedup in stateMerge all break the moment a human annotation is concatenated into it.
//
// The deterministic importers already sanitize IPs through siemImport's cleanIp(). The AI extraction
// path did not: responseSchema only requires `value` to be a non-empty string, so whatever the model
// emitted was persisted verbatim — host labels ("10.10.20.15 (DC01)"), descriptive suffixes
// ("northlakeportal.com (exfil endpoint)"), even multi-KB text blobs typed as "ip".
//
// Two functions, deliberately with different strictness:
//
//   repairIocValue()      — INGEST. Splits the annotation into `note`, canonicalizes the indicator,
//                           and returns null ONLY for values that cannot be an indicator at all
//                           (empty, multi-line, absurdly long). A single-line value it cannot
//                           validate is kept verbatim: dropping an analyst's odd-but-real token
//                           would silently lose evidence, which is worse than carrying it.
//   isWellFormedIocValue() — EXPORT. Strict per-type validity, so a push can skip an indicator with
//                           a specific reason instead of collecting a wall of remote 403s.

export interface RepairedIocValue {
  value: string; // the bare indicator
  note?: string; // annotation lifted out of the raw value ("DC01", "exfil endpoint", "port 443")
}

// Longest plausible value per type. Anything past this is a text blob that was mis-typed, not an
// indicator — the only class we drop outright. Unknown types fall back to OTHER_MAX.
const MAX_LEN: Record<string, number> = {
  ip: 45, // longest full IPv6 form
  domain: 253, // RFC 1035 max FQDN
  hash: 128, // SHA-512 hex
  url: 2048, // conventional browser/proxy ceiling
  file: 1024, // generous path
  process: 512,
  sid: 184,
};
const OTHER_MAX = 512;

// Types whose legitimate values never contain a space-separated parenthetical, so a trailing
// "(...)" group is safe to read as an annotation. Path-like types are excluded on purpose:
// "invoice (1).xlsm" is a perfectly ordinary filename.
const ANNOTATABLE = new Set(["ip", "domain", "url", "hash"]);

const IPV4 = /^\d{1,3}(?:\.\d{1,3}){3}$/;
const HASH_LEN = /^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/;
// One or more DNS labels. Single-label hostnames ("DC01") are accepted — they are routinely
// recorded as domain IOCs — as are underscores, which appear in SRV/DKIM records.
const DOMAIN_RE =
  /^(?=.{1,253}$)[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?)*\.?$/;
// Reject the loopback/placeholder addresses that carry no investigative signal, matching cleanIp.
const NOISE_IP = new Set(["::1", "127.0.0.1", "0.0.0.0", "::", "-", "::ffff:127.0.0.1"]);

// Full IPv6 plus every valid "::"-compressed form (mirrors siemImport.ts — a naive "contains a
// colon" check treats any colon-bearing free-text blob as a valid address).
const IPV6_RE =
  /^(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}$|^(?:[0-9a-f]{1,4}:){1,7}:$|^(?:[0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}$|^(?:[0-9a-f]{1,4}:){1,5}(?::[0-9a-f]{1,4}){1,2}$|^(?:[0-9a-f]{1,4}:){1,4}(?::[0-9a-f]{1,4}){1,3}$|^(?:[0-9a-f]{1,4}:){1,3}(?::[0-9a-f]{1,4}){1,4}$|^(?:[0-9a-f]{1,4}:){1,2}(?::[0-9a-f]{1,4}){1,5}$|^[0-9a-f]{1,4}:(?:(?::[0-9a-f]{1,4}){1,6})$|^:(?:(?::[0-9a-f]{1,4}){1,7}|:)$/;

// Private / internal / link-local IPv4 ranges that must NEVER be sent to enrichment providers.
// 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 0.0.0.0/8, 169.254.0.0/16 (link-local / cloud metadata).
function isPrivateIpv4(ip: string): boolean {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return false;
  const [a, b] = parts;
  if (a === 10) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 127) return true;
  if (a === 0) return true;
  if (a === 169 && b === 254) return true;
  return false;
}

// Parses a pure hex-group IPv6 address (no embedded dotted-decimal) into its 8 16-bit groups,
// honoring "::" compression. Returns null for anything that doesn't parse cleanly.
// Exported so anonymize.ts's isMaskableIpv6() can judge an address's high-order group (2000::/3
// global unicast) against the SAME parser that decides mapped/compatible here, rather than
// re-deriving IPv6 syntax a second time and drifting from it.
export function expandIpv6Groups(ip: string): number[] | null {
  const halves = ip.split("::");
  if (halves.length > 2) return null;
  const HEX_GROUP = /^[0-9a-f]{1,4}$/i;
  const parseGroups = (s: string): number[] | null => {
    if (s === "") return [];
    const tokens = s.split(":");
    return tokens.every((t) => HEX_GROUP.test(t)) ? tokens.map((t) => parseInt(t, 16)) : null;
  };
  const head = parseGroups(halves[0]);
  const tail = halves.length === 2 ? parseGroups(halves[1]) : [];
  if (head === null || tail === null) return null;
  if (halves.length === 1) return head.length === 8 ? head : null;
  const missing = 8 - head.length - tail.length;
  return missing >= 1 ? [...head, ...new Array(missing).fill(0), ...tail] : null;
}

// Returns the dotted-decimal IPv4 address embedded in an IPv4-mapped (::ffff:a.b.c.d) or the
// deprecated IPv4-compatible (::a.b.c.d) IPv6 address — from EITHER its dotted-decimal form OR
// its hex-canonicalized form. This matters because anything that re-serializes an IPv6 address
// (e.g. `new URL()`) always does so in hex — "::ffff:127.0.0.1" round-trips as "::ffff:7f00:1" —
// so a check that only recognizes the dotted-decimal spelling silently stops catching
// mapped/compatible addresses wherever the hex form can occur: a prompt-injected
// `http://[::ffff:169.254.169.254]/` cloud-metadata URL, or a hex-form victim IPv6 address in raw
// log text (see anonymize.ts's isInternalIpv6, which imports this to stay in sync — the two
// modules independently classify "is this IPv6 internal" for different purposes, SSRF-guarding
// vs. PII-redaction, but must agree on what an IPv4-mapped address looks like).
export function embeddedIpv4(ip: string): string | null {
  const dotted = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(ip);
  if (dotted) return dotted[1];
  const groups = expandIpv6Groups(ip);
  if (!groups) return null;
  const [g0, g1, g2, g3, g4, g5, g6, g7] = groups;
  const isMapped = g0 === 0 && g1 === 0 && g2 === 0 && g3 === 0 && g4 === 0 && g5 === 0xffff;
  const isCompatible = g0 === 0 && g1 === 0 && g2 === 0 && g3 === 0 && g4 === 0 && g5 === 0;
  if (!isMapped && !isCompatible) return null;
  return [(g6 >> 8) & 0xff, g6 & 0xff, (g7 >> 8) & 0xff, g7 & 0xff].join(".");
}

// Private / internal IPv6 ranges: loopback (::1), unique-local (fc00::/7), link-local (fe80::/10),
// IPv4-mapped/compatible loopback or private (::ffff:127.x.x.x, ::a.b.c.d), unspecified (::).
function isPrivateIpv6(ip: string): boolean {
  const lower = ip.toLowerCase();
  if (lower === "::1" || lower === "::") return true;
  if (lower.startsWith("fc") || lower.startsWith("fd")) return true;
  if (
    lower.startsWith("fe8") ||
    lower.startsWith("fe9") ||
    lower.startsWith("fea") ||
    lower.startsWith("feb")
  )
    return true;
  const mapped = embeddedIpv4(lower);
  if (mapped && isPrivateIpv4(mapped)) return true;
  return false;
}

/** Returns true when the value is an IP or URL host that points at a private/internal target
 *  and must not be enriched (SSRF guard). Checks both bare IPs and the host portion of URLs. */
export function isInternalTarget(value: string, type?: string): boolean {
  const v = value.trim();
  if (!v) return false;
  // Bare IP — check IPv4, IPv6, and any IPv4 embedded in an IPv6 host (mapped/compatible, in
  // either dotted-decimal or hex-canonicalized form).
  if (IPV4.test(v) && isPrivateIpv4(v)) return true;
  if (IPV6_RE.test(v) && isPrivateIpv6(v)) return true;
  const embedded = embeddedIpv4(v);
  if (embedded && isPrivateIpv4(embedded)) return true;
  // URL: extract the host and check if it resolves to a private IP
  if (type === "url" || v.startsWith("http://") || v.startsWith("https://") || v.startsWith("ftp://")) {
    try {
      const host = new URL(v).hostname.replace(/^\[|\]$/g, "");
      if (!host) return false;
      if (IPV4.test(host) && isPrivateIpv4(host)) return true;
      if (IPV6_RE.test(host) && isPrivateIpv6(host)) return true;
      const hostEmbedded = embeddedIpv4(host);
      if (hostEmbedded && isPrivateIpv4(hostEmbedded)) return true;
      // localhost / loopback hostnames
      if (host.toLowerCase() === "localhost" || host === "127.0.0.1") return true;
      return false;
    } catch {
      return false;
    }
  }
  // Domain that looks like a loopback hostname (bare "localhost" or any "*.localhost" subdomain)
  if (type === "domain") {
    const lower = v.toLowerCase();
    if (lower === "localhost" || lower.endsWith(".localhost")) return true;
  }
  return false;
}

function isValidIp(v: string): boolean {
  if (NOISE_IP.has(v)) return false;
  if (IPV4.test(v)) return v.split(".").every((o) => Number(o) <= 255);
  return IPV6_RE.test(v) && !/^fe80:/i.test(v);
}

// Strict per-type validity of an ALREADY-TRIMMED value. Free-form types (file, process, sid, other,
// and anything outside the union) have no canonical shape, so any non-empty single-line value passes.
export function isWellFormedIocValue(type: string, value: string): boolean {
  const v = value.trim();
  if (!v) return false;
  if (v.length > (MAX_LEN[type] ?? OTHER_MAX)) return false;
  if (/[\r\n\t]/.test(v)) return false;
  switch (type) {
    case "ip":
      return isValidIp(v);
    case "hash":
      return HASH_LEN.test(v.toLowerCase());
    case "domain":
      return DOMAIN_RE.test(v.toLowerCase());
    case "url":
      return !/\s/.test(v) && /[./]/.test(v);
    default:
      return true;
  }
}

// Canonicalize a value that is already believed to be of `type`. Returns "" when it does not
// canonicalize (the caller then keeps the raw value, or tries the other half of an annotation).
function canonicalize(type: string, v: string): string {
  switch (type) {
    case "ip": {
      const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(v);
      const bare = mapped ? mapped[1] : v;
      return isValidIp(bare) ? bare : "";
    }
    // Case is PRESERVED. Validation is case-insensitive (DNS and hex digests both are), but the
    // stored value keeps the casing it was first seen with — dedup is already case-insensitive, so
    // rewriting the case would change what analysts see for no correlation benefit.
    case "hash":
      return HASH_LEN.test(v.toLowerCase()) ? v : "";
    case "domain":
      return DOMAIN_RE.test(v.toLowerCase()) ? v.replace(/\.$/, "") : "";
    case "url":
      return isWellFormedIocValue("url", v) ? v : "";
    default:
      return v;
  }
}

// A trailing parenthetical that is SEPARATED BY WHITESPACE — "10.10.20.15 (DC01)". The whitespace
// requirement is what keeps "…/wiki/Foo_(bar)" intact: there, the parens belong to the indicator.
const ANNOTATION_RE = /^([^()]*\S)\s+\(([^()]+)\)$/;

export function repairIocValue(ioc: { type: string; value: string }): RepairedIocValue | null {
  const type = ioc.type;
  const raw = (ioc.value ?? "").trim();
  if (!raw) return null;
  // Multi-line or oversized: this is a text blob that was mis-typed as an indicator (a whole
  // PowerShell help page stored as an "ip"), not an annotated indicator. Nothing to salvage.
  if (/[\r\n]/.test(raw)) return null;
  if (raw.length > (MAX_LEN[type] ?? OTHER_MAX)) return null;

  const withNote = (value: string, note?: string): RepairedIocValue => {
    const n = note?.trim();
    return n && n.toLowerCase() !== value.toLowerCase() ? { value, note: n } : { value };
  };

  if (ANNOTATABLE.has(type)) {
    const m = ANNOTATION_RE.exec(raw);
    if (m) {
      const outside = m[1].trim();
      const inside = m[2].trim();
      // Whichever half canonicalizes as this type is the indicator; the other half is the note.
      // Covers both "10.10.20.15 (DC01)" and the reversed "FS01 (10.10.20.30)".
      const fromOutside = canonicalize(type, outside);
      if (fromOutside) return withNote(fromOutside, inside);
      const fromInside = canonicalize(type, inside);
      if (fromInside) return withNote(fromInside, outside);
    }
  }

  // "185.220.101.47:443" — the port is context, not part of the address.
  if (type === "ip") {
    const withPort = /^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$/.exec(raw);
    if (withPort && isValidIp(withPort[1])) return withNote(withPort[1], `port ${withPort[2]}`);
  }

  const canonical = canonicalize(type, raw);
  // Kept verbatim when it does not canonicalize: a single-line token we do not recognise may still
  // be real evidence. isWellFormedIocValue() is what export layers gate on.
  return { value: canonical || raw };
}
