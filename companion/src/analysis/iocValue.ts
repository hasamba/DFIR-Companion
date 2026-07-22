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
  value: string;   // the bare indicator
  note?: string;   // annotation lifted out of the raw value ("DC01", "exfil endpoint", "port 443")
}

// Longest plausible value per type. Anything past this is a text blob that was mis-typed, not an
// indicator — the only class we drop outright. Unknown types fall back to OTHER_MAX.
const MAX_LEN: Record<string, number> = {
  ip: 45,        // longest full IPv6 form
  domain: 253,   // RFC 1035 max FQDN
  hash: 128,     // SHA-512 hex
  url: 2048,     // conventional browser/proxy ceiling
  file: 1024,    // generous path
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
const DOMAIN_RE = /^(?=.{1,253}$)[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?)*\.?$/;
// Reject the loopback/placeholder addresses that carry no investigative signal, matching cleanIp.
const NOISE_IP = new Set(["::1", "127.0.0.1", "0.0.0.0", "::", "-", "::ffff:127.0.0.1"]);
// Full IPv6 plus every valid "::"-compressed form (mirrors siemImport.ts — a naive "contains a
// colon" check treats any colon-bearing free-text blob as a valid address).
const IPV6_RE =
  /^(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}$|^(?:[0-9a-f]{1,4}:){1,7}:$|^(?:[0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}$|^(?:[0-9a-f]{1,4}:){1,5}(?::[0-9a-f]{1,4}){1,2}$|^(?:[0-9a-f]{1,4}:){1,4}(?::[0-9a-f]{1,4}){1,3}$|^(?:[0-9a-f]{1,4}:){1,3}(?::[0-9a-f]{1,4}){1,4}$|^(?:[0-9a-f]{1,4}:){1,2}(?::[0-9a-f]{1,4}){1,5}$|^[0-9a-f]{1,4}:(?:(?::[0-9a-f]{1,4}){1,6})$|^:(?:(?::[0-9a-f]{1,4}){1,7}|:)$/;

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
    case "ip":     return isValidIp(v);
    case "hash":   return HASH_LEN.test(v.toLowerCase());
    case "domain": return DOMAIN_RE.test(v.toLowerCase());
    case "url":    return !/\s/.test(v) && /[./]/.test(v);
    default:       return true;
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
    case "hash":   return HASH_LEN.test(v.toLowerCase()) ? v : "";
    case "domain": return DOMAIN_RE.test(v.toLowerCase()) ? v.replace(/\.$/, "") : "";
    case "url":    return isWellFormedIocValue("url", v) ? v : "";
    default:       return v;
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
