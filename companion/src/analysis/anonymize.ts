import type { InvestigationState } from "./stateTypes.js";
import { extractAccounts } from "./assetGraph.js";
import { embeddedIpv4, expandIpv6Groups } from "./iocValue.js";

// Reversible anonymization of the TEXT sent to the LLM. Real values stay in state; only the
// wire is tokenized. Typed numbered tokens keep the model's semantic understanding (it still
// knows ANON_HOST_1 is a host) and within-call correlation (same value → same token). Restore
// walks the model's PARSED JSON response (not the raw string) so real values containing JSON
// metacharacters — e.g. a Windows path's backslashes — never corrupt parsing.

export type AnonCategory =
  | "IP" | "EMAIL" | "USER" | "HOST" | "DOMAIN" | "PATH" | "CMD" | "REG"
  | "CARD" | "PHONE" | "NATID";

// OTHER and EXTIP are token-only: they never appear in the per-case `categories` toggle map.
// EXTIP is produced by the IP detector when maskPublicIps is on, so a public address stays
// distinguishable from an internal one in the token the model reads.
//
// PERSON is token-only: there is no local detector for it. It is minted solely from Presidio
// findings, which arrive as custom entities.
export type AnonTokenCategory = AnonCategory | "OTHER" | "EXTIP" | "PERSON";

// The single source of truth for every category assign() can mint. Declaring it as a
// Record<AnonTokenCategory, true> makes TypeScript reject any new union member that is not
// listed here — which is what stops a new category from silently failing to restore.
const TOKEN_CATEGORY_KEYS: Record<AnonTokenCategory, true> = {
  IP: true, EXTIP: true, EMAIL: true, USER: true, HOST: true,
  DOMAIN: true, PATH: true, CMD: true, REG: true,
  CARD: true, PHONE: true, NATID: true, PERSON: true, OTHER: true,
};

export const ALL_TOKEN_CATEGORIES = Object.keys(TOKEN_CATEGORY_KEYS) as readonly AnonTokenCategory[];

// Longest-first so no category can be shadowed by another that is a prefix of it.
const TOKEN_ALTERNATION = [...ALL_TOKEN_CATEGORIES].sort((a, b) => b.length - a.length).join("|");
const TOKEN_RE = new RegExp(`ANON_(?:${TOKEN_ALTERNATION})_\\d+`, "gi");

/** True when the whole string is a single anonymization token. Used to drop Presidio findings
 *  that fired on a token rather than on real text. Builds a fresh non-global regex per call so
 *  it never shares lastIndex state with TOKEN_RE. */
export function isAnonToken(s: string): boolean {
  return new RegExp(`^ANON_(?:${TOKEN_ALTERNATION})_\\d+$`, "i").test(s.trim());
}

export interface CustomEntity {
  value: string;
  category: AnonTokenCategory;
}

export interface AnonPolicy {
  enabled: boolean;
  categories: Record<AnonCategory, boolean>;
  redactSecrets: boolean;
  // When true, PUBLIC addresses are tokenized as ANON_EXTIP_n as well. True on the AI wire
  // (nothing about an address is asked of the model, and restore() puts it back). False for
  // the redacted export, where the recipient needs adversary infrastructure to stay actionable.
  maskPublicIps: boolean;
}

// Known victim entities derived from the case, used for high-precision exact-match tokenizing
// of things regex can't reliably find (usernames, hostnames) and to decide which domains/UPNs
// are "internal" (tokenize) vs third-party/adversary (preserve).
export interface KnownEntities {
  hosts: string[];          // victim hostnames / FQDNs (longest-first)
  accounts: string[];       // DOMAIN\user or user@domain
  internalDomains: string[]; // AD/email domains to tokenize (lowercased, longest-first)
  custom?: CustomEntity[];   // analyst-added + auto-discovered exact-match entities (tokenized when enabled)
  // Values the analyst REMOVED from auto-discovery (lowercased). Never tokenized — even when a
  // pattern would match — so removing a false positive (e.g. a mis-matched path) actually stops it
  // being redacted. Checked at the single assign() chokepoint, so it covers every matcher.
  suppressed?: string[];
}

export interface Anonymizer {
  apply(text: string): string;
  restore(text: string): string;
  restoreDeep<T>(value: T): T;
  // The entities this anonymizer tokenized so far (across apply() calls), with their category —
  // used to feed OCR-discovered entities back into the case's auto-discovery list. Never includes
  // one-way secrets (those are redacted to a placeholder, not minted as a reversible token).
  discoveries(): CustomEntity[];
}

export const SECRET_PLACEHOLDER = "[REDACTED_SECRET]";

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// Exact-match tokenizing of a KNOWN value (hostname, internal domain, analyst-added or
// Presidio-approved custom entity) needs a word boundary so "DC01" doesn't fire inside "DC01X"
// and "Jane" doesn't fire inside "Janes". JS `\b` CANNOT be used for that here: it is defined
// against ASCII `\w` ([A-Za-z0-9_]), so a value whose first or last character is outside that
// set — every Hebrew, Cyrillic, Greek, CJK or accented name, and anything starting with "+" —
// puts `\b` between two non-word characters, where it never matches. The value was then NEVER
// masked, silently and permanently: once approved it lives in known.custom, so the Presidio
// gate sees it as already-known and never asks again, and the analyst is told it is tokenized
// while it goes to the provider (and into the redacted export) in cleartext. This branch ships
// Israeli Teudat Zehut and Israeli phone detectors, so non-Latin values are the target domain.
//
// The replacement is an explicit Unicode-aware boundary: refuse to match when the character
// immediately before/after is a letter, a number or "_" in ANY script. That keeps the
// anti-substring property for ASCII while making it work for every other script.
//
// This is deliberately NOT `\b`-equivalent in both directions, and the difference is worth
// knowing. `\b` is a TRANSITION test, so for a value whose own edge is a non-word character it
// inverts: `\b-corp\b` DID fire inside "ACME-corp", and `\b\.local\b` DID fire inside
// "corp.local", because the neighbouring "E"/"p" supplied the transition. These lookarounds ask
// only "is the neighbour a word character", so neither fires now. That is the correct reading of
// the anti-substring rule — a value should not match glued inside a longer word — and it is
// unreachable from the case-derived lists, whose values are whole hostnames and domains. It IS
// reachable from ANALYST-TYPED custom entities: someone entering ".corp.local" as a suffix
// expecting it to catch "dc01.corp.local" gets no match. Enter the whole value ("dc01.corp.local")
// or rely on known.internalDomains, which already handles the parent-domain case.
//
// The `u` flag
// is required for \p{…} and is safe with escapeRegExp above: every character it escapes
// (. * + ? ^ $ { } ( ) | [ ] \) is a SyntaxCharacter, i.e. a legal identity escape in Unicode
// mode, so no escaped value can turn into an "Invalid regular expression" under `u`.
const UNICODE_WORD = "\\p{L}\\p{N}_";
function exactValueRegExp(value: string): RegExp {
  return new RegExp(`(?<![${UNICODE_WORD}])${escapeRegExp(value)}(?![${UNICODE_WORD}])`, "giu");
}

// RFC1918 + loopback + link-local + CGNAT = "internal/victim" IPv4s we tokenize as ANON_IP_n.
// A public IP is frequently adversary C2 — classification here is unchanged by maskPublicIps;
// it's the CALLER (anonIps in createAnonymizer) that decides whether a non-internal address is
// tokenized as ANON_EXTIP_n (AI wire) or left visible (redacted export), never this function.
export function isInternalIp(ip: string): boolean {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  if (!m) return false;
  const [a, b] = [Number(m[1]), Number(m[2])];
  if ([a, b, Number(m[3]), Number(m[4])].some((n) => n > 255)) return false;
  if (a === 10 || a === 127) return true;
  if (a === 192 && b === 168) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT 100.64/10
  return false;
}

// IPV4_RE is a DETECTOR, not a validator — \d{1,3} happily matches 999. Before treating a
// non-internal match as an address worth masking, require four in-range octets and exclude
// ranges that are never adversary infrastructure. This also spares the most common collision:
// four-part software version strings such as "1.0.0.0" still match the regex, so anything we
// can rule out structurally is worth ruling out.
export function isMaskableIpv4(ip: string): boolean {
  const parts = ip.split(".");
  if (parts.length !== 4) return false;
  const nums = parts.map((p) => Number(p));
  if (nums.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return false;
  if (nums[0] === 0) return false;     // 0.0.0.0/8 "this network"
  if (nums[0] >= 224) return false;    // 224/4 multicast, 240/4 reserved, 255.255.255.255 broadcast
  return true;
}

// NAT64 well-known prefix 64:ff9b::/96 (RFC 6052 §2.1). embeddedIpv4() deliberately does not
// cover this: it recognizes only the all-zero mapped (::ffff:0:0/96) and compatible (::/96)
// prefixes, so "64:ff9b::c000:201" parses as a perfectly well-formed literal whose first group
// is 0x0064 — outside 2000::/3 — and both isMaskableIpv6() and isInternalIpv6() said "no",
// leaving the address completely untouched. 64:ff9b::/96 is a real, allocated, routable prefix
// that appears wherever an IPv6-only network reaches IPv4, so "mask every IP on the wire" has to
// cover it.
//
// The embedded IPv4 is the last 32 bits, i.e. groups[6] and groups[7] — verified against
// expandIpv6Groups(), which zero-fills "::" in the middle: "64:ff9b::c000:201" expands to
// [0x0064, 0xff9b, 0, 0, 0, 0, 0xc000, 0x0201] → 192.0.2.1.
//
// Only the WELL-KNOWN /96 prefix is decoded. RFC 6052 also permits network-specific prefixes at
// /32…/64, where the embedded IPv4 straddles the u-octet at bits 64-71 and its position depends
// on a prefix length that is not recoverable from the address text, and RFC 8215 reserves
// 64:ff9b:1::/48 for local use with the same ambiguity. Guessing there would mint garbage
// tokens; those addresses fall through to the normal 2000::/3 test (which rejects them), same
// as before.
function nat64EmbeddedIpv4(groups: number[]): string | null {
  if (groups[0] !== 0x0064 || groups[1] !== 0xff9b) return null;
  if (groups[2] !== 0 || groups[3] !== 0 || groups[4] !== 0 || groups[5] !== 0) return null;
  return [(groups[6] >> 8) & 0xff, groups[6] & 0xff, (groups[7] >> 8) & 0xff, groups[7] & 0xff].join(".");
}

// IPv6: loopback, unique-local (fc00::/7), link-local (fe80::/10), IPv4-mapped/compatible
// (::ffff:x.x.x.x or its hex-canonicalized form). As with isInternalIp(), classification here is
// unchanged by maskPublicIps — the caller decides whether a non-internal address becomes
// ANON_EXTIP_n or stays visible. The mapped/compatible check delegates extraction to iocValue.ts's
// embeddedIpv4() rather than re-deriving it here: a naive dotted-decimal-only regex misses the
// hex-canonical spelling (e.g. "::ffff:127.0.0.1" as "::ffff:7f00:1") — a check that only
// recognizes the dotted form would let a victim's internal IPv6 address in that spelling reach
// the external AI provider unredacted. Classification still uses isInternalIp() (not
// iocValue.ts's isPrivateIpv4) so the CGNAT range stays covered here.
export function isInternalIpv6(ip: string): boolean {
  const lower = ip.toLowerCase().replace(/^\[|\]$/g, "");
  if (lower === "::1" || lower === "::") return true;
  if (lower.startsWith("fc") || lower.startsWith("fd")) return true; // unique-local fc00::/7
  if (/^fe[89ab][0-9a-f]?:/i.test(lower)) return true;               // link-local fe80::/10
  const mapped = embeddedIpv4(lower);
  if (mapped && isInternalIp(mapped)) return true;
  // Mirror the NAT64 branch in isMaskableIpv6() so an INTERNAL destination behind the well-known
  // prefix fails CLOSED (ANON_IP_n) rather than being judged as external.
  const groups = expandIpv6Groups(lower);
  const nat64 = groups ? nat64EmbeddedIpv4(groups) : null;
  if (nat64 && isInternalIp(nat64)) return true;
  return false;
}

// The IPv6 counterpart of isMaskableIpv4(), and for the same reason: IPV6_RE is a DETECTOR, not a
// validator. It fires on any "::" followed by hex, so ordinary text is full of matches that are
// syntactically legal IPv6 literals but are not addresses at all — "[Convert]::FromBase64String"
// yields "::F", "std::cout" yields "::c", "WIN11::admin" yields "11::ad".
//
// While public addresses were PRESERVED this was harmless (a junk match was left alone), but once
// they are tokenized every false positive is destructive: it mints a garbage ANON_EXTIP_n, that
// garbage is persisted into the case's auto-discovery store, and — because a reserved literal is
// hidden from every other pass (see reserveIpv6Literals) — it blinds the encoded-command, host,
// account, email, path, domain and custom detectors over the span it swallowed.
//
// So a non-internal match is only worth masking when it is a real, routable IPv6 address:
//   - 2000::/3 — the entire globally-routable unicast space. Adversary infrastructure lives here
//     (as does 2001:db8::/32 documentation space, which tests and sanitized reports use).
//   - an IPv4-mapped/compatible address whose embedded IPv4 is itself maskable, judged by
//     isMaskableIpv4 so the two families cannot disagree.
// Everything else (::F, ::a, 11::ad, abc::def, fe00::…) is left completely untouched — not
// reserved, not tokenized — so the pass that actually owns that text still gets to see it.
// Internal/victim addresses are NOT routed through here: isInternalIpv6() decides those, and they
// always fail CLOSED regardless of how odd the surrounding text looks.
export function isMaskableIpv6(ip: string): boolean {
  const lower = ip.toLowerCase().replace(/^\[|\]$/g, "");
  const mapped = embeddedIpv4(lower);
  if (mapped) return isMaskableIpv4(mapped);
  const groups = expandIpv6Groups(lower);
  if (!groups) return false;                            // not a well-formed IPv6 literal
  const nat64 = nat64EmbeddedIpv4(groups);
  if (nat64) return isMaskableIpv4(nat64);              // NAT64 64:ff9b::/96 — judge by the embedded IPv4
  return groups[0] >= 0x2000 && groups[0] <= 0x3fff;    // 2000::/3 global unicast
}

// Match full and compressed IPv6 addresses. Not a validator — a detector for anonymization.
// Handles full (a:b:c:d:e:f:g:h), compressed (::), and IPv4-mapped (::ffff:x.x.x.x).
//
// The two "::ffff:…" (IPv4-mapped) branches are FIRST in the alternation on purpose. JS regex
// alternation is first-match, not longest-match: a generic branch like the bare "::" one further
// down can match a truncated prefix of a mapped address (e.g. just "::ffff:127" out of
// "::ffff:127.0.0.1", stopping at the first "." since "." isn't a hex digit) and the engine never
// backtracks to try the more specific, longer-matching branch below it. Putting the specific
// dotted/hex-group mapped forms first means they get first refusal at a "::ffff:" prefix, so the
// WHOLE address is consumed as one match before IPV4_RE (run second, see anonIps below) ever gets
// a chance to tokenize the embedded dotted quad on its own and leave a dangling "::ffff:" behind.
const IPV6_RE = /::ffff(?::\d{1,3}){3}|::ffff:\d{1,3}(?:\.\d{1,3}){3}|(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,7}:(?:[0-9a-f]{1,4}:){0,5}[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,6}::(?:[0-9a-f]{1,4}:){0,5}[0-9a-f]{1,4}?|(?:[0-9a-f]{1,4}:){1,5}(?::[0-9a-f]{1,4}){1,3}|(?:[0-9a-f]{1,4}:){1,4}(?::[0-9a-f]{1,4}){1,4}|(?:[0-9a-f]{1,4}:){1,3}(?::[0-9a-f]{1,4}){1,5}|(?:[0-9a-f]{1,4}:){1,2}(?::[0-9a-f]{1,4}){1,6}|[0-9a-f]{1,4}:(?::[0-9a-f]{1,4}){1,7}|::(?:[0-9a-f]{1,4}:){0,6}[0-9a-f]{1,4}/gi;

const IPV4_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
// DOMAIN\user — guarded so it doesn't match path segments (C:\Users\srv). Mirrors assetGraph.ts.
const NETBIOS_ACCT = /(?<![\\/:.\w])([A-Za-z][A-Za-z0-9.-]{1,14})\\([A-Za-z0-9._$-]{2,20})(?![\\/\w])/g;
const UPN_ACCT = /\b[A-Za-z0-9._%+-]{2,}@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\b/g;
const PATH_DOMAINS = /^(Users|Windows|Program|ProgramData|ProgramFiles|System|System32|AppData|Device|Temp|Documents|Desktop|Downloads)$/i;

// Private-key blocks in every armor this is likely to meet: PEM (RSA / EC / DSA / OPENSSH /
// ENCRYPTED PKCS#8 / bare PKCS#8), the PGP form (which ends "PRIVATE KEY BLOCK", not "PRIVATE KEY"),
// and the SSH2 export form ("---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----" — four dashes, inner spaces).
//
// The trailing alternation is the point. A key spilled into a log is exactly where the tail gets
// TRUNCATED, and demanding a matching END delimiter would then redact NOTHING at all — the whole
// body would go to the model in cleartext. When no END is found we fall back to the base64 body, so
// the key material still goes. Both branches are length-bounded (a 4096-bit RSA PEM is ~3.2 KB):
// that bounds the over-redaction a stray header can cause, and it keeps the scan linear, since an
// unbounded lazy scan re-walks the rest of the input for EVERY begin marker.
const PEM_PRIVATE_KEY =
  /-{4,5} ?BEGIN [A-Z0-9 ]{0,32}PRIVATE KEY(?: BLOCK)? ?-{4,5}(?:[\s\S]{0,8192}?-{4,5} ?END [A-Z0-9 ]{0,32}PRIVATE KEY(?: BLOCK)? ?-{4,5}|[A-Za-z0-9+/=\s]{0,8192})/g;

// A detector, not a validator: matches only real card GROUPINGS, plus a bare contiguous run.
// Separators are permitted ONLY at genuine group boundaries — NOT between every digit (an
// earlier version of this pattern allowed a separator after each digit, so two unrelated bare
// numbers sitting next to each other in ordinary forensic text — a PID and a port, an offset
// and a byte count — got silently concatenated into one candidate before the prefix/Luhn
// filters ever ran, e.g. "30001 35174909" -> digits "3000135174909" -> passes both filters).
// Requiring the separator to land on a real 4-4-4-4 / 4-6-5 / 4-4-4-4-3 boundary means two
// adjacent-but-unrelated numbers essentially never happen to have exactly those group widths.
//
// Longest/most-specific alternative FIRST: JS regex alternation is first-match, not
// longest-match, so the 19-digit 4-4-4-4-3 grouping must be tried before the 16-digit 4-4-4-4
// grouping — otherwise a real 19-digit card would match only its first 16 digits (the engine
// finds \b right after the 4th group, since the following char is a separator), leaving the
// trailing "-123" unmasked in cleartext.
const CARD_RE =
  /\b\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{3}\b|\b\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{4}\b|\b\d{4}[ -]\d{6}[ -]\d{5}\b|\b\d{13,19}\b/g;

// Three NARROW patterns. A bare run of ten digits is deliberately NOT matched — forensic text is
// full of PIDs, ports, offsets and sequence numbers, and a generic rule would shred it. Every
// pattern demands either a leading + or explicit separators.
//
// The negative lookbehind on PHONE_E164 keeps it off a "+" that CONTINUES a token rather than
// starting a number: module+offset notation in crash dumps/stack traces (kernel32.dll+1245184)
// and SemVer build metadata (1.0.0+20130313144700 — the SemVer spec's own example) both glue a
// bare "+<digits>" suffix directly onto a preceding identifier. A genuine E.164 number is never
// preceded by a letter, digit, dot, underscore or dash — it follows whitespace, line start, or
// punctuation such as a label colon ("Tel:+972...") — so those are the only characters excluded.
const PHONE_E164 = /(?<![A-Za-z0-9._-])\+\d{7,15}\b/g;
const PHONE_IL = /\b0(?:5\d|[2-46-9])-?\d{7}\b/g;
const PHONE_NANP = /\(?\b\d{3}\)?[-. ]\d{3}[-. ]\d{4}\b/g;

// Exactly nine digits, not adjacent to another digit, a dot, a dash, or an underscore. The
// lookarounds keep this out of longer runs (byte counts, ten-digit unix seconds), dotted version
// strings, AND snake_case identifiers — session_id_123456782, txn_123456782_archived and similar
// underscore-glued session/request/ticket/backup IDs are routine in forensic text, so `_` is
// excluded on BOTH sides for the same reason as `.`/`-`: a systematic false-positive source, not
// a random one. The exclusion is symmetric because an identifier scheme that glues an ID onto a
// preceding label with `_` is just as likely to glue a trailing qualifier on with `_` the same way.
const NATID_RE = /(?<![\d._-])\d{9}(?![\d._-])/g;

/** Israeli Teudat Zehut check digit: digits at odd indices are doubled, the decimal digits of
 *  each product are summed, and the total must be divisible by 10. Exported for the tests. */
export function israeliIdValid(id: string): boolean {
  if (!/^\d{9}$/.test(id)) return false;
  let sum = 0;
  for (let i = 0; i < 9; i++) {
    let d = id.charCodeAt(i) - 48;
    if (i % 2 === 1) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
  }
  return sum % 10 === 0;
}

/** Luhn checksum. Exported for the detector table tests. */
export function luhnValid(digits: string): boolean {
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (double) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    double = !double;
  }
  return sum % 10 === 0;
}

export function createAnonymizer(policy: AnonPolicy, known: KnownEntities): Anonymizer {
  const toToken = new Map<string, string>();  // "CAT:reallower" -> token
  const toReal = new Map<string, string>();   // token (UPPER) -> real value
  const counters: Record<string, number> = {};
  // Values the analyst removed from auto-discovery — never tokenize them (leave as-is), even when
  // a pattern matches. The check sits in assign(), the single point every matcher funnels through.
  const suppressed = new Set((known.suppressed ?? []).map((s) => s.toLowerCase()));

  function assign(category: AnonTokenCategory, real: string): string {
    if (suppressed.has(real.toLowerCase())) return real; // suppressed → keep the real value verbatim
    const key = `${category}:${real.toLowerCase()}`;
    const existing = toToken.get(key);
    if (existing) return existing;
    counters[category] = (counters[category] ?? 0) + 1;
    const token = `ANON_${category}_${counters[category]}`;
    toToken.set(key, token);
    toReal.set(token, real);
    return token;
  }

  // Every (real value, category) this anonymizer minted a token for. Secrets never appear here —
  // redactSecrets() replaces them with a placeholder rather than calling assign().
  function discoveries(): CustomEntity[] {
    const out: CustomEntity[] = [];
    const seen = new Set<string>();
    for (const [token, real] of toReal) {
      const cat = (/^ANON_([A-Z]+)_\d+$/.exec(token)?.[1] ?? "OTHER") as AnonTokenCategory;
      const key = `${cat}:${real.toLowerCase()}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({ value: real, category: cat });
    }
    return out;
  }

  // ── detectors (filled in across later tasks; order is fixed in apply()) ──
  function redactSecrets(t: string): string {
    let out = t;
    // key/value credentials: keep the key name, redact the value.
    out = out.replace(
      /\b(password|passwd|pwd|secret|api[_-]?key|apikey|token|authorization|bearer)\b(\s*[:=]\s*)(?:bearer\s+|basic\s+)?["']?([^\s"'<>,;]{3,})/gi,
      (_m, k: string, sep: string) => `${k}${sep}${SECRET_PLACEHOLDER}`,
    );
    // URL userinfo password (scheme://user:pass@host) — redact just the password.
    out = out.replace(/([a-z][a-z0-9+.-]*:\/\/[^\s:@/]+:)([^\s:@/]+)(@)/gi, (_m, a: string, _pw: string, c: string) => `${a}${SECRET_PLACEHOLDER}${c}`);
    // Distinctive fixed-shape secrets. NOTE: deliberately NO generic high-entropy rule — it
    // would clobber hashes (which we must keep as IOCs).
    const fixed: RegExp[] = [
      /\bAKIA[0-9A-Z]{16}\b/g,                                                   // AWS access key id
      /\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}\b/g,         // JWT
      /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g,                                         // GitHub tokens
      /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,                                       // Slack tokens
      PEM_PRIVATE_KEY,                                                           // PEM/PGP/SSH2 private keys
    ];
    for (const re of fixed) out = out.replace(re, SECRET_PLACEHOLDER);
    return out;
  }
  function isInternalDomain(domain: string): boolean {
    const d = domain.toLowerCase();
    return known.internalDomains.some((kd) => d === kd || d.endsWith("." + kd));
  }
  function anonAccounts(t: string): string {
    let out = t.replace(NETBIOS_ACCT, (m, dom: string, user: string) =>
      PATH_DOMAINS.test(dom) ? m : assign("USER", `${dom}\\${user}`));
    // Only UPNs on an internal domain are AD accounts → USER. Others stay for anonEmails.
    out = out.replace(UPN_ACCT, (m) => {
      const domain = m.split("@")[1] ?? "";
      return isInternalDomain(domain) ? assign("USER", m) : m;
    });
    return out;
  }
  const EMAIL_RE = /\b[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)*[A-Za-z0-9-]+(?:\.[A-Za-z]{2,}|\.xn--[A-Za-z0-9-]+)\b/g;
  function anonEmails(t: string): string {
    return t.replace(EMAIL_RE, (m) => assign("EMAIL", m));
  }
  // Capture the profile-dir prefix + the username segment; tokenize only the username.
  const USER_PATH_RE = /([A-Za-z]:\\Users\\|\\Users\\|\/home\/|\/Users\/|\/root\/)([^\\/\r\n"'<>|:*?]+)/g;
  const WELL_KNOWN_PROFILE = /^(public|default|default user|all users|administrator|admin|guest|system|systemprofile|localservice|networkservice)$/i;
  function anonUserPaths(t: string): string {
    return t.replace(USER_PATH_RE, (m, prefix: string, name: string) =>
      WELL_KNOWN_PROFILE.test(name) ? m : prefix + assign("USER", name));
  }
  // Encoded command-line blobs: the base64 after PowerShell -e/-ec/-enc/-EncodedCommand and inside
  // FromBase64String('…'). Tokenize ONLY the blob — the command verb + flag stay visible as
  // tradecraft signal (the model still sees that an encoded command ran), and victim data embedded
  // in the encoded payload never reaches the wire. The `=` padding is matched outside the class.
  const ENC_CMD_RE = /(?<![A-Za-z0-9])(-(?:e|ec|enc|encodedcommand)\s+)([A-Za-z0-9+\/_-]{16,}={0,2})/gi;
  const FROM_B64_RE = /(FromBase64String\(\s*["'])([A-Za-z0-9+\/_-]{16,}={0,2})(["'])/gi;
  function anonEncodedCmd(t: string): string {
    let out = t.replace(ENC_CMD_RE, (_m, flag: string, blob: string) => flag + assign("CMD", blob));
    out = out.replace(FROM_B64_RE, (_m, a: string, blob: string, c: string) => a + assign("CMD", blob) + c);
    return out;
  }
  // Machine/domain-issued user SIDs (S-1-5-21-…-RID) are victim-identifying. Well-known SIDs
  // (S-1-5-18, S-1-5-19/20, S-1-5-32-*) lack the S-1-5-21 prefix and are preserved.
  const SID_RE = /\bS-1-5-21(?:-\d{1,10}){4}\b/gi;
  function anonSids(t: string): string {
    return t.replace(SID_RE, (m) => assign("REG", m));
  }
  function anonHosts(t: string): string {
    let out = t;
    for (const h of known.hosts) {
      if (h.length < 2) continue;
      out = out.replace(exactValueRegExp(h), (m) => assign("HOST", m));
    }
    return out;
  }
  function anonDomains(t: string): string {
    let out = t;
    for (const d of known.internalDomains) {
      if (d.length < 2) continue;
      out = out.replace(exactValueRegExp(d), (m) => assign("DOMAIN", m));
    }
    return out;
  }
  // An IPv6 literal (especially an IPv4-mapped one like ::ffff:10.0.0.5) is an atomic lexical
  // unit: whatever text is embedded inside it must be classified and tokenized as ONE address,
  // never as a separately-matched substring. Every OTHER detector in apply() (anonCustom,
  // accounts, emails, paths, encoded commands, SIDs, hosts, domains) does word-boundary text
  // substitution and none of them know about IPv6 syntax — a known.custom IPv4 value (exactly
  // what pipeline.ts persists from auto-discovery and re-injects on the next call) or any other
  // pass that happens to substring-match inside "::ffff:10.0.0.5" would leave a mutated remnant
  // for IPV6_RE to (mis)parse when the real IP pass finally runs, corrupting the token. So an
  // IPv6 literal is pulled out and replaced with an inert placeholder BEFORE any other pass runs,
  // and only spliced back in — correctly classified via isInternalIpv6, exactly as if nothing had
  // run before it — right before the IPv4 pass. Placeholders are delimited by \uE000 so no other
  // detector's pattern can match one.
  //
  // Reservation is a BLINDFOLD: whatever it swallows becomes invisible to every later pass. So a
  // literal is reserved ONLY when this anonymizer would genuinely tokenize it — an internal/victim
  // address (isInternalIpv6, unconditionally, so it still fails CLOSED when it abuts trailing
  // text) or a real routable one (isMaskableIpv6). IPV6_RE's many false positives ("::F" out of
  // "[Convert]::FromBase64String(", "11::ad" out of "WIN11::admin", "::c" out of "std::cout") are
  // left in place verbatim, so the encoded-command / host / account / email / path / SID / domain /
  // custom passes still see the text they own. Reserving on the raw detector match with no
  // validator is what silently sent base64 payloads and hostnames to the wire in cleartext.
  const IPV6_SENTINEL = "\uE000";
  const IPV6_SENTINEL_RE = /\uE000/g;
  const IPV6_PLACEHOLDER_RE = /\uE000IPV6:(\d+)\uE000/g;

  function reserveIpv6Literals(t: string): { text: string; literals: string[] } {
    const literals: string[] = [];
    // Case text is ATTACKER-INFLUENCED (logs, screenshots, imported evidence), so a hand-crafted
    // "\uE000IPV6:0\uE000" can arrive in the input. Strip the sentinel before minting any of our own:
    // a forged placeholder must never index the literals table and make restore() invent an
    // address in text that never contained one.
    const text = t.replace(IPV6_SENTINEL_RE, "").replace(IPV6_RE, (m) => {
      if (!isInternalIpv6(m) && !isMaskableIpv6(m)) return m; // detector false positive — leave it alone
      const i = literals.length;
      literals.push(m);
      return `${IPV6_SENTINEL}IPV6:${i}${IPV6_SENTINEL}`;
    });
    return { text, literals };
  }

  function restoreIpv6Literals(t: string, literals: string[]): string {
    return t.replace(IPV6_PLACEHOLDER_RE, (m, idxStr: string) => {
      const ip = literals[Number(idxStr)];
      if (ip === undefined) return m; // belt-and-braces with the strip above: never invent a value
      if (isInternalIpv6(ip)) return assign("IP", ip);
      return policy.maskPublicIps ? assign("EXTIP", ip) : ip;
    });
  }

  function anonIpv4(t: string): string {
    return t.replace(IPV4_RE, (ip) => {
      if (isInternalIp(ip)) return assign("IP", ip);
      if (!policy.maskPublicIps || !isMaskableIpv4(ip)) return ip;
      return assign("EXTIP", ip);
    });
  }

  // Two independent filters — a plausible issuer prefix AND Luhn — keep this out of trouble in
  // forensic text. Hashes are hexadecimal, so long bare DECIMAL runs are already uncommon.
  // No length check here: every CARD_RE alternative already guarantees 13–19 digits once
  // separators are stripped — the three grouped alternatives have fixed digit counts (19, 16,
  // 15) and the contiguous alternative is itself bounded by the {13,19} quantifier — so a
  // post-hoc length check on `digits` can never fail and would be dead code.
  function anonCards(t: string): string {
    return t.replace(CARD_RE, (m) => {
      const digits = m.replace(/[ -]/g, "");
      if (!/^[3-6]/.test(digits)) return m;   // Amex 3, Visa 4, Mastercard 5, Discover 6
      if (!luhnValid(digits)) return m;
      return assign("CARD", m);
    });
  }

  // E.164 runs first: it is the most specific, and an international number has no leading zero
  // for the Israeli pattern to latch onto.
  function anonPhones(t: string): string {
    let out = t.replace(PHONE_E164, (m) => assign("PHONE", m));
    out = out.replace(PHONE_IL, (m) => assign("PHONE", m));
    out = out.replace(PHONE_NANP, (m) => assign("PHONE", m));
    return out;
  }

  // KNOWN LIMITATION: roughly one in ten arbitrary nine-digit numbers passes the check digit, and
  // a Teudat Zehut has no other structure to filter on. In a case with no Israeli PII this WILL
  // tokenize the occasional file offset or sequence number. Two escape hatches exist: untick the
  // NATID category for the case, or add the specific value to the suppressed list, which is
  // honoured at the assign() chokepoint.
  function anonNatIds(t: string): string {
    return t.replace(NATID_RE, (m) => (israeliIdValid(m) ? assign("NATID", m) : m));
  }

  function anonCustom(t: string): string {
    const custom = known.custom ?? [];
    if (custom.length === 0) return t;
    let out = t;
    for (const { value, category } of [...custom].sort((a, b) => b.value.length - a.value.length)) {
      if (!value || value.length < 1) continue;
      // A public IP the anonymizer minted as EXTIP earlier (e.g. discovered from a screenshot,
      // then persisted into known.custom) must NOT be re-tokenized here when maskPublicIps is
      // off — otherwise the redacted export (which always disables it) would exact-match and
      // hide adversary infrastructure that policy explicitly says to keep visible, even though
      // anonIpv4()/restoreIpv6Literals() themselves correctly leave live public-IP text alone.
      if (category === "EXTIP" && !policy.maskPublicIps) continue;
      out = out.replace(exactValueRegExp(value), (m) => assign(category, m));
    }
    return out;
  }

  function apply(text: string): string {
    let t = text;
    // Reserve IPv6 literals FIRST — before anonCustom or any other pass — so nothing can
    // substitute inside one. Only when IP masking is active: if the IP category is off, no later
    // step ever reparses an IPv6 literal, so there is nothing to protect it FROM.
    let ipv6Literals: string[] = [];
    if (policy.categories.IP) {
      const reserved = reserveIpv6Literals(t);
      t = reserved.text;
      ipv6Literals = reserved.literals;
    }
    t = anonCustom(t);                       // analyst-added entities always win (outside IPv6 literals)
    if (policy.redactSecrets) t = redactSecrets(t);
    if (policy.categories.USER) t = anonAccounts(t);
    if (policy.categories.EMAIL) t = anonEmails(t);
    if (policy.categories.PATH) t = anonUserPaths(t);
    if (policy.categories.CMD) t = anonEncodedCmd(t);
    if (policy.categories.REG) t = anonSids(t);
    if (policy.categories.HOST) t = anonHosts(t);
    if (policy.categories.DOMAIN) t = anonDomains(t);
    if (policy.categories.IP) {
      t = restoreIpv6Literals(t, ipv6Literals);  // classify + tokenize the reserved literals
      t = anonIpv4(t);                           // then any standalone (non-embedded) IPv4 address
    }
    if (policy.categories.CARD) t = anonCards(t);
    if (policy.categories.PHONE) t = anonPhones(t);
    if (policy.categories.NATID) t = anonNatIds(t);
    return t;
  }

  function restore(text: string): string {
    return text.replace(TOKEN_RE, (m) => toReal.get(m.toUpperCase()) ?? m);
  }

  function restoreDeep<T>(value: T): T {
    if (typeof value === "string") return restore(value) as unknown as T;
    if (Array.isArray(value)) return value.map((v) => restoreDeep(v)) as unknown as T;
    if (value && typeof value === "object") {
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(value as Record<string, unknown>)) out[k] = restoreDeep(v);
      return out as unknown as T;
    }
    return value;
  }

  return { apply, restore, restoreDeep, discoveries };
}

// Tokens that LOOK like a "DOMAIN\user" or "host.domain" but are NEVER a victim/customer
// domain. extractAccounts()'s DOMAIN\user regex has three big false-positive sources, and
// deriveKnownEntities() would otherwise promote each to an "internal domain": registry hives
// (HKU\Software), Windows well-known principals (BUILTIN\…, NT AUTHORITY\…, FONT DRIVER HOST\…),
// and EVTX-ATTACK-SAMPLES-style tactic folders (Execution\…, Persistence\…). Promoting them is
// doubly harmful: it pollutes the analyst's anonymization list AND, because anonDomains() does a
// word-boundary replace, it tokenizes these ultra-common words ("access", "code", "files",
// "execution") throughout the timeline — wrecking the text the model reads. All single-label,
// lowercase. A dotted FQDN (windomain.local) is always treated as a real domain and kept.
export const NON_VICTIM_DOMAINS: ReadonlySet<string> = new Set([
  // Windows well-known principals / NETBIOS authorities (the DOMAIN half of e.g. BUILTIN\Administrators)
  "nt", "authority", "service", "builtin", "workgroup", "virtual", "machine",
  "iis", "apppool", "window", "manager", "font", "driver", "host", "dwm", "umfd",
  "everyone", "system", "owner", "creator",
  // Registry hives (HKU\Software → "hku")
  "hku", "hklm", "hkcu", "hkcr", "hkcc",
  "hkey_users", "hkey_local_machine", "hkey_current_user", "hkey_classes_root", "hkey_current_config",
  // Bare single-label LAN suffixes (a 2-label host like dc.local would otherwise add "local")
  "local", "localdomain", "lan", "home",
  // MITRE ATT&CK tactics — the EVTX-ATTACK-SAMPLES folder names that keep getting mis-parsed
  "reconnaissance", "resource", "development", "initial", "access", "execution",
  "persistence", "privilege", "escalation", "defense", "evasion", "credential",
  "discovery", "lateral", "movement", "collection", "command", "control",
  "exfiltration", "impact", "tactics", "techniques", "mitre", "attack",
  // Common tool / process / generic folder names that get mis-parsed as a DOMAIN
  "defender", "explorer", "vgauth", "ransomware", "malware", "samples", "results",
  "tools", "setup", "files", "hours", "global", "launch", "layers", "code", "jobs",
  "lite", "csv", "zip", "logs", "temp", "data", "output", "report", "reports",
  "evidence", "downloads", "desktop", "documents", "users", "public", "default",
  "windows", "programdata", "program", "system32", "appdata",
]);

// A single-label token is "noise" when it's a known non-victim word; a dotted FQDN is kept.
export function isNoiseDomain(domain: string): boolean {
  const d = domain.toLowerCase().trim();
  if (!d) return true;
  if (d.includes(".")) return false;          // real FQDN (windomain.local) — always keep
  return NON_VICTIM_DOMAINS.has(d);
}

// An extracted account is noise when its domain part is a non-victim word — e.g.
// HKU\Software, BUILTIN\Administrators, NT AUTHORITY\SYSTEM, Execution\evil.exe.
export function isNoiseAccount(account: string): boolean {
  const slash = account.indexOf("\\");
  if (slash > 0) return isNoiseDomain(account.slice(0, slash));
  const at = account.indexOf("@");
  if (at > 0) return isNoiseDomain(account.slice(at + 1));
  return false;
}

// Derive the victim entities to tokenize from the case state: hosts (event.asset), accounts
// (DOMAIN\user / UPN in event text) and the internal domains those imply (NETBIOS name, UPN
// domain, and the parent domain of any FQDN host). Pure + deterministic. Noise accounts/domains
// (registry hives, Windows principals, ATT&CK tactic folders, generic words) are filtered out so
// they neither pollute the analyst's list nor get tokenized as common words across the timeline.
export function deriveKnownEntities(state: InvestigationState): KnownEntities {
  const hosts = new Set<string>();
  const accounts = new Set<string>();
  const internalDomains = new Set<string>();
  for (const e of state.forensicTimeline) {
    if (e.asset && e.asset.trim()) hosts.add(e.asset.trim());
    for (const acct of extractAccounts(e.description)) {
      if (isNoiseAccount(acct)) continue;       // registry hive / Windows principal / tactic folder, not a victim account
      accounts.add(acct);
      if (acct.includes("\\")) internalDomains.add(acct.split("\\")[0]);
      else if (acct.includes("@")) internalDomains.add(acct.split("@")[1]);
    }
  }
  for (const h of hosts) {
    const i = h.indexOf(".");
    if (i > 0) internalDomains.add(h.slice(i + 1)); // FQDN → parent domain is internal
  }
  const byLenDesc = (a: string, b: string) => b.length - a.length || a.localeCompare(b);
  return {
    hosts: [...hosts].sort(byLenDesc),
    accounts: [...accounts],
    internalDomains: [...internalDomains]
      .map((d) => d.toLowerCase())
      .filter((d) => !isNoiseDomain(d))         // belt-and-suspenders: also drops noisy FQDN-parent labels (dc.local → "local")
      .sort(byLenDesc),
  };
}

// Is the configured AI provider on-box (so screenshots sent to it don't leave the machine)?
// Used to decide whether to warn that screenshots are NOT anonymized.
export function isLocalAiProvider(name: string | undefined, baseUrl: string | undefined): boolean {
  if ((name ?? "").toLowerCase() === "ollama") return true;
  const u = (baseUrl ?? "").toLowerCase();
  return /(?:\/\/|@)(?:localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0)(?::|\/|$)/.test(u);
}
