import { luhnValid } from "./anonChecksums.js";

// The card, phone and national-id detectors of the anonymizer. Moved out of anonymize.ts so the
// glued-remnant pass (anonGluedSecret.ts, #3028) can stop at the same matches. The glued card and
// IPv4 readers (#3058) live here too, to keep anonymize.ts under its size limit.

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
export const CARD_RE =
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
export const PHONE_E164 = /(?<![A-Za-z0-9._-])\+\d{7,15}\b/g;
export const PHONE_IL = /\b0(?:5\d|[2-46-9])-?\d{7}\b/g;
export const PHONE_NANP = /\(?\b\d{3}\)?[-. ]\d{3}[-. ]\d{4}\b/g;

// Exactly nine digits, not adjacent to another digit, a dot, a dash, or an underscore. The
// lookarounds keep this out of longer runs (byte counts, ten-digit unix seconds), dotted version
// strings, AND snake_case identifiers — session_id_123456782, txn_123456782_archived and similar
// underscore-glued session/request/ticket/backup IDs are routine in forensic text, so `_` is
// excluded on BOTH sides for the same reason as `.`/`-`: a systematic false-positive source, not
// a random one. The exclusion is symmetric because an identifier scheme that glues an ID onto a
// preceding label with `_` is just as likely to glue a trailing qualifier on with `_` the same way.
export const NATID_RE = /(?<![\d._-])\d{9}(?![\d._-])/g;

// A card number: a plausible issuer prefix AND Luhn. Two independent filters keep this out of trouble
// in forensic text (hashes are hexadecimal). No length check: every CARD_RE alternative already
// guarantees 13–19 digits once separators are stripped, so one could never fail.
function isCardNumber(m: string): boolean {
  const digits = m.replace(/[ -]/g, "");
  return /^[3-6]/.test(digits) && luhnValid(digits); // Amex 3, Visa 4, Mastercard 5, Discover 6
}

// A 4-4-4-4 card with one to three digits glued on either end (#3058): CARD_RE's `\b` failed on the
// glued side, so the whole number went out in clear. Only the grouped shape: in a bare run of
// digits any 16-digit window would be tried, and long decimals (FILETIMEs) would be read as cards.
const GLUED_CARD_RE = /(?<!\d)(?:\d{5,7}(?:[ -]\d{4}){2}[ -]\d{4,7}|\d{4}(?:[ -]\d{4}){2}[ -]\d{5,7})(?!\d)/g;
/** The 16-digit card a GLUED_CARD_RE match is read as: the four groups cut to four digits. */
function gluedCardCore(m: string): string {
  const groups = m.split(/[ -]/);
  const last = groups.length - 1;
  return groups.map((g, i) => (i === 0 ? g.slice(-4) : i === last ? g.slice(0, 4) : g)).join("");
}

// An IPv4 address whose last part is not an octet: digits glued on (4+ digits) or one digit too
// many (over 255) (#3058). IPV4_RE's `\b` and the octet check left it in clear.
const GLUED_IPV4_RE = /\b(?:\d{1,3}\.){3}(?:\d{4,}|25[6-9]|2[6-9]\d|[3-9]\d\d)\b/g;
// A public head needs five or more digits in its last part: `2.0.0.1024` is a version string far
// more often than an address with digits glued on.
/** The address a GLUED_IPV4_RE match is read as (its last part cut to its longest octet), or null. */
function gluedIpv4Head(m: string, internal: (ip: string) => boolean): string | null {
  const cut = m.lastIndexOf(".") + 1;
  const last = m.slice(cut);
  const ip = m.slice(0, cut) + last.slice(0, Number(last.slice(0, 3)) <= 255 ? 3 : 2);
  return internal(ip) || last.length >= 5 ? ip : null;
}

/** Mint each card, the plain shapes (CARD_RE) and then the glued ones, with `mint`. */
export function replaceCards(text: string, mint: (m: string) => string): string {
  const out = text.replace(CARD_RE, (m) => (isCardNumber(m) ? mint(m) : m));
  return out.replace(GLUED_CARD_RE, (m) => (isCardNumber(gluedCardCore(m)) ? mint(m) : m));
}

/** Mint each glued IPv4 run whole with `mint(head, run)`, its head as gluedIpv4Head reads it. */
export function replaceGluedIpv4(
  text: string,
  internal: (ip: string) => boolean,
  mint: (head: string, run: string) => string,
): string {
  return text.replace(GLUED_IPV4_RE, (m) => {
    const head = gluedIpv4Head(m, internal);
    return head ? mint(head, m) : m;
  });
}
