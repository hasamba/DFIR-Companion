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
export function isCardNumber(m: string): boolean {
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
/** The address a GLUED_IPV4_RE match is read as: its last part cut to its longest octet. A public
 * one is masked only under public masking, where a four-part version can read as one (#3062). */
function gluedIpv4Head(m: string): string {
  const cut = m.lastIndexOf(".") + 1;
  const last = m.slice(cut);
  return m.slice(0, cut) + last.slice(0, Number(last.slice(0, 3)) <= 255 ? 3 : 2);
}

/** A card shape: its group widths (separators stripped) and the issuer prefixes it accepts. */
export interface CardShape {
  readonly widths: readonly number[];
  readonly prefix: RegExp;
}
const ANY_ISSUER = /^[3-6]/;
export const C19: CardShape = { widths: [4, 4, 4, 4, 3], prefix: ANY_ISSUER };
export const C16: CardShape = { widths: [4, 4, 4, 4], prefix: ANY_ISSUER };
export const AMEX: CardShape = { widths: [4, 6, 5], prefix: /^3[47]/ };
export const cardOk = (digits: string, shape: CardShape) => shape.prefix.test(digits) && luhnValid(digits);
/** Whether a grouped match with digits glued on one end holds a card of `shape`. */
function gluedCore(m: string, shape: CardShape): boolean {
  const groups = m.split(/[ -]/);
  const last = groups.length - 1;
  const w = shape.widths;
  return cardOk(
    groups.map((g, i) => (i === 0 ? g.slice(-w[0]) : i === last ? g.slice(0, w[last]) : g)).join(""),
    shape,
  );
}
// Amex and 19-digit groupings with one to three digits glued on either end (#3062). They run before
// CARD_RE, whose 4-4-4-4 alternative would take the first sixteen digits and leave the rest in clear.
// Grouped shapes only, as GLUED_CARD_RE: a bare long run is never cut into a card window. Nor is a
// window of a longer column of number groups (event IDs, ports, years): no group may sit on either side.
const GLUED_LONG: ReadonlyArray<readonly [RegExp, CardShape]> = [
  [/(?<!\d|\d[ -])\d{4}(?:[ -]\d{4}){3}[ -]\d{4,6}(?!\d|[ -]\d)/g, C19],
  [/(?<!\d|\d[ -])\d{5,7}(?:[ -]\d{4}){3}[ -]\d{3}(?!\d|[ -]\d)/g, C19],
  [/(?<!\d|\d[ -])\d{4}[ -]\d{6}[ -]\d{6,8}(?!\d|[ -]\d)/g, AMEX],
  [/(?<!\d|\d[ -])\d{5,7}[ -]\d{6}[ -]\d{5}(?!\d|[ -]\d)/g, AMEX],
];

/** Replace each match `fn` accepts; a rejected match is tried again one character later. */
export function replaceEach(text: string, re: RegExp, fn: (m: RegExpExecArray) => string | null): string {
  let out = "";
  let at = 0;
  re.lastIndex = 0;
  for (let m = re.exec(text); m; m = re.exec(text)) {
    const r = fn(m);
    if (r === null) {
      re.lastIndex = m.index + 1;
      continue;
    }
    out += text.slice(at, m.index) + r;
    at = re.lastIndex = m.index + m[0].length;
  }
  return out + text.slice(at);
}

/** Mint each card with `mint`: the glued Amex/19-digit shapes, the plain shapes (CARD_RE), then the
 * glued 4-4-4-4 shape. A card glued to an address is anonGluedPairs.ts's (#3062). */
export function replaceCards(text: string, mint: (m: string) => string): string {
  let out = text;
  for (const [re, shape] of GLUED_LONG)
    out = replaceEach(out, re, (m) => (gluedCore(m[0], shape) ? mint(m[0]) : null));
  return readCardsAsBefore(out, mint);
}

/** The card readings #3058 had (CARD_RE, then the glued 4-4-4-4 shape), with `mint`. */
export function readCardsAsBefore(text: string, mint: (m: string) => string): string {
  const out = text.replace(CARD_RE, (m) => (isCardNumber(m) ? mint(m) : m));
  return out.replace(GLUED_CARD_RE, (m) => (isCardNumber(gluedCardCore(m)) ? mint(m) : m));
}

/** Mint each glued IPv4 run whole with `mask(head, run)`, its head as gluedIpv4Head reads it. */
export function replaceGluedIpv4(text: string, mask: (head: string, run: string) => string): string {
  return text.replace(GLUED_IPV4_RE, (m) => mask(gluedIpv4Head(m), m));
}

/** The glued IPv4 reading #3058 had: a public head only with five or more digits in its last part. */
export function readGluedIpv4AsBefore(
  text: string,
  internal: (ip: string) => boolean,
  mask: (head: string, run: string) => string,
): string {
  return text.replace(GLUED_IPV4_RE, (m) => {
    const head = gluedIpv4Head(m);
    return internal(head) || m.length - m.lastIndexOf(".") > 5 ? mask(head, m) : m;
  });
}

// Encoded command-line blobs: the base64 after PowerShell -e/-ec/-enc/-EncodedCommand and inside
// FromBase64String('…') in one, doubled or JSON-escaped quotes (#3053). Tokenize ONLY the blob: the verb
// and flag stay visible as tradecraft signal, the payload never reaches the wire. `=` padding is outside.
// A cue may follow a number or a JSON `\n`; padding before a glued IPv4 stays out of the token (#3060).
export const ENC_CMD_RE =
  /(?:(?<![A-Za-z])|(?<=(?<!\\)(?:\\\\)*\\[nrt]))(-(?:e|ec|enc|encodedcommand)\s+)([A-Za-z0-9+\/_-]{16,})(={0,2})/gi;
export const FROM_B64_RE =
  /(FromBase64String\(\s*(?:''|""|\\"|["']))([A-Za-z0-9+\/_-]{16,}={0,2})(''|""|\\"|["'])/gi;
const IPV4_AT = /\d{1,3}(?:\.\d{1,3}){3}/y;

/** True when an IPv4 address starts at `at` in `text`. */
export function ipv4StartsAt(text: string, at: number): boolean {
  IPV4_AT.lastIndex = at;
  return IPV4_AT.test(text);
}
