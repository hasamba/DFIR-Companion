import type { AnonTokenCategory } from "./anonymize.js";
import type { TokenEnds } from "./anonTokenLiterals.js";
import { PHONE_IL, PHONE_NANP, replaceEach } from "./anonPiiPatterns.js";

// #3071: an IPv4 address glued right after a word ("ab" + address, "srv01" + address, "srv01_" +
// address) went out in clear: IPV4_RE and the #3058 glued reader both need a word boundary before the
// first number. This pass runs in the IPv4 pass after both readers, on text they left in clear, so
// nothing they mask can change. The address gets its own token; the word before it stays as it is.
//
// It is graded as a standalone address would be: an internal one always, a public one only with
// public masking on. A word made only of digits is left alone: a long number glued to an address
// (a card) is the card pass's, and a three-digit one is the address itself, already judged.

/** What the pass needs from the anonymizer. */
export interface WordGluedRules {
  /** The category a standalone address gets ("IP" when internal), or null when it stays in clear. */
  readonly category: (ip: string) => AnonTokenCategory | null;
  /** Mint `run` (the address and any digits glued on its end) as the address `head`. */
  readonly mask: (head: string, run: string) => string;
  /** The call's token ends: where a token alias spliced before a digit ends. */
  readonly ends: Pick<TokenEnds, "aliasEnd">;
}

// A word (not inside another word or a dotted run) ending in digits, then three more address parts.
// The last part may run on in digits (masked whole, as #3058); no word or ".digit" may follow.
const WORD_GLUED_V4 = /(?<![\w.])(\w*[A-Za-z_])(\d+)\.(\d{1,3})\.(\d{1,3})\.(\d+)(?!\w|\.\d)/g;
const OCTET = /^(?:0|[1-9]\d?|1\d\d|2[0-4]\d|25[0-5])$/;
const TOKEN_TAIL = /ANON_[A-Z]+_\d*$/;
const CARD_GROUP_NEXT = /^[ -]\d/;
const PHONE_REACH = 16; // past the match: the longest phone shape is fourteen characters

/** The last part as an address reads it: cut to its longest octet when digits are glued on. */
function lastHead(last: string): string {
  return OCTET.test(last) ? last : last.slice(0, Number(last.slice(0, 3)) <= 255 ? 3 : 2);
}

/** Where the address digits may start: after a spliced alias, or null when a token's number is there. */
function digitsStart(text: string, m: RegExpExecArray, r: WordGluedRules): number | null {
  const word = m[1] + m[2];
  const at = word.lastIndexOf("ANON_");
  const digits = m.index + m[1].length;
  if (at < 0) return digits;
  const end = r.ends.aliasEnd(text, m.index + at);
  if (end >= 0) return Math.max(end, digits);
  return TOKEN_TAIL.test(word) ? null : digits; // a token's number is never read as an octet
}

/** A phone number the phone pass reads starts inside the match and runs past it: it stays the phone's. */
function phoneCrosses(text: string, m: RegExpExecArray): boolean {
  const len = m[0].length;
  const near = text.slice(m.index, m.index + len + PHONE_REACH);
  return [PHONE_NANP, PHONE_IL].some((re) =>
    [...near.matchAll(new RegExp(re.source, "g"))].some((p) => p.index < len && p.index + p[0].length > len),
  );
}

/**
 * The address glued after the word: the first part a one- to three-digit tail of the digits before
 * it. An internal reading wins, then a masked public one; on a tie the longest (it hides the most).
 */
function readAddress(text: string, m: RegExpExecArray, r: WordGluedRules): string | null {
  const from = digitsStart(text, m, r);
  if (from === null) return null;
  const digits = text.slice(from, m.index + m[1].length + m[2].length);
  const [b, c, last] = [m[3], m[4], m[5]];
  if (!OCTET.test(String(Number(b))) || !OCTET.test(String(Number(c)))) return null;
  // Digits run on into a number group: they may open a card the card pass reads, as before.
  if (!OCTET.test(last) && CARD_GROUP_NEXT.test(text.slice(m.index + m[0].length))) return null;
  if (phoneCrosses(text, m)) return null;
  let best: { k: number; rank: number } | null = null;
  for (let k = 1; k <= Math.min(3, digits.length); k++) {
    const a = digits.slice(-k);
    if (!OCTET.test(a)) continue;
    const head = `${a}.${b}.${c}.${lastHead(last)}`;
    const cat = r.category(head);
    if (!cat) continue;
    const rank = cat === "IP" ? 2 : 1; // internal
    if (!best || rank >= best.rank) best = { k, rank };
  }
  if (!best) return null;
  const a = digits.slice(-best.k);
  const head = `${a}.${b}.${c}.${lastHead(last)}`;
  const start = m.index + m[1].length + m[2].length - best.k;
  return text.slice(m.index, start) + r.mask(head, `${a}.${b}.${c}.${last}`);
}

/** Give each IPv4 address glued after a word, and still in clear, its own token. */
export function replaceWordGluedIpv4(text: string, r: WordGluedRules): string {
  return replaceEach(text, WORD_GLUED_V4, (m) => readAddress(text, m, r));
}
