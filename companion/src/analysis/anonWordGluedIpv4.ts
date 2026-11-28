import type { AnonTokenCategory } from "./anonymize.js";
import type { TokenEnds } from "./anonTokenLiterals.js";
import { PHONE_IL, PHONE_NANP } from "./anonPiiPatterns.js";

// #3071: an IPv4 address glued right after a word ("ab" + address, "srv01" + address, "srv01_" +
// address) went out in clear: IPV4_RE and the #3058 glued reader both need a word boundary before the
// first number. This pass runs in the IPv4 pass after both readers, on text they left in clear, so
// nothing they mask can change. The address gets its own token; the word before it stays as it is.
//
// It is graded as a standalone address would be: an internal one always, a public one only with
// public masking on. #3078: more dotted numbers after the address are masked with it, as a standalone
// address with a fifth number is (#3018). One to three digits glued before the first number (a word of
// four to six digits) are masked with the address: which of them open it cannot be told. A phone number that starts in the last number gets its own
// token after the address token, as for a standalone address (#3018).

/** What the pass needs from the anonymizer. */
export interface WordGluedRules {
  /** The category a standalone address gets ("IP" when internal), or null when it stays in clear. */
  readonly category: (ip: string) => AnonTokenCategory | null;
  /** Mint `run` (the address and any digits glued on its end) as the address `head`. */
  readonly mask: (head: string, run: string) => string;
  /** The call's token ends: where a token alias spliced before a digit ends. */
  readonly ends: Pick<TokenEnds, "aliasEnd">;
  /** Mint a phone number's `value` (its part after the address; `whole` as the phone pass reads it), or null: PHONE off. */
  readonly phone: ((value: string, whole: string) => string) | null;
}

// An optional word (not inside another word or a dotted run) ending in digits, then three more address
// parts and any dotted numbers. The last part may run on in digits (masked whole, as #3058); no word
// or ".digit" may follow.
const WORD_GLUED_V4 =
  /(?<![\w.])((?:\w*[A-Za-z_])?)(\d+)\.(\d{1,3})\.(\d{1,3})\.(\d+)((?:\.\d{1,3})*)(?!\w|\.\d)/g;
const OCTET = /^(?:0|[1-9]\d?|1\d\d|2[0-4]\d|25[0-5])$/;
const TOKEN_TAIL = /ANON_[A-Z]+_\d*$/;
const CARD_GROUP_NEXT = /^[ -]\d/;
const NUMBER_GROUP_BEFORE = /\d[ -]$/;
const PHONE_REACH = 16; // past the match: the longest phone shape is fourteen characters

type Phone = { readonly gap: string; readonly value: string; readonly whole: string };
type Step = { readonly out: string; readonly skip: number };

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

/**
 * A phone number the phone pass reads that starts inside the match and runs past it: "cross" when it
 * starts in the last number (one to three digits, a separator before the rest), "keep" when it
 * starts earlier (the phone pass's, as before), null when there is none.
 */
function phoneAt(text: string, m: RegExpExecArray): { kind: "cross" | "keep"; phone: Phone } | null {
  const len = m[0].length;
  const near = text.slice(m.index, m.index + len + PHONE_REACH);
  for (const re of [PHONE_NANP, PHONE_IL])
    for (const p of near.matchAll(new RegExp(re.source, "g"))) {
      const end = p.index + p[0].length;
      if (p.index >= len || end <= len) continue;
      const rest = near.slice(len, end);
      const gap = /^\D*/.exec(rest)?.[0] ?? "";
      const phone = { gap, value: rest.slice(gap.length), whole: p[0] };
      const inLast = !m[6] && OCTET.test(m[5]) && p.index >= len - m[5].length && gap !== "";
      return { kind: inLast ? "cross" : "keep", phone };
    }
  return null;
}

/** The first part: a one- to three-digit tail of `digits`. Internal wins, then masked public, then the longest. */
function firstOctet(digits: string, rest: string, r: WordGluedRules): string | null {
  let best: { a: string; rank: number } | null = null;
  for (let k = 1; k <= Math.min(3, digits.length); k++) {
    const a = digits.slice(-k);
    if (!OCTET.test(a)) continue;
    const cat = r.category(`${a}.${rest}`);
    if (!cat) continue;
    const rank = cat === "IP" ? 2 : 1; // internal
    if (!best || rank >= best.rank) best = { a, rank };
  }
  return best ? best.a : null;
}

/** The address glued after the word, masked, or null when it stays as it is. */
function readAddress(text: string, m: RegExpExecArray, r: WordGluedRules): Step | null {
  const from = digitsStart(text, m, r);
  if (from === null) return null;
  const digitsEnd = m.index + m[1].length + m[2].length;
  const digits = text.slice(from, digitsEnd);
  const [b, c, last, tail] = [m[3], m[4], m[5], m[6]];
  if (!OCTET.test(String(Number(b))) || !OCTET.test(String(Number(c)))) return null;
  // A word made only of digits: one to three glued on the first number, as #3058 reads digits glued on
  // the last. Three or fewer the IPv4 pass read itself; a longer run, or one after a number group, is
  // a number (a card, a FILETIME) the card pass and the rest read as before.
  const bare = m[1] === "" && from === m.index;
  if (bare && (digits.length <= 3 || digits.length > 6 || NUMBER_GROUP_BEFORE.test(text.slice(0, from))))
    return null;
  if (tail && !OCTET.test(last)) return null; // digits glued on, then more numbers: no reading
  // Digits run on into a number group: they may open a card the card pass reads, as before.
  if (!OCTET.test(last) && CARD_GROUP_NEXT.test(text.slice(m.index + m[0].length))) return null;
  const crossing = r.phone ? phoneAt(text, m) : null;
  if (crossing?.kind === "keep") return null;
  const a = firstOctet(digits, `${b}.${c}.${lastHead(last)}`, r);
  if (a === null) return null;
  const head = `${a}.${b}.${c}.${lastHead(last)}`;
  const start = bare ? from : digitsEnd - a.length;
  const tok = r.mask(head, text.slice(start, m.index + m[0].length));
  const out = text.slice(m.index, start) + tok;
  if (!crossing || !r.phone) return { out, skip: 0 };
  const { gap, value, whole } = crossing.phone;
  return { out: out + gap + r.phone(value, whole), skip: gap.length + value.length };
}

/** Give each IPv4 address glued after a word, and still in clear, its own token. */
export function replaceWordGluedIpv4(text: string, r: WordGluedRules): string {
  let out = "";
  let at = 0;
  WORD_GLUED_V4.lastIndex = 0;
  for (let m = WORD_GLUED_V4.exec(text); m; m = WORD_GLUED_V4.exec(text)) {
    const s = readAddress(text, m, r);
    if (s === null) {
      WORD_GLUED_V4.lastIndex = m.index + 1;
      continue;
    }
    out += text.slice(at, m.index) + s.out;
    at = WORD_GLUED_V4.lastIndex = m.index + m[0].length + s.skip;
  }
  return out + text.slice(at);
}
