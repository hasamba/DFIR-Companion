import type { AnonTokenCategory } from "./anonymize.js";
import { AMEX, C16, C19, type CardShape, cardOk, isCardNumber, replaceEach } from "./anonPiiPatterns.js";
import { readCardsAsBefore, readGluedIpv4AsBefore } from "./anonPiiPatterns.js";

// Values glued to each other (#3062): a card glued to an IPv4 address (either order), or two
// addresses glued together, were read as one value and the rest was left in clear. Each part now
// gets its own token. A pair is split only where both parts read exactly: four in-range octets each,
// the card shape's fixed group widths, and a bare card only as exactly sixteen digits.
//
// The pass runs BEFORE the custom pass: a value saved on an earlier call cannot match inside a glued
// run (its edge is a digit), so the pair must be split first or a saved #3058 reading claims it.
// For the same reason every split also mints what #3058 read in the pair (saved pairs only): a later
// call that cannot split it (a category off, public masking off) then hides it as before.

/** What the pass needs from the anonymizer. `ip` / `card`: whether those categories are on. */
export interface PairRules {
  readonly ip: boolean;
  readonly card: boolean;
  readonly category: (ip: string) => AnonTokenCategory | null;
  readonly internal: (ip: string) => boolean;
  readonly assign: (category: AnonTokenCategory, raw: string) => string;
  /** Splices a token before what follows it (a digit needs a delimiter, #2992). */
  readonly ended: (token: string, value: string, at: number, end: number, text: string) => string;
}

const V4 = String.raw`\d{1,3}(?:\.\d{1,3}){3}`;
const HEAD3 = String.raw`\d{1,3}\.\d{1,3}\.\d{1,3}`;
// Not inside a word or a dotted run, nor after an address group ("abcd:", anonTailJoin's place).
const V4_START = String.raw`(?<![\w.]|[0-9A-Fa-f]:)`;
type Shape = {
  readonly src: string;
  readonly shape: CardShape;
  readonly bare: boolean;
  readonly alone: boolean;
};
// `alone`: with the address left in clear, the card may still be split off (no #3058 reading hid any
// of it, or it is checked below). A 4-4-4-4 card keeps its #3058 reading (the first octet with it).
const SHAPES: readonly Shape[] = [
  { src: String.raw`\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{3}`, shape: C19, bare: false, alone: true },
  { src: String.raw`\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{4}`, shape: C16, bare: false, alone: false },
  { src: String.raw`\d{4}[ -]\d{6}[ -]\d{5}`, shape: AMEX, bare: false, alone: true },
  { src: String.raw`\d{16}`, shape: C16, bare: true, alone: true },
];
const CARD_FIRST = SHAPES.map((s) => ({
  ...s,
  re: new RegExp(String.raw`(?<![\w.])(${s.src})(${V4})(?!\w|\.\d)`, "g"),
}));
const IP_FIRST = SHAPES.map((s) => ({
  ...s,
  re: new RegExp(String.raw`${V4_START}(${HEAD3}\.\d{1,3}?)(${s.src})(?!\w)`, "g"),
}));
// Two addresses: the glued middle holds the first one's last octet and the second one's first.
const V4_PAIR_RE = new RegExp(String.raw`${V4_START}(${HEAD3})\.(\d{2,6})\.(${HEAD3})(?!\w|\.\d)`, "g");
const OCTET = /^(?:0|[1-9]\d?|1\d\d|2[0-4]\d|25[0-5])$/;
const validV4 = (ip: string) => ip.split(".").every((p) => Number(p) <= 255);
const lastOctetOk = (ip: string) => OCTET.test(ip.slice(ip.lastIndexOf(".") + 1)) && validV4(ip);
const digitsOf = (raw: string) => raw.replace(/[ -]/g, "");

/** The minting helpers both passes share. `old` mints what #3058 read in a pair (saved pairs only). */
function minters(r: PairRules) {
  const maskable = (ip: string) => r.ip && r.category(ip) !== null;
  const ip = (a: string) => r.assign(r.category(a) ?? "IP", a);
  const card = (c: string) => r.assign("CARD", c);
  const old = (run: string) => {
    const minted = (head: string, m: string) => {
      const cat = r.ip ? r.category(head) : null;
      return cat ? (r.assign(cat, m), "_") : m;
    };
    const left = r.ip ? readGluedIpv4AsBefore(run, r.internal, minted) : run;
    if (r.card) readCardsAsBefore(left, card);
  };
  return { maskable, ip, card, old };
}

/** Before the custom pass: each glued pair whose parts are all masked gets one token per part. */
export function replaceGluedPairs(text: string, r: PairRules): string {
  const { maskable, ip, card, old } = minters(r);
  let out = text;
  if (r.card) {
    for (const s of CARD_FIRST)
      out = replaceEach(out, s.re, (m) => {
        const [c, a] = [m[1], m[2]];
        if (!cardOk(digitsOf(c), s.shape) || !validV4(a) || !maskable(a)) return null;
        if (s.bare && isCardNumber(c + a.slice(0, a.indexOf(".")))) return null; // CARD_RE's whole run
        return (old(m[0]), card(c) + ip(a));
      });
    for (const s of IP_FIRST)
      out = replaceEach(out, s.re, (m) => {
        const [a, c] = [m[1], m[2]];
        if (!lastOctetOk(a) || !maskable(a) || !cardOk(digitsOf(c), s.shape)) return null;
        return (old(m[0]), ip(a) + card(c));
      });
  }
  return r.ip ? replaceEach(out, V4_PAIR_RE, (m) => splitPair(m, maskable, r, ip, old)) : out;
}

/**
 * In the card pass, after the custom pass (so a saved #3058 reading still claims its run when the
 * IP category is off): a card glued to an address left in clear gets its own token. A 4-4-4-4 card
 * keeps its #3058 reading; a bare run CARD_RE reads whole as a card stays CARD_RE's.
 */
export function replaceCardOnlyPairs(text: string, r: PairRules): string {
  const { maskable, card, old } = minters(r);
  let out = text;
  for (const s of CARD_FIRST)
    out = replaceEach(out, s.re, (m) => {
      const [c, a] = [m[1], m[2]];
      if (!s.alone || !cardOk(digitsOf(c), s.shape) || !validV4(a) || maskable(a)) return null;
      if (s.bare && isCardNumber(c + a.slice(0, a.indexOf(".")))) return null;
      return (old(m[0]), r.ended(card(c), c, m.index, m.index + c.length, out) + a);
    });
  const bare = IP_FIRST[IP_FIRST.length - 1];
  return replaceEach(out, bare.re, (m) => {
    const [a, c] = [m[1], m[2]];
    if (!lastOctetOk(a) || maskable(a) || !cardOk(c, bare.shape)) return null;
    if (isCardNumber(a.slice(a.lastIndexOf(".") + 1) + c)) return null;
    return (old(m[0]), a + card(c));
  });
}

/** Two glued addresses, or null. A first address masked whole with a run after it (#3018) is left. */
function splitPair(
  m: RegExpExecArray,
  maskable: (ip: string) => boolean,
  r: PairRules,
  ip: (a: string) => string,
  old: (run: string) => void,
): string | null {
  const [head, mid, tail] = [m[1], m[2], m[3]];
  if (OCTET.test(mid) && maskable(`${head}.${mid}`)) return null;
  let best: { a: string; b: string; rank: number } | null = null;
  for (let i = 1; i <= 3 && i < mid.length; i++) {
    const [x, y] = [mid.slice(0, i), mid.slice(i)];
    const [a, b] = [`${head}.${x}`, `${y}.${tail}`];
    if (!OCTET.test(x) || !OCTET.test(y) || y === "0" || !validV4(a) || !validV4(b)) continue;
    if (!maskable(b)) continue; // the glued digits of the second address were hidden: keep them so
    const rank = (maskable(a) ? 4 : 0) + (r.internal(a) ? 2 : 0) + (r.internal(b) ? 1 : 0);
    if (!best || rank > best.rank) best = { a, b, rank };
  }
  if (!best) return null;
  old(m[0]);
  return (maskable(best.a) ? ip(best.a) : best.a) + ip(best.b);
}
