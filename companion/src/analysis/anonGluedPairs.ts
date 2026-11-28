import type { AnonTokenCategory } from "./anonymize.js";
import { AMEX, C16, C19, type CardShape, cardOk, isCardNumber, replaceEach } from "./anonPiiPatterns.js";
import { readCardsAsBefore, readGluedIpv4AsBefore, replaceGluedIpv4 } from "./anonPiiPatterns.js";
import type { TokenEnds } from "./anonTokenLiterals.js";
import { replaceWordGluedIpv4 } from "./anonWordGluedIpv4.js";

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
  /** Whether the PHONE category is on: a phone number that starts in a glued address's last number (#3078). */
  readonly phone: boolean;
  /** The call's token ends: `ended` splices a token before a digit (#2992), `aliasEnd` (#3071). */
  readonly ends: Pick<TokenEnds, "aliasEnd" | "ended">;
  /** Whether the REG category is on: a SID before a pair is folded into a REG token (review). */
  readonly reg?: boolean;
  /** False: no address glued after a word is split off. A profile name keeps its one token, as before. */
  readonly word?: boolean;
}

const V4 = String.raw`\d{1,3}(?:\.\d{1,3}){3}`;
const HEAD3 = String.raw`\d{1,3}\.\d{1,3}\.\d{1,3}`;
// Not inside a word or a dotted run, nor after an address group ("abcd:", anonTailJoin's place).
// A pair never starts at a SID's number (review): one that started at the RID left the SID's prefix in
// clear. A pair after a SID is matched with the SID in front (group 1); the SID gets a REG token.
const SID_HEAD = String.raw`(?:\b([Ss]-1-5-21(?:-\d{1,10}){0,3}-)|(?<![Ss]-1-5-21(?:-\d{1,10}){0,3}-))`;
const V4_START = String.raw`(?<![\w.]|[0-9A-Fa-f]:)`;
type Shape = {
  readonly src: string;
  readonly shape: CardShape;
  readonly bare: boolean;
  readonly alone: boolean;
  readonly front?: boolean;
};
// `alone`: with the address left in clear, the card may still be split off (no #3058 reading hid any
// of it, or it is checked below). A 4-4-4-4 card keeps its #3058 reading (the first octet with it).
const SHAPES: readonly Shape[] = [
  { src: String.raw`\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{3}`, shape: C19, bare: false, alone: true },
  { src: String.raw`\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{4}`, shape: C16, bare: false, alone: false },
  { src: String.raw`\d{4}[ -]\d{6}[ -]\d{5}`, shape: AMEX, bare: false, alone: true },
  { src: String.raw`\d{16}`, shape: C16, bare: true, alone: true },
];
// A grouped card with one to three digits glued in front (#3068): judged on its core (the last
// group widths' worth of digits). Split only when both parts are masked; otherwise #3058's reading.
const FRONT: readonly Shape[] = [
  {
    src: String.raw`\d{5,7}[ -]\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{3}`,
    shape: C19,
    bare: false,
    alone: false,
    front: true,
  },
  { src: String.raw`\d{5,7}[ -]\d{4}[ -]\d{4}[ -]\d{4}`, shape: C16, bare: false, alone: false, front: true },
  { src: String.raw`\d{5,7}[ -]\d{6}[ -]\d{5}`, shape: AMEX, bare: false, alone: false, front: true },
];
const CARD_FIRST = [...SHAPES, ...FRONT].map((s) => ({
  ...s,
  re: new RegExp(String.raw`${SID_HEAD}(?<![\w.])(${s.src})(${V4})(?!\w|\.\d)`, "g"),
}));
const IP_FIRST = SHAPES.map((s) => ({
  ...s,
  re: new RegExp(String.raw`${SID_HEAD}${V4_START}(${HEAD3}\.\d{1,3}?)(${s.src})(?!\w)`, "g"),
}));
// Two addresses: the glued middle holds the first one's last octet and the second one's first.
const V4_PAIR_RE = new RegExp(
  String.raw`${SID_HEAD}${V4_START}(${HEAD3})\.(\d{2,6})\.(${HEAD3})(?!\w|\.\d)`,
  "g",
);
const OCTET = /^(?:0|[1-9]\d?|1\d\d|2[0-4]\d|25[0-5])$/;
const validV4 = (ip: string) => ip.split(".").every((p) => Number(p) <= 255);
const lastOctetOk = (ip: string) => OCTET.test(ip.slice(ip.lastIndexOf(".") + 1)) && validV4(ip);
const digitsOf = (raw: string) => raw.replace(/[ -]/g, "");
/** The digits a card match is judged on: a front-glued one by its last group widths' worth. */
const coreOf = (raw: string, s: Shape) =>
  s.front ? digitsOf(raw).slice(-s.shape.widths.reduce((n, w) => n + w, 0)) : digitsOf(raw);

/** A match's SID head ("" without one), its groups after the head, and the glued run itself. */
function headOf(m: RegExpExecArray) {
  const head = m[1] ?? "";
  return { head, g: m.slice(2), run: m[0].slice(head.length), at: m.index + head.length };
}

/**
 * A pair's output after its SID head: the head gets a REG token with the REG category on. A first part
 * left in clear (suppressed, or not masked) keeps the head as is: the SID pass reads it with the RID.
 */
function withHead(head: string, rest: string, r: PairRules): string {
  return !head || !r.reg || /^\d/.test(rest) ? head + rest : r.assign("REG", head) + rest;
}

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
  // #3078: a part kept in clear (suppressed) opens with a digit; the token before it is spliced as #2992.
  const join = (first: string, value: string, second: string, m: RegExpExecArray) => {
    const { at } = headOf(m);
    return /^\d/.test(second)
      ? r.ends.ended(first, value, at, at + value.length, m.input) + second
      : first + second;
  };
  let out = text;
  if (r.card) {
    for (const s of CARD_FIRST)
      out = replaceEach(out, s.re, (m) => {
        const { head, g, run } = headOf(m);
        const [c, a] = g;
        if (!cardOk(coreOf(c, s), s.shape) || !validV4(a) || !maskable(a)) return null;
        if (s.bare && isCardNumber(c + a.slice(0, a.indexOf(".")))) return null; // CARD_RE's whole run
        return (old(run), withHead(head, join(card(c), c, ip(a), m), r));
      });
    for (const s of IP_FIRST)
      out = replaceEach(out, s.re, (m) => {
        const { head, g, run } = headOf(m);
        const [a, c] = g;
        if (!lastOctetOk(a) || !maskable(a) || !cardOk(digitsOf(c), s.shape)) return null;
        return (old(run), withHead(head, join(ip(a), a, card(c), m), r));
      });
  }
  if (!r.ip) return out;
  return replaceEach(out, V4_PAIR_RE, (m) => {
    const res = splitPair(m, maskable, r, ip, old, join);
    return res === null ? null : withHead(headOf(m).head, res, r);
  });
}

/**
 * The glued IPv4 readings (#3058), then an address glued after a word (#3071). A run minted whole also
 * mints the card reading master had of it (saved only, #3068): a later call that leaves the run in
 * clear (public masking off) still hides it.
 */
export function replaceGluedIpv4Runs(text: string, r: PairRules): string {
  const mask = (head: string, run: string) => {
    const cat = r.category(head);
    if (!cat) return run;
    if (r.card) readCardsAsBefore(run, (c) => r.assign("CARD", c));
    return r.assign(cat, run);
  };
  const out = replaceGluedIpv4(text, mask);
  if (r.word === false) return out;
  const phone = r.phone
    ? (value: string, whole: string) => (r.assign("PHONE", whole), r.assign("PHONE", value))
    : null;
  return replaceWordGluedIpv4(out, { category: r.category, mask, ends: r.ends, phone });
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
      const { head, g, run, at } = headOf(m);
      const [c, a] = g;
      if (!s.alone || !cardOk(digitsOf(c), s.shape) || !validV4(a) || maskable(a)) return null;
      if (s.bare && isCardNumber(c + a.slice(0, a.indexOf(".")))) return null;
      return (old(run), head + r.ends.ended(card(c), c, at, at + c.length, out) + a);
    });
  const bare = IP_FIRST[IP_FIRST.length - 1];
  return replaceEach(out, bare.re, (m) => {
    const { head, g, run } = headOf(m);
    const [a, c] = g;
    if (!lastOctetOk(a) || maskable(a) || !cardOk(c, bare.shape)) return null;
    if (isCardNumber(a.slice(a.lastIndexOf(".") + 1) + c)) return null;
    return (old(run), head + a + card(c));
  });
}

/** Two glued addresses, or null. A first address masked whole with a run after it (#3018) is left. */
function splitPair(
  m: RegExpExecArray,
  maskable: (ip: string) => boolean,
  r: PairRules,
  ip: (a: string) => string,
  old: (run: string) => void,
  join: (first: string, value: string, second: string, m: RegExpExecArray) => string,
): string | null {
  const [head, mid, tail] = headOf(m).g;
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
  old(headOf(m).run);
  return join(maskable(best.a) ? ip(best.a) : best.a, best.a, ip(best.b), m);
}
