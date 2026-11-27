import { isIPv6 } from "node:net";
import type { AnonTokenCategory } from "./anonymize.js";
import { anonPairKey } from "./anonPatterns.js";
import { ipv6Mask, type SeparatorFlags } from "./anonIpv6Scan.js";

/**
 * The dotted IPv4 that follows an IPv6 address, and the late stage that joins it (#2990, #2995).
 *
 * IPV6_RE cannot read ".", so the detector stops at the first octet of a dotted IPv4 tail
 * ("fd00::192" of "fd00::192.168.1.5"), and the IPv4 pass needs a boundary that an IPv4 glued right
 * after a complete address ("fd00::ab:12cd192.168.1.5") does not have. Everything here runs AFTER the
 * text passes (accounts, emails, paths, hosts, domains), and joins a tail only while it is still
 * intact: a pass that took part of it (an email domain after it) keeps what it took.
 */

/** An address set aside before the other passes: a plain address (null) or a custom group. */
export type ReservedLiteral = { value: string; category: AnonTokenCategory | null } & SeparatorFlags;

// A value whose last group can open a dotted IPv4 ("fd00::192" of "fd00::192.168.1.5").
const CUT_OCTET = /:\d{1,3}$/;
const FIFTH_OCTET = /^\.\d/;
// A saved value that already holds a whole dotted tail ("fd00::10.10.0.0", #3011).
const DOTTED_V6 = /:\d{1,3}(?:\.\d{1,3}){3}$/;
const GLUED_IPV4 = /^\d{1,3}(?:\.\d{1,3}){3}\b/;
const DOTTED_V4 = /^\d{1,3}(?:\.\d{1,3}){3}$/;
const EXTRA = /^(?:\.\d{1,3})+\b/;
// The IPv4 pass's own reading (IPV4_RE in anonymize.ts), and the dotted numbers after it (#3018).
const IPV4_READ = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const MORE = /(?:\.\d{1,3})+\b/y;
// A dotted run of five or more numbers right after an address left in clear (#3012 shape 2).
const RUN_RAW_RE = /(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})((?:\.\d{1,3})+)\b/g;
// A bare "::" that opens an IPv4-compatible address ("::10.0.0.5"), not a label such as "Evtx::".
const BARE_V6 = /(?:^|[^0-9A-Za-z_:.])::$/;
// A placeholder, then a cut dotted tail or a glued IPv4 address.
const RESTORE_RE = /IPV6:(\d+)(?:((?:\.\d{1,3}){3}\b)|(\d{1,3}(?:\.\d{1,3}){3}\b))?/g;
// An IPv4 glued to the four-digit last group of an address left in clear ("2001:db8::abcd10.0.0.5").
const GLUED_RAW_RE = /(?<=:[0-9a-f]{4})\d{1,3}(?:\.\d{1,3}){3}\b/gi;
const SINGLE_TOKEN = /^ANON_([A-Z]+)_\d+$/;
const NEXT = 32; // how far a phone number after the tail is read

/** Whether an IPv4 glued right after this point of the text could be read as its own address. */
export function gluedIpv4At(text: string, at: number): boolean {
  return GLUED_IPV4.test(text.slice(at, at + 16));
}

/** A phone match that starts inside `seg` and runs into `next`: the part after `seg`, split at its first digit. */
interface Crossing {
  gap: string;
  value: string;
  len: number;
  whole: string;
}

function crossing(seg: string, next: string, crossers: readonly RegExp[]): Crossing | null {
  const text = seg + next;
  for (const re of crossers)
    for (const m of text.matchAll(new RegExp(re.source, "g" + re.flags.replace("g", "")))) {
      if (m.index >= seg.length) break;
      const end = m.index + m[0].length;
      if (end <= seg.length) continue;
      const rest = text.slice(seg.length, end);
      const gap = /^\D*/.exec(rest)?.[0] ?? "";
      return { gap, value: rest.slice(gap.length), len: rest.length, whole: m[0] };
    }
  return null;
}

/** How a tail is joined: a phone match that crosses it must keep its own digits masked (#2995). */
export interface TailRules {
  suppressed: ReadonlySet<string>;
  crossers: readonly RegExp[];
}

function phoneOk(c: Crossing | null, suppressed: ReadonlySet<string>): boolean {
  if (!c) return true;
  return /\d/.test(c.value) && ![c.value, c.whole].some((v) => suppressed.has(v.toLowerCase()));
}

// A phone number that starts in the last number of a plain IPv4 ("100 555-0100" of
// "10.0.0.100 555-0100", #3018). One that starts earlier ("100.200 4624") is not a phone number.
function lastOctetPhone(ip: string, next: string, rules: TailRules): Crossing | null {
  if (FIFTH_OCTET.test(next)) return null;
  const c = crossing(ip, next, rules.crossers);
  if (!c || c.whole.length - c.len > ip.length - ip.lastIndexOf(".") - 1) return null;
  return phoneOk(c, rules.suppressed) ? c : null;
}

/**
 * The value to mint for a masked address and the text left after its token (#2990). `cut` is the
 * rest of a dotted IPv4 (".168.1.5") still intact after every earlier pass; it joins the token. It
 * does not before a fifth octet (the IPv4 pass takes the last four), nor when the joined value is
 * suppressed and the mask is not forced. A phone number that starts in the last octet
 * ("100 555-0100") is split (#2995): the whole address is one token and the rest of the number
 * (`phone`) its own, so nothing goes in clear. If that rest is suppressed, the head keeps its token
 * as before.
 */
export function ipv4TailJoin(
  value: string,
  cut: string,
  next: string,
  forced: boolean,
  rules: TailRules,
): { value: string; rest: string; phone: Crossing | null } {
  const whole = value + cut;
  const joins =
    cut !== "" &&
    CUT_OCTET.test(value) &&
    !FIFTH_OCTET.test(next) &&
    (forced || !rules.suppressed.has(whole.toLowerCase()));
  const phone = joins ? crossing(cut, next, rules.crossers) : null;
  if (!joins || !phoneOk(phone, rules.suppressed)) return { value, rest: cut, phone: null };
  return { value: whole, rest: "", phone };
}

// Whether `value` ends in an IPv6 address that `tail` completes ("lab-fd00::10" + ".0.0.5").
function endsInAddress(value: string, tail: string): boolean {
  for (let i = Math.max(0, value.length - 40); i < value.length; i++)
    if (value[i] !== ":" && isIPv6(value.slice(i) + tail)) return true;
  return false;
}

function beforeIsAddress(text: string, at: number): boolean {
  return endsInAddress(text.slice(Math.max(0, at - 40), at), "");
}

// After an address or a bare "::" (#3012): where a run of dotted numbers belongs to an address.
function afterAddress(text: string, at: number): boolean {
  return beforeIsAddress(text, at) || BARE_V6.test(text.slice(Math.max(0, at - 3), at));
}

/** What the late stage needs from the anonymizer. */
export interface TailMinter {
  assign: (cat: AnonTokenCategory, value: string) => string;
  forcing: <T>(fn: () => T) => T;
  mintCustom: (cat: AnonTokenCategory, value: string) => string;
  ended: (result: string, value: string, at: number, end: number, text: string) => string;
  real: (token: string) => string | undefined;
  ipv4Category: (ip: string) => AnonTokenCategory | null; // the IPv4 pass's own rule
  suppressed: ReadonlySet<string>;
  crossers: () => readonly RegExp[];
  range: (read: string) => AnonTokenCategory | null;
  base: (ip: string) => AnonTokenCategory | null;
}

type Step = { out: string; skip: number };
type Head = { forced: boolean; mint: (v: string) => string };

// String.replace that may also consume `skip` characters after the match.
function consume(text: string, re: RegExp, fn: (m: RegExpExecArray) => Step): string {
  let out = "";
  let at = 0;
  re.lastIndex = 0;
  for (let m = re.exec(text); m; m = re.exec(text)) {
    const r = fn(m);
    out += text.slice(at, m.index) + r.out;
    at = m.index + m[0].length + r.skip;
    re.lastIndex = Math.max(at, m.index + 1);
  }
  return out + text.slice(at);
}

export interface TailJoiner {
  /** Remember a custom token whose value ends in an address head (anonCustom's mint). */
  mark: (result: string, value: string) => string;
  /** Join an intact tail after every marked token; clears the marks. */
  joinMarked: (text: string) => string;
  /** Put the set-aside addresses back, masked, with a cut tail or a glued IPv4 (#2990, #2995). */
  restore: (text: string, literals: readonly ReservedLiteral[]) => string;
  /** Mask an IPv4 glued to an address left in clear. */
  gluedRaw: (text: string) => string;
  /** A pair only this stage minted that is never saved as a discovery (anonPairKey). */
  unsaved: (key: string) => boolean;
}

export function createTailJoiner(d: TailMinter): TailJoiner {
  const marks = new Set<string>();
  const rules = (): TailRules => ({ suppressed: d.suppressed, crossers: d.crossers() });
  // A value this stage joins is never saved as a discovery: as a custom value on a later call it
  // would cut an address with a fifth octet and leave that octet in clear. The head stays saved.
  // A value joined the #2990 way as well is saved as it was before.
  const late = new Set<string>();
  const normal = new Set<string>();
  const track = (tok: string, value: string, isLate: boolean) => {
    const cat = SINGLE_TOKEN.exec(tok)?.[1];
    if (cat) (isLate ? late : normal).add(anonPairKey(cat, value));
    return tok;
  };
  const unsaved = (tok: string, value: string) => track(tok, value, true);
  // Addresses the IPv4 pass would have read in the octets a saved plain IPv4 took (#3018). They
  // are minted by `restore`, which runs only with the IP category on, as the IPv4 pass does.
  const readings: string[] = [];
  // `saved`: the number as the phone pass read it stays a discovery, as before. After a plain IPv4
  // the phone pass never read it, and saved it would cut the last number of another address (#3018).
  function phoneOut(c: Crossing | null, saved = true): Step {
    if (!c) return { out: "", skip: 0 };
    const tok = d.assign("PHONE", c.value);
    if (saved) d.assign("PHONE", c.whole);
    unsaved(tok, c.value);
    return { out: c.gap + tok, skip: c.len };
  }
  // A glued IPv4 as the IPv4 pass masks it; a phone number that starts in it is split as for a tail.
  function glued(ip: string, next: string, saved = true): Step {
    const cat = d.ipv4Category(ip);
    // Before a fifth octet the IPv4 pass reads another four, and it keeps that reading. Before an
    // address still set aside nothing ends the IPv4: that address may go back in clear, digits first.
    if (!cat || d.suppressed.has(ip) || FIFTH_OCTET.test(next) || next.startsWith("\uE000"))
      return { out: ip, skip: 0 };
    const c = crossing(ip, next, d.crossers());
    if (!phoneOk(c, d.suppressed)) return { out: ip, skip: 0 };
    const p = phoneOut(c, saved);
    return { out: d.assign(cat, ip) + p.out, skip: p.skip };
  }
  function head(e: ReservedLiteral): Head | null {
    const cat = e.category;
    if (cat) return { forced: true, mint: (v) => d.mintCustom(cat, v) };
    const m = ipv6Mask<AnonTokenCategory>(e, {
      range: d.range,
      closed: "IP",
      base: d.base,
      suppressed: d.suppressed,
    });
    if (!m) return null;
    return {
      forced: m.forced,
      mint: (v) => (m.forced ? d.forcing(() => d.assign(m.cat, v)) : d.assign(m.cat, v)),
    };
  }
  // #3012: a cut tail with more octets after it ("fd00::10" + ".0.0.5" + ".6"). The IPv4 pass reads
  // the first four numbers after the head. With one extra octet and a maskable reading, that IPv4
  // is masked as a glued one, so a phone number after it is split. Otherwise the whole run is one
  // token under the head's category, forced and never saved; the head and today's IPv4 pair are
  // still minted, so the saved discoveries do not change. null: fall back to the normal join.
  function extraRun(
    h: Head,
    value: string,
    cut: string,
    extra: string,
    at: number,
    end: number,
    t: string,
  ): Step | null {
    const nums = (cut + extra).slice(1).split(".");
    const ip = nums.slice(0, 4).join(".");
    const cat = d.ipv4Category(ip);
    const after = t.slice(end + extra.length, end + extra.length + NEXT);
    if (nums.length === 4 && cat) {
      const tok = h.mint(value);
      const g = glued(ip, after);
      if (g.out === ip) return null;
      const skip = extra.length + g.skip;
      return { out: d.ended(tok + "." + g.out, value, at, end + skip, t), skip };
    }
    if (cat) d.assign(cat, ip); // today's saved pair
    h.mint(value);
    const c = crossing(cut + extra, after, d.crossers());
    if (!phoneOk(c, d.suppressed)) return null;
    const whole = value + cut + extra;
    const tok = unsaved(
      d.forcing(() => h.mint(whole)),
      whole,
    );
    const p = phoneOut(c);
    const skip = extra.length + p.skip;
    return { out: d.ended(tok + p.out, value, at, end + skip, t), skip };
  }
  function restore(t: string, literals: readonly ReservedLiteral[]): string {
    for (const ip of readings.splice(0)) mintReadings(ip, "");
    // Tokens of a whole dotted-tail address with more octets after it (#3012 shape 1), joined late.
    const dotted = new Set<string>();
    const out = consume(t, RESTORE_RE, (m) => {
      const [all, idx, cut = "", ip = ""] = m;
      const at = m.index;
      const end = at + all.length;
      const e = literals[Number(idx)];
      if (e === undefined) return { out: all, skip: 0 }; // never invent a value
      const h = head(e);
      // In clear: the IPv4 pass masks a cut tail, gluedRaw a glued IPv4.
      if (!h) return { out: d.ended(e.value + cut + ip, e.value + cut + ip, at, end, t), skip: 0 };
      const next = t.slice(end, end + NEXT);
      if (ip) {
        const tok = h.mint(e.value);
        const g = glued(ip, next);
        if (g.out === ip) return { out: d.ended(tok, e.value, at, end - ip.length, t) + ip, skip: 0 };
        return { out: d.ended(tok + g.out, e.value, at, end + g.skip, t), skip: g.skip };
      }
      const extra = cut ? (EXTRA.exec(next)?.[0] ?? "") : "";
      const run = extra ? extraRun(h, e.value, cut, extra, at, end, t) : null;
      if (run) return run;
      const j = ipv4TailJoin(e.value, cut, next, h.forced, rules());
      // With a phone split the head keeps the pair it had, so it is still saved as before.
      const tok = track(h.mint(j.value), j.value, j.phone !== null);
      if (j.phone) h.mint(e.value);
      if (!cut && DOTTED_V6.test(j.value) && EXTRA.test(next)) dotted.add(tok);
      if (j.rest) return { out: tok + j.rest, skip: 0 };
      const p = phoneOut(j.phone);
      return { out: d.ended(tok + p.out, e.value, at, end + p.skip, t), skip: p.skip };
    });
    return [...dotted].reduce(joinOne, out);
  }
  function joinOne(t: string, token: string): string {
    const value = d.real(token);
    const cat = SINGLE_TOKEN.exec(token)?.[1] as AnonTokenCategory | undefined;
    if (value === undefined || !cat) return t;
    // A saved dotted-tail value takes every extra intact octet, or the rest would go in clear (#3011).
    // So does a saved plain IPv4 (#3018), and a phone number that starts in its last number is split.
    const v6 = DOTTED_V6.test(value) && isIPv6(value);
    const v4 = !v6 && DOTTED_V4.test(value);
    const dotted = v6 || v4;
    const octets = v4 ? "*" : dotted ? "+" : "{3}";
    const re = new RegExp(`(?<![A-Za-z0-9_])${token}((?:\\.\\d{1,3})${octets})\\b`, "g");
    return consume(t, re, (m) => {
      const tail = m[1];
      const end = m.index + m[0].length;
      const next = t.slice(end, end + NEXT);
      const keep = { out: m[0], skip: 0 };
      if (v4 && tail === "") {
        const p = phoneOut(lastOctetPhone(value, next, rules()), false);
        if (!p.skip) return keep;
        return { out: d.ended(m[0] + p.out, value, m.index, end + p.skip, t), skip: p.skip };
      }
      if (!dotted && (FIFTH_OCTET.test(next) || !endsInAddress(value, tail))) return keep;
      const c = crossing(tail, next, d.crossers());
      if (!phoneOk(c, d.suppressed)) return keep;
      if (v4) readings.push(...(tail.match(IPV4_READ) ?? []));
      const whole = unsaved(
        d.forcing(() => d.assign(cat, value + tail)),
        value + tail,
      );
      const p = phoneOut(c);
      return { out: d.ended(whole + p.out, value, m.index, end + p.skip, t), skip: p.skip };
    });
  }
  // Every address the IPv4 pass reads in a dotted run is still minted, so it is saved as before.
  function mintReadings(first: string, extra: string): void {
    for (const ip of [first, ...(extra.match(IPV4_READ) ?? [])]) {
      const cat = d.ipv4Category(ip);
      if (cat) d.assign(cat, ip);
    }
  }
  // #3012 shape 2: a run of five or more dotted numbers right after an address left in clear (or a
  // bare "::") is masked whole, unsaved, when its first four are an address the IPv4 pass masks.
  // Its pairs are still minted. A plain run is plainRun's (#3018).
  function runRaw(t: string): string {
    return consume(t, RUN_RAW_RE, (m) => {
      const keep = { out: m[0], skip: 0 };
      const cat = d.ipv4Category(m[1]);
      if (!cat || !afterAddress(t, m.index) || d.suppressed.has(m[1])) return keep;
      const end = m.index + m[0].length;
      const c = crossing(m[0], t.slice(end, end + NEXT), d.crossers());
      if (!phoneOk(c, d.suppressed)) return keep;
      mintReadings(m[1], m[2]);
      const tok = unsaved(
        d.forcing(() => d.assign(cat, m[0])),
        m[0],
      );
      const p = phoneOut(c);
      return { out: d.ended(tok + p.out, m[0], m.index, end + p.skip, t), skip: p.skip };
    });
  }
  // #3018: a plain IPv4 as the IPv4 pass reads it. With more dotted numbers after it, the whole
  // run is one token, unsaved, and its pairs are still minted. Without, a phone number that starts
  // in its last number is split. Anything else is left to the IPv4 pass.
  function plainRun(t: string): string {
    return consume(t, IPV4_READ, (m) => {
      const keep = { out: m[0], skip: 0 };
      const cat = d.ipv4Category(m[0]);
      if (!cat || d.suppressed.has(m[0])) return keep;
      const end = m.index + m[0].length;
      MORE.lastIndex = end;
      const extra = MORE.exec(t)?.[0] ?? "";
      const after = t.slice(end + extra.length, end + extra.length + NEXT);
      if (!extra) {
        if (!lastOctetPhone(m[0], after, rules())) return keep;
        const g = glued(m[0], after, false);
        if (g.out === m[0]) return keep;
        return { out: d.ended(g.out, m[0], m.index, end + g.skip, t), skip: g.skip };
      }
      const run = m[0] + extra;
      const c = crossing(run, after, d.crossers());
      if (!phoneOk(c, d.suppressed)) return keep;
      mintReadings(m[0], extra);
      const tok = unsaved(
        d.forcing(() => d.assign(cat, run)),
        run,
      );
      const p = phoneOut(c);
      const skip = extra.length + p.skip;
      return { out: d.ended(tok + p.out, run, m.index, end + skip, t), skip };
    });
  }
  function gluedRaw(raw: string): string {
    const t = runRaw(raw);
    const out = consume(t, GLUED_RAW_RE, (m) => {
      const end = m.index + m[0].length;
      const g = beforeIsAddress(t, m.index) ? glued(m[0], t.slice(end, end + NEXT)) : null;
      if (!g || g.out === m[0]) return { out: m[0], skip: 0 };
      return { out: d.ended(g.out, m[0], m.index, end + g.skip, t), skip: g.skip };
    });
    return plainRun(out);
  }
  return {
    mark: (result, value) => {
      const head = CUT_OCTET.test(value) || DOTTED_V6.test(value) || DOTTED_V4.test(value);
      if (SINGLE_TOKEN.test(result) && head) marks.add(result);
      return result;
    },
    joinMarked: (t) => {
      readings.length = 0;
      let out = t;
      for (const token of marks) out = joinOne(out, token);
      marks.clear();
      return out;
    },
    restore,
    unsaved: (key) => late.has(key) && !normal.has(key),
    gluedRaw,
  };
}
