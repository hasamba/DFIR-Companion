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
// A saved value that starts with a number can match inside a longer dotted run (#3019).
const LEAD_DIGIT = /^\d/;
// A phone value whose first (dotted) number can end a dotted IPv4 in front of it ("100 555-0100").
const PHONE_HEAD = /^(\d{1,3}(?:\.\d{1,3}){0,3})([^\d.]\D*)(\d.*)$/s;
const NEXT = 32; // how far a phone number after the tail is read
// A last group of digits a phone number can start in ("fd00::164" + " 555-0100", #3043).
const DIGIT_GROUP = /:(\d{1,4})$/;
// A REG token, then a saved phone value or dotted numbers glued after it (#3037).
const SID_TAIL_RE =
  /(?<![A-Za-z0-9_])(ANON_REG_\d+)(?:((?:\.\d{1,3})*\.)(ANON_PHONE_\d+)(?!\d)|((?:\.\d{1,3}){3,})\b)/g;
const SID_VALUE = /^S-1-5-21(?:-\d{1,10}){4}$/i;
const OCTET = /^(?:0|[1-9]\d?|1\d\d|2[0-4]\d|25[0-5])$/;

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

// The end of an address a phone number may start in: the dotted IPv4 after its first number
// ("::ffff:198" + ".51.100.120" + " 4624", as for a cut tail), or a last group of digits
// ("fd00::" + "164" + " 555-0100", #3043). A plain IPv4 keeps lastOctetPhone (#3018).
function endPhone(value: string, next: string, rules: TailRules): Crossing | null {
  if (DOTTED_V4.test(value)) return lastOctetPhone(value, next, rules);
  if (FIFTH_OCTET.test(next)) return null;
  const ipv4 = value.slice(value.lastIndexOf(":") + 1);
  const seg = DOTTED_V6.test(value) ? ipv4.slice(ipv4.indexOf(".")) : DIGIT_GROUP.exec(value)?.[1];
  const c = seg ? crossing(seg, next, rules.crossers) : null;
  return phoneOk(c, rules.suppressed) ? c : null;
}

// The addresses a dotted run glued after a SID may hold: the SID's last one to three digits open it
// (the SID's last digits plus a private address such as 192.168.x.x, read with one, two or three of
// those digits; a leading zero is no address), and the IPv4 pass reads any four numbers in the run
// itself (#3037).
function sidReadings(sid: string, dotted: string): { all: string[]; tail: string[] } {
  const rid = sid.slice(sid.lastIndexOf("-") + 1);
  const rest = dotted.split(".").slice(1, 4).join(".");
  const heads = [1, 2, 3].filter((n) => n < rid.length && OCTET.test(rid.slice(-n)));
  const tail = dotted.match(IPV4_READ) ?? [];
  return { all: [...heads.map((n) => `${rid.slice(-n)}.${rest}`), ...tail], tail };
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
  // Saved phone tokens with dotted numbers in front of them, split in `restore` (#3019).
  const phoneLeads = new Set<string>();
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
  function restore(raw: string, literals: readonly ReservedLiteral[]): string {
    for (const ip of readings.splice(0)) mintReadings(ip, "");
    const t = [...phoneLeads].reduce(splitPhoneLead, sidTail(raw));
    phoneLeads.clear();
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
      if (!h) {
        const s =
          cut || ip ? null : (clearHeadSaved(e.value, at, end, t) ?? clearHeadPhone(e.value, at, end, t));
        return s ?? { out: d.ended(e.value + cut + ip, e.value + cut + ip, at, end, t), skip: 0 };
      }
      const next = t.slice(end, end + NEXT);
      if (ip) {
        const tok = h.mint(e.value);
        const g = glued(ip, next);
        if (g.out === ip) return { out: d.ended(tok, e.value, at, end - ip.length, t) + ip, skip: 0 };
        return { out: d.ended(tok + g.out, e.value, at, end + g.skip, t), skip: g.skip };
      }
      const split = cut
        ? null
        : (savedPhoneTail(h, e.value, at, end, t) ?? mappedPhone(h, e.value, at, end, t));
      if (split) return split;
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
  // #3019: an address left in clear whose last group opens a dotted run that a saved IPv4 ends
  // ("2001:db8::10" + "." + the token of "10.0.0.5"). A call without saved values masks the run
  // whole (runRaw), so the last group joins the saved address in one token, forced and unsaved.
  function clearHeadSaved(value: string, at: number, end: number, t: string): Step | null {
    const last = /:(\d{1,3})$/.exec(value)?.[1];
    const m = /^\.(ANON_[A-Z]+_\d+)(?!\d)/.exec(t.slice(end, end + 40));
    const saved = m ? d.real(m[1]) : undefined;
    if (!last || !m || saved === undefined || !/^\d{1,3}(?:\.\d{1,3}){3,}$/.test(saved)) return null;
    const run = `${last}.${saved}`;
    const ip = run.split(".").slice(0, 4).join(".");
    const cat = d.ipv4Category(ip);
    if (!cat || d.suppressed.has(ip)) return null;
    mintReadings(ip, run.slice(ip.length));
    const tok = unsaved(
      d.forcing(() => d.assign(cat, run)),
      run,
    );
    const skip = m[0].length;
    const out = value.slice(0, -last.length) + tok;
    return { out: d.ended(out, value, at, end + skip, t), skip };
  }
  // The same before a saved phone value ("2001:db8::10" + ".0.0." + the token of "100 555-0100"):
  // the dotted IPv4 is masked as the IPv4 pass masks it, and the rest of the number is its own token.
  function clearHeadPhone(value: string, at: number, end: number, t: string): Step | null {
    const last = /:(\d{1,3})$/.exec(value)?.[1];
    const m = /^((?:\.\d{1,3}){0,2}\.)(ANON_PHONE_\d+)(?!\d)/.exec(t.slice(end, end + 40));
    const head = m ? PHONE_HEAD.exec(d.real(m[2]) ?? "") : null;
    if (!last || !m || !head || (m[1] + head[1]).split(".").length < 4) return null;
    const [, num, gap, rest] = head;
    const run = last + m[1] + num;
    const ip = run.split(".").slice(0, 4).join(".");
    const cat = d.ipv4Category(ip);
    if (!cat || d.suppressed.has(ip)) return null;
    // A longer run ("2001:db8::10" + "." + the token of "10.0.0.100 555-0100") is one token, forced
    // and unsaved, as runRaw masks it on a call without saved values; its readings are minted (#3027).
    const ipTok = run === ip ? d.assign(cat, ip) : clearRun(cat, ip, run);
    const phone = unsaved(
      d.forcing(() => d.assign("PHONE", rest)),
      rest,
    );
    const skip = m[0].length;
    const out = value.slice(0, -last.length) + ipTok + gap + phone;
    return { out: d.ended(out, value, at, end + skip, t), skip };
  }
  function clearRun(cat: AnonTokenCategory, ip: string, run: string): string {
    mintReadings(ip, run.slice(ip.length));
    return unsaved(
      d.forcing(() => d.assign(cat, run)),
      run,
    );
  }
  // #3019: a masked address head whose dotted tail ends in a saved phone value ("fd00::10" +
  // ".0.0." + the token of "100 555-0100"). As on a call without saved values, the whole address is
  // one token, unsaved, the head keeps its pair, and the rest of the number is its own token.
  function savedPhoneTail(h: Head, value: string, at: number, end: number, t: string): Step | null {
    const m = /^((?:\.\d{1,3}){0,2}\.)(ANON_PHONE_\d+)(?!\d)/.exec(t.slice(end, end + 40));
    const head = m && CUT_OCTET.test(value) ? PHONE_HEAD.exec(d.real(m[2]) ?? "") : null;
    if (!m || !head || (m[1] + head[1]).split(".").length !== 4) return null;
    const [, num, gap, rest] = head;
    const whole = value + m[1] + num;
    if (!h.forced && d.suppressed.has(whole.toLowerCase())) return null;
    const tok = track(h.mint(whole), whole, true);
    h.mint(value);
    const phone = unsaved(
      d.forcing(() => d.assign("PHONE", rest)),
      rest,
    );
    const skip = m[0].length;
    return { out: d.ended(tok + gap + phone, value, at, end + skip, t), skip };
  }
  // #3033: an address set aside whole with its dotted IPv4 ("::ffff:10.0.0.100", which IPV6_RE reads
  // in one piece) has no cut tail to join. A phone number that starts in its last number is split
  // as for "fd00::10.0.0.100", whose cut tail (".0.0.100") it may start in: the address keeps its
  // token, still saved, and the rest of the number is its own token, never saved.
  // #3043: so is a phone number that starts in a last group of digits ("fd00::164 555-0100").
  function mappedPhone(h: Head, value: string, at: number, end: number, t: string): Step | null {
    if (!DOTTED_V6.test(value) && !DIGIT_GROUP.test(value)) return null;
    const c = endPhone(value, t.slice(end, end + NEXT), rules());
    if (!c) return null;
    const tok = h.mint(value);
    const p = phoneOut(c, false);
    return { out: d.ended(tok + p.out, value, at, end + p.skip, t), skip: p.skip };
  }
  // #3037: a SID with an IPv4 glued right after it ("S-1-5-21-…-1001" + "192.168.1.5"). The RID took
  // the address's first number, and where the address starts cannot be known, so the dotted numbers
  // after the REG token join it in one token, forced and never saved. The SID's pair and every
  // address the IPv4 pass reads in the run stay minted, so the saved values do not change. Only when
  // a reading is one the IPv4 pass masks. A phone number that starts in the run is split, and so is a
  // saved phone value the run ends in. It runs in `restore`, so only with the IP category on.
  function sidTail(t: string): string {
    return consume(t, SID_TAIL_RE, (m) => {
      const [all, token, lead = "", phoneTok = "", tail = ""] = m;
      const keep = { out: all, skip: 0 };
      const sid = d.real(token) ?? "";
      const ph = phoneTok ? PHONE_HEAD.exec(d.real(phoneTok) ?? "") : null;
      const dotted = phoneTok ? lead + (ph?.[1] ?? "") : tail;
      if (!SID_VALUE.test(sid) || (phoneTok && (!ph || dotted.split(".").length < 4))) return keep;
      const r = sidReadings(sid, dotted);
      if (!r.all.some((ip) => d.ipv4Category(ip) && !d.suppressed.has(ip))) return keep;
      const end = m.index + all.length;
      const c = ph ? null : crossing(tail, t.slice(end, end + NEXT), d.crossers());
      if (!phoneOk(c, d.suppressed)) return keep;
      for (const ip of r.tail) mintReadings(ip, "");
      const whole = sid + dotted;
      const tok = unsaved(
        d.forcing(() => d.assign("REG", whole)),
        whole,
      );
      if (ph) {
        const rest = unsaved(
          d.forcing(() => d.assign("PHONE", ph[3])),
          ph[3],
        );
        return { out: d.ended(tok + ph[2] + rest, all, m.index, end, t), skip: 0 };
      }
      // Saved as the phone pass would read it: not after a plain IPv4 the IPv4 pass splits (#3018).
      const plain = r.tail.length === 1 && r.tail[0] === tail.slice(1) && d.ipv4Category(r.tail[0]);
      const p = phoneOut(c, !plain || d.suppressed.has(r.tail[0]));
      return { out: d.ended(tok + p.out, all, m.index, end + p.skip, t), skip: p.skip };
    });
  }
  function joinOne(t: string, token: string): string {
    const value = d.real(token);
    const cat = SINGLE_TOKEN.exec(token)?.[1] as AnonTokenCategory | undefined;
    if (value === undefined || !cat) return t;
    // A saved dotted-tail value takes every extra intact octet, or the rest would go in clear (#3011).
    // So does a saved plain IPv4 (#3018), and a phone number that starts in its last number is split.
    // A value that ends in ":" + a dotted IPv4 ("ffff:10.0.0.5") is read the same way (#3019).
    const v6 = DOTTED_V6.test(value);
    const v4 = !v6 && DOTTED_V4.test(value);
    const dotted = v6 || v4;
    // Without a tail, a value that ends in a group of digits may still start a phone number (#3043).
    const octets = dotted ? "(?:\\.\\d{1,3})*" : "(?:\\.\\d{1,3}){3}|";
    const re = new RegExp(`(?<!\\d)${token}(${octets})\\b`, "g");
    return consume(t, re, (m) => {
      const tail = m[1];
      const end = m.index + m[0].length;
      const next = t.slice(end, end + NEXT);
      const keep = { out: m[0], skip: 0 };
      // A phone number that starts in the last number of a saved dotted tail ("fd00::10.0.0.100" +
      // " 555-0100") is split, as on a call without saved values (#3027), and one that starts where
      // a call without saved values splits it after that address (#3043).
      if (tail === "") {
        const p = phoneOut(endPhone(value, next, rules()), false);
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
  // #3019: a saved value that starts with a number, matched at the end of a longer dotted run
  // ("10.0.0.5" in "10.10.0.0.5", "10.0.0.5@…" in "10.10.0.0.5@…"), takes the numbers in front of it,
  // or they go in clear where a call without saved values masks them. Forced and never saved. A
  // saved IPv4 takes the extra numbers after it too, and a phone number that starts in it is split.
  // The cut tail of an address still set aside is restore's ("fd00::10" + ".10.0.0"), never a lead.
  // Fewer than three numbers are never a cut tail, so they can be ("fd00::10" + ".10." + token).
  const afterSetAside = (t: string, m: RegExpExecArray) =>
    /\.?$/.test(t.slice(Math.max(0, m.index - 2), m.index)) && m[1].split(".").length > 3;
  function leadRe(token: string, tail: string): RegExp {
    return new RegExp(`(?<![A-Za-z0-9_])((?:\\d{1,3}\\.)+)${token}${tail}(?!\\d)`, "g");
  }
  function joinLead(t: string, token: string): string {
    const value = d.real(token);
    const cat = SINGLE_TOKEN.exec(token)?.[1] as AnonTokenCategory | undefined;
    if (value === undefined || !cat) return t;
    const v4 = DOTTED_V4.test(value);
    // A value that can take a dotted tail takes it with the lead, in one token.
    const tails = v4 || DOTTED_V6.test(value) || CUT_OCTET.test(value);
    return consume(t, leadRe(token, tails ? "((?:\\.\\d{1,3})*)" : "()"), (m) => {
      const [all, lead, tail = ""] = m;
      if (afterSetAside(t, m)) return { out: all, skip: 0 };
      const end = m.index + all.length;
      const whole = lead + value + tail;
      // A run the IPv4 pass would leave in clear ("8.8." + a saved private address, public masking
      // off) keeps the saved token as it is: a call without saved values masks none of it.
      const first = whole.match(IPV4_READ)?.[0];
      if (v4 && (!first || !d.ipv4Category(first))) return { out: all, skip: 0 };
      // Every address the IPv4 pass reads in the run is still minted, so it is saved as before.
      readings.push(...(whole.match(IPV4_READ) ?? []));
      if (!tails) {
        const tok = unsaved(d.mintCustom(cat, whole), whole);
        return { out: d.ended(tok, whole, m.index, end, t), skip: 0 };
      }
      const c = crossing(whole, t.slice(end, end + NEXT), d.crossers());
      if (!phoneOk(c, d.suppressed)) return { out: all, skip: 0 };
      const tok = unsaved(
        d.forcing(() => d.assign(cat, whole)),
        whole,
      );
      const p = phoneOut(c);
      return { out: d.ended(tok + p.out, whole, m.index, end + p.skip, t), skip: p.skip };
    });
  }
  // A saved phone value whose first number ends a dotted IPv4 in front of it ("192.168.1." +
  // "100 555-0100"): the address and the rest of the number each get a token, as on a call without
  // saved values. It runs in `restore`, so only with the IP category on, as the IPv4 pass does. The
  // rest of the number is forced: the saved token hid it already.
  function splitPhoneLead(t: string, token: string): string {
    const head = PHONE_HEAD.exec(d.real(token) ?? "");
    if (!head) return t;
    const [, num, gap, rest] = head;
    return consume(t, leadRe(token, ""), (m) => {
      const keep = { out: m[0], skip: 0 };
      if (afterSetAside(t, m)) return keep;
      const run = m[1] + num;
      const nums = run.split(".");
      const ip = nums.slice(0, 4).join(".");
      const cat = d.ipv4Category(ip);
      if (nums.length < 4 || !cat || d.suppressed.has(ip)) return keep;
      let ipTok: string;
      if (nums.length === 4) ipTok = d.assign(cat, ip);
      else {
        mintReadings(ip, run.slice(ip.length));
        ipTok = unsaved(
          d.forcing(() => d.assign(cat, run)),
          run,
        );
      }
      const phTok = unsaved(
        d.forcing(() => d.assign("PHONE", rest)),
        rest,
      );
      const end = m.index + m[0].length;
      return { out: d.ended(ipTok + gap + phTok, m[0], m.index, end, t), skip: 0 };
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
      const head = DIGIT_GROUP.test(value) || DOTTED_V6.test(value) || DOTTED_V4.test(value);
      if (SINGLE_TOKEN.test(result) && (head || LEAD_DIGIT.test(value))) marks.add(result);
      return result;
    },
    joinMarked: (t) => {
      readings.length = 0;
      phoneLeads.clear();
      let out = t;
      for (const token of marks) {
        const value = d.real(token) ?? "";
        if (token.startsWith("ANON_PHONE_")) phoneLeads.add(token);
        else if (LEAD_DIGIT.test(value)) out = joinLead(out, token);
        if (DIGIT_GROUP.test(value) || DOTTED_V6.test(value) || DOTTED_V4.test(value))
          out = joinOne(out, token);
      }
      marks.clear();
      return out;
    },
    restore,
    unsaved: (key) => late.has(key) && !normal.has(key),
    gluedRaw,
  };
}
