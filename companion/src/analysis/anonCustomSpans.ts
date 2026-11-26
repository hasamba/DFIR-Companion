import { isIP, type BlockList } from "node:net";
import type { AnonTokenCategory, CustomEntity } from "./anonymize.js";
import {
  cidrBlock,
  exactValueRegExp,
  LEAD_TRIM,
  parseCidr,
  TRAIL_TRIM,
  validatePatternEntity,
  wildcardRegExp,
} from "./anonPatterns.js";

// One pass over the original text for every custom entity — exact values, wildcard patterns and
// IPv4 ranges (#2946). Matching each kind in turn over already-tokenized text could tokenize a
// token ("prod-ANON_USER_1"), which restore() cannot undo. So every matcher reports spans on the
// SAME text, overlaps are resolved (longest first, then leftmost, then exact before pattern) and
// the text is rewritten once.

export interface CompiledCustom {
  exact: Array<{ re: RegExp; category: AnonTokenCategory }>;
  wildcards: Array<{ re: RegExp; category: AnonTokenCategory }>;
  ranges: Array<{ block: BlockList; category: AnonTokenCategory }>;
}

export interface CustomSpan {
  start: number;
  end: number;
  category: AnonTokenCategory;
}

/**
 * Compile the custom list once per anonymizer. An EXTIP entry is skipped when public IPs stay
 * visible (the redacted export): policy says adversary infrastructure stays readable there. A
 * stored pattern that fails validation (a hand-edited file) masks its literal spelling, which is
 * what it did before patterns existed; the dashboard flags it.
 */
export function compileCustomEntities(
  entities: readonly CustomEntity[],
  maskPublicIps: boolean,
): CompiledCustom {
  const out: CompiledCustom = { exact: [], wildcards: [], ranges: [] };
  for (const e of entities) {
    if (!e.value) continue;
    if (e.category === "EXTIP" && !maskPublicIps) continue;
    const valid = e.match === "pattern" && validatePatternEntity(e) === null;
    if (!valid) out.exact.push({ re: exactValueRegExp(e.value), category: e.category });
    else if (e.category === "IP" || e.category === "EXTIP") {
      const cidr = parseCidr(e.value);
      if (typeof cidr !== "string") out.ranges.push({ block: cidrBlock(cidr), category: e.category });
    } else out.wildcards.push({ re: wildcardRegExp(e.value, e.category), category: e.category });
  }
  return out;
}

/** The category of the first custom range holding this address, or null. */
export function rangeCategory(c: CompiledCustom, ip: string): AnonTokenCategory | null {
  const family = isIP(ip);
  if (family === 0) return null;
  for (const r of c.ranges) if (r.block.check(ip, family === 6 ? "ipv6" : "ipv4")) return r.category;
  return null;
}

const IPV4_CANDIDATE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
// Wider than anonymize.ts's IPV6_RE on purpose: a range must catch "fd00:abcd::" (terminal ::)
// and "::ffff:10.20.1.1". Every candidate is validated with isIP before it counts.
const IPV6_CANDIDATE = /(?<![\p{L}\p{N}_:.])[0-9A-Fa-f.]*:[0-9A-Fa-f:.]*(?![\p{L}\p{N}_:])/gu;
const SENTINEL = /[]/u;

/**
 * Replace every IPv6 literal inside a custom range with what `reserve` returns, before any other
 * pass can substitute inside it. An IPv4-mapped address is checked against IPv4 ranges too.
 */
export function reserveCustomIpv6(text: string, c: CompiledCustom, reserve: (ip: string) => string): string {
  if (c.ranges.length === 0) return text;
  return text.replace(IPV6_CANDIDATE, (m) => {
    const ip = m.replace(/\.+$/, "");
    if (isIP(ip) !== 6 || !rangeCategory(c, ip)) return m;
    return reserve(ip) + m.slice(ip.length);
  });
}

interface Candidate extends CustomSpan {
  kind: number; // 0 exact, 1 wildcard, 2 range — the tie-break order
}

function wildcardSpan(m: RegExpMatchArray, category: AnonTokenCategory): Candidate | null {
  const start0 = m.index ?? 0;
  const lead = m.groups?.l ?? "";
  const trail = m.groups?.t ?? "";
  const cutLead = lead.length - lead.replace(LEAD_TRIM, "").length;
  const cutTrail = trail.length - trail.replace(TRAIL_TRIM, "").length;
  const start = start0 + cutLead;
  const end = start0 + m[0].length - cutTrail;
  return end > start ? { start, end, category, kind: 1 } : null;
}

function candidates(text: string, c: CompiledCustom): Candidate[] {
  const out: Candidate[] = [];
  for (const { re, category } of c.exact)
    for (const m of text.matchAll(re))
      out.push({ start: m.index ?? 0, end: (m.index ?? 0) + m[0].length, category, kind: 0 });
  for (const { re, category } of c.wildcards)
    for (const m of text.matchAll(re)) {
      const span = wildcardSpan(m, category);
      if (span) out.push(span);
    }
  if (c.ranges.length > 0)
    for (const m of text.matchAll(IPV4_CANDIDATE)) {
      const category = rangeCategory(c, m[0]);
      if (category) out.push({ start: m.index ?? 0, end: (m.index ?? 0) + m[0].length, category, kind: 2 });
    }
  return out;
}

/** Non-overlapping custom spans on `text`, in text order. */
export function findCustomSpans(text: string, c: CompiledCustom): CustomSpan[] {
  const all = candidates(text, c).filter(
    (s) => !SENTINEL.test(text[s.start - 1] ?? "") && !SENTINEL.test(text[s.end] ?? ""),
  );
  if (all.length === 0) return [];
  all.sort((a, b) => b.end - b.start - (a.end - a.start) || a.start - b.start || a.kind - b.kind);
  const taken = new Uint8Array(text.length);
  const kept: CustomSpan[] = [];
  for (const s of all) {
    let free = true;
    for (let i = s.start; i < s.end && free; i++) free = taken[i] === 0;
    if (!free) continue;
    taken.fill(1, s.start, s.end);
    kept.push({ start: s.start, end: s.end, category: s.category });
  }
  return kept.sort((a, b) => a.start - b.start);
}

/** Rewrite `text` once, replacing each span with what `mint` returns for its real value. */
export function spliceSpans(
  text: string,
  spans: readonly CustomSpan[],
  mint: (category: AnonTokenCategory, real: string) => string,
): string {
  let out = "";
  let at = 0;
  for (const s of spans) {
    out += text.slice(at, s.start) + mint(s.category, text.slice(s.start, s.end));
    at = s.end;
  }
  return out + text.slice(at);
}
