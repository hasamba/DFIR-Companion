import { isIP, type BlockList } from "node:net";
import type { AnonTokenCategory, CustomEntity } from "./anonymize.js";
import {
  cidrBlock,
  exactValueRegExp,
  parseCidr,
  validatePatternEntity,
  wildcardMatchSpan,
  wildcardRegExp,
} from "./anonPatterns.js";

// One pass over the original text for every custom entity — exact values, wildcard patterns and
// IPv4 ranges (#2946). Matching each kind in turn over already-tokenized text could tokenize a
// token ("prod-ANON_USER_1"), which restore() cannot undo. So every matcher reports spans on the
// SAME text and the text is rewritten once. Overlapping matches are MERGED into one span, never
// dropped: dropping the shorter of two crossing matches left its uncovered part in clear text
// ("payroll.corp.example/secret" under "*.corp.example" and "corp.example/secret"). The merged
// span takes the category of its longest member. IPv6 range literals are found here too, in the
// same coordinates, so a longer custom value that encloses one is still hidden whole.

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

interface Candidate extends CustomSpan {
  kind: number; // 0 exact, 1 wildcard, 2 range — the tie-break order
}

function rangeCandidates(text: string, c: CompiledCustom): Candidate[] {
  const out: Candidate[] = [];
  for (const re of [IPV4_CANDIDATE, IPV6_CANDIDATE])
    for (const m of text.matchAll(re)) {
      const ip = m[0].replace(/\.+$/, "");
      const category = rangeCategory(c, ip);
      if (category) out.push({ start: m.index ?? 0, end: (m.index ?? 0) + ip.length, category, kind: 2 });
    }
  return out;
}

function candidates(text: string, c: CompiledCustom): Candidate[] {
  const out: Candidate[] = [];
  for (const { re, category } of c.exact)
    for (const m of text.matchAll(re))
      out.push({ start: m.index ?? 0, end: (m.index ?? 0) + m[0].length, category, kind: 0 });
  for (const { re, category } of c.wildcards)
    for (const m of text.matchAll(re)) {
      const span = wildcardMatchSpan(m);
      if (span) out.push({ ...span, category, kind: 1 });
    }
  if (c.ranges.length > 0) out.push(...rangeCandidates(text, c));
  return out;
}

/** Non-overlapping custom spans on `text`, in text order; overlapping matches are merged. */
export function findCustomSpans(text: string, c: CompiledCustom): CustomSpan[] {
  const all = candidates(text, c).filter(
    (s) => !SENTINEL.test(text[s.start - 1] ?? "") && !SENTINEL.test(text[s.end] ?? ""),
  );
  all.sort((a, b) => a.start - b.start || b.end - a.end);
  const merged: CustomSpan[] = [];
  let group: Candidate[] = [];
  let end = -1;
  const flush = () => {
    if (group.length === 0) return;
    const lead = group.reduce((best, s) => (dominates(s, best) ? s : best));
    merged.push({ start: group[0].start, end, category: lead.category });
  };
  for (const s of all) {
    if (s.start >= end) {
      flush();
      group = [];
    }
    group.push(s);
    end = Math.max(end, s.end);
  }
  flush();
  return merged;
}

// Longest wins; then exact before pattern before range; then leftmost.
function dominates(a: Candidate, b: Candidate): boolean {
  const len = a.end - a.start - (b.end - b.start);
  return len > 0 || (len === 0 && (a.kind < b.kind || (a.kind === b.kind && a.start < b.start)));
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
