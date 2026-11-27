import type { AnonTokenCategory } from "./anonymize.js";
import { exactValueRegExp } from "./anonPatterns.js";
import { nextSpan, valuesCanOverlap } from "./anonChunkedMatch.js";

// Known hosts and internal domains are masked one value at a time, longest first, as before. But a
// value replaced first used up the start of an overlapping one, so the rest went out in clear: with
// the hosts "ws-alpha" and "alpha-01", "ws-alpha-01" became "ANON_HOST_1-01" (#3013). The pass now
// runs over the original text and keeps each replaced span; a known value that overlaps a replaced
// span and would leave a letter, digit or "_" in clear joins it into one token. Where nothing would
// go out in clear, the spans and tokens are exactly what the one-at-a-time replace made.

export interface KnownValue {
  value: string;
  category: AnonTokenCategory;
}
interface Claim {
  start: number;
  end: number;
  token: string;
  parts: KnownValue[];
  order: number;
}
const WORD_CHAR = /[\p{L}\p{N}_]/u;

/** Replaced spans, sorted by start. They never overlap, so their ends are sorted too. */
class Claims {
  list: Claim[] = [];
  /** [i, j) of the spans that overlap [s, e), or also touch it when `touch` is set. */
  range(s: number, e: number, touch: boolean): [number, number] {
    let lo = 0;
    let hi = this.list.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (touch ? this.list[mid].end < s : this.list[mid].end <= s) lo = mid + 1;
      else hi = mid;
    }
    let j = lo;
    while (j < this.list.length && (touch ? this.list[j].start <= e : this.list[j].start < e)) j++;
    return [lo, j];
  }
  add(found: readonly Claim[]): void {
    this.list = [...this.list, ...found].sort((a, b) => a.start - b.start);
  }
  /** True when [s, e) holds a letter, digit or "_" that no span covers. */
  leaks(text: string, s: number, e: number): boolean {
    const [i, j] = this.range(s, e, false);
    let pos = s;
    for (const c of this.list.slice(i, j)) {
      if (c.start > pos && WORD_CHAR.test(text.slice(pos, c.start))) return true;
      pos = Math.max(pos, c.end);
    }
    return pos < e && WORD_CHAR.test(text.slice(pos, e));
  }
}

// The matchers of a value list, compiled once: one anonymizer applies the same list to every text.
const COMPILED = new WeakMap<readonly KnownValue[], Array<ReturnType<typeof exactValueRegExp>>>();
function compiled(values: readonly KnownValue[]): Array<ReturnType<typeof exactValueRegExp>> {
  let list = COMPILED.get(values);
  if (!list) COMPILED.set(values, (list = values.map((v) => exactValueRegExp(v.value))));
  return list;
}

/** The spans a one-at-a-time replace would have replaced, each minted in its order. */
function claimSpans(text: string, values: readonly KnownValue[], mint: (v: KnownValue) => string): Claims {
  const claims = new Claims();
  let order = 0;
  const matchers = compiled(values);
  for (const [k, v] of values.entries()) {
    const re = matchers[k];
    const found: Claim[] = [];
    // A replaced span is a token, so a later value can neither match inside it nor touch it.
    const blocked = (m: [number, number]) => {
      const [i, j] = claims.range(m[0], m[1], true);
      return i < j;
    };
    for (let m = nextSpan(re, text, 0); m; m = nextSpan(re, text, blocked(m) ? m[0] + 1 : m[1])) {
      if (blocked(m)) continue;
      const part = { value: text.slice(m[0], m[1]), category: v.category };
      const token = mint(part);
      if (token !== part.value) found.push({ start: m[0], end: m[1], token, parts: [part], order: order++ }); // a suppressed value stays text
    }
    claims.add(found);
  }
  return claims;
}

/** Every occurrence of every value, overlapping ones included, that is not inside one span. */
function occurrences(
  text: string,
  values: readonly KnownValue[],
  claims: Claims,
): Array<[number, number, KnownValue]> {
  const out: Array<[number, number, KnownValue]> = [];
  const matchers = compiled(values);
  for (const [k, v] of values.entries()) {
    const re = matchers[k];
    for (let m = nextSpan(re, text, 0); m; m = nextSpan(re, text, m[0] + 1)) {
      const [i, j] = claims.range(m[0], m[1], false);
      const inside = j === i + 1 && claims.list[i].start <= m[0] && claims.list[i].end >= m[1];
      if (!inside) out.push([m[0], m[1], v]);
    }
  }
  return out;
}

/**
 * Replace every known value with `mint(...)`, one value at a time in the given order. A value that
 * overlaps the replaced spans and would leave part of itself in clear joins them into one span,
 * minted with `join(span, parts)`: `parts` are the values it is made of. A value `kept` says the
 * analyst suppressed never joins anything: it stays text, as it did before.
 */
export function replaceKnownValues(
  text: string,
  values: readonly KnownValue[],
  mint: (v: KnownValue) => string,
  join: (span: KnownValue, parts: KnownValue[]) => string,
  kept: (value: string) => boolean,
): string {
  const claims = claimSpans(text, values, mint);
  if (claims.list.length === 0 || isPlain(values)) return splice(text, claims);
  const occ = occurrences(text, values, claims);
  for (let changed = true; changed;) {
    changed = false;
    for (const [s, e, v] of occ) {
      const [i, j] = claims.range(s, e, true);
      if (i === j || kept(text.slice(s, e)) || !claims.leaks(text, s, e)) continue;
      const touched = claims.list.slice(i, j);
      const start = Math.min(s, touched[0].start);
      const end = Math.max(e, touched[touched.length - 1].end);
      const first = touched.reduce((a, b) => (b.order < a.order ? b : a));
      const parts = [...touched.flatMap((c) => c.parts), { value: text.slice(s, e), category: v.category }];
      const whole = s === start && e === end; // the value covers the run: it keeps its own category
      const span = { value: text.slice(start, end), category: whole ? v.category : first.parts[0].category };
      if (kept(span.value)) continue; // a suppressed run would stay text: keep the spans as they were
      const joined = { start, end, token: join(span, parts), parts, order: first.order };
      claims.list = [...claims.list.slice(0, i), joined, ...claims.list.slice(j)];
      changed = true;
    }
  }
  return splice(text, claims);
}

// Whether a value list needs the join pass at all, per list: one anonymizer applies the same list
// to every text, and the check sorts and compares every value.
const PLAIN = new WeakMap<readonly KnownValue[], boolean>();
function isPlain(values: readonly KnownValue[]): boolean {
  let plain = PLAIN.get(values);
  if (plain === undefined) {
    plain = !valuesCanOverlap(values.map((v) => v.value)) && !containsEarlier(values);
    PLAIN.set(values, plain);
  }
  return plain;
}

/** True when a value contains one that is replaced before it (a domain holding a host label). */
function containsEarlier(values: readonly KnownValue[]): boolean {
  const low = values.map((v) => v.value.toLowerCase());
  for (let j = 1; j < low.length; j++)
    for (let i = 0; i < j; i++) if (low[i].length < low[j].length && low[j].includes(low[i])) return true;
  return false;
}

function splice(text: string, claims: Claims): string {
  let out = "";
  let at = 0;
  for (const c of claims.list) {
    out += text.slice(at, c.start) + c.token;
    at = c.end;
  }
  return out + text.slice(at);
}
