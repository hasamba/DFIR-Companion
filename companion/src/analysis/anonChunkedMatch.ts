import { escapeRegExp } from "./regexEscape.js";

// V8 compiles a regex literal under "iu" recursively and overflows the stack near 12k letters (about
// 8k from a deep call stack). One learned name or known value can be that long — a profile path
// followed by a long line on the same line is one username (#3007) — and the throw came at the first
// exec, on every masked call of the case. A value longer than MAX_LITERAL is matched chunk by chunk
// instead: a "giu" head with the leading word boundary, sticky "iuy" chunks, then the trailing
// boundary. Case folding in JavaScript regexes is 1:1 (simple folding), so the chunks match exactly
// what the single literal matched.

/** The longest value compiled as one literal; 256 leaves a ~30x margin under the deep-stack limit. */
export const MAX_LITERAL = 256;
const UNICODE_WORD = "\\p{L}\\p{N}_";
const TAIL = new RegExp(`(?![${UNICODE_WORD}])`, "uy");

export interface LongLiteral {
  head: RegExp;
  rest: RegExp[];
}

/** Compile one long value into its chunks (split by code point, so a surrogate pair stays whole). */
export function compileLong(value: string): LongLiteral {
  const chunks = value.match(new RegExp(`[\\s\\S]{1,${MAX_LITERAL}}`, "gu")) ?? [""];
  const head = new RegExp(`(?<![${UNICODE_WORD}])${escapeRegExp(chunks[0])}`, "giu");
  return { head, rest: chunks.slice(1).map((c) => new RegExp(escapeRegExp(c), "iuy")) };
}

/** The first whole-word [start, end) at or after `from` where the long value matches, or null. */
export function nextLong(text: string, ln: LongLiteral, from: number): [number, number] | null {
  ln.head.lastIndex = from;
  for (let m = ln.head.exec(text); m; m = ln.head.exec(text)) {
    let pos = m.index + m[0].length;
    const ok = ln.rest.every((r) => {
      r.lastIndex = pos;
      const mm = r.exec(text);
      if (mm) pos += mm[0].length;
      return !!mm;
    });
    TAIL.lastIndex = pos;
    if (ok && TAIL.test(text)) return [m.index, pos];
    ln.head.lastIndex = m.index + 1;
  }
  return null;
}

type Span = [number, number];
export type ValueReplacer = (m: string, offset: number, whole: string) => string;
/** A whole-word, case-insensitive matcher of ONE long value, usable with String.replace (#3009). */
export interface LongValueMatcher {
  next(text: string, from: number): Span | null;
  [Symbol.replace](text: string, fn: ValueReplacer): string;
}
export function longValueMatcher(value: string): LongValueMatcher {
  const ln = compileLong(value);
  const next = (text: string, from: number) => nextLong(text, ln, from);
  return {
    next,
    [Symbol.replace](text: string, fn: ValueReplacer): string {
      let out = "";
      let at = 0;
      for (let m = next(text, 0); m; m = next(text, at)) {
        out += text.slice(at, m[0]) + fn(text.slice(m[0], m[1]), m[0], text);
        at = m[1];
      }
      return out + text.slice(at);
    },
  };
}

/** The first [start, end) of a global RegExp or a long-value matcher at or after `from`, or null. */
export function nextSpan(re: RegExp | LongValueMatcher, text: string, from: number): Span | null {
  if (!(re instanceof RegExp)) return re.next(text, from);
  re.lastIndex = from;
  const m = re.exec(text);
  return m ? [m.index, m.index + m[0].length] : null;
}

/** The [start, end) spans a global replace with `re` visits, in text order. */
export function matchSpans(re: RegExp | LongValueMatcher, text: string): Span[] {
  const out: Span[] = [];
  for (let m = nextSpan(re, text, 0); m; m = nextSpan(re, text, Math.max(m[1], m[0] + 1))) out.push(m);
  return out;
}

const BOUNDARY = /[^\p{L}\p{N}_]/gu;
/**
 * True when one value can start inside another and run past its end (#3010, #3013): a part of A
 * that begins after a non-word character is a strict prefix of B (A and B may be the same value).
 * Compared in two lower-case foldings; a miss only keeps the plain pass that ran before.
 */
export function valuesCanOverlap(names: readonly string[]): boolean {
  for (const fold of [(n: string) => n.toLowerCase(), (n: string) => n.toUpperCase().toLowerCase()]) {
    const keys = [...new Set(names.map(fold))].sort();
    const startsLonger = (p: string) => {
      let lo = 0;
      let hi = keys.length;
      while (lo < hi) {
        const mid = (lo + hi) >> 1;
        if (keys[mid] < p) lo = mid + 1;
        else hi = mid;
      }
      return [keys[lo], keys[lo + 1]].some((k) => k !== undefined && k !== p && k.startsWith(p));
    };
    for (const a of keys)
      for (const m of a.matchAll(BOUNDARY))
        if (m.index + 1 < a.length && startsLonger(a.slice(m.index + 1))) return true;
  }
  return false;
}
