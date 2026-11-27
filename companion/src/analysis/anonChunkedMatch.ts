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
