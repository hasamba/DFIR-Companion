// Bounded search over analyst-pasted text. Pure and streaming: one pass over the
// string by line offsets, no array of all lines, no regex built from model input.

export const WATSON_PASTE_MAX_BYTES = 50 * 1024 * 1024;

const DEFAULT_MAX_LINES = 200;
const DEFAULT_CONTEXT = 1;
const EXCERPT_MAX_CHARS = 24000;

export interface PasteSearchResult {
  excerpt: string;
  matchedLines: number;
  truncated: boolean;
}

interface Span {
  n: number;
  start: number;
  end: number;
}

export function searchPaste(
  text: string,
  terms: readonly string[],
  opts: { maxLines?: number; context?: number } = {},
): PasteSearchResult {
  const needles = terms.map((t) => t.toLowerCase()).filter((t) => t.length > 0);
  if (needles.length === 0 || text.length === 0) {
    return { excerpt: "", matchedLines: 0, truncated: false };
  }
  const maxLines = Math.max(1, Math.floor(opts.maxLines ?? DEFAULT_MAX_LINES));
  const context = Math.max(0, Math.floor(opts.context ?? DEFAULT_CONTEXT));

  const out: string[] = [];
  let chars = 0;
  let closed = false; // line or char cap reached
  let truncated = false;
  let matchedLines = 0;
  let afterLeft = 0;
  const before: Span[] = []; // sliding window of unemitted preceding lines

  const emit = (s: Span): void => {
    if (closed) {
      truncated = true;
      return;
    }
    const row = `${s.n}: ${text.slice(s.start, s.end)}`;
    if (out.length >= maxLines || chars + row.length + 1 > EXCERPT_MAX_CHARS) {
      closed = true;
      truncated = true;
      return;
    }
    out.push(row);
    chars += row.length + 1;
  };

  let pos = 0;
  let n = 0;
  while (pos <= text.length) {
    let end = text.indexOf("\n", pos);
    if (end === -1) end = text.length;
    n++;
    const span: Span = { n, start: pos, end };
    const lower = text.slice(pos, end).toLowerCase();
    if (needles.some((t) => lower.includes(t))) {
      matchedLines++;
      if (!closed) {
        for (const b of before) emit(b);
        emit(span);
      } else {
        truncated = true;
      }
      before.length = 0;
      afterLeft = context;
    } else if (afterLeft > 0) {
      emit(span);
      afterLeft--;
    } else if (context > 0) {
      before.push(span);
      if (before.length > context) before.shift();
    }
    pos = end + 1;
  }
  return { excerpt: out.join("\n"), matchedLines, truncated };
}

export function pasteHead(text: string, maxChars = 6000): string {
  if (text.length <= maxChars) return text;
  const cut = text.lastIndexOf("\n", maxChars);
  // Whole lines when possible; a single over-long first line is cut hard.
  if (cut > 0 && text[maxChars] === "\n") return text.slice(0, maxChars);
  return cut > 0 ? text.slice(0, cut) : text.slice(0, maxChars);
}
