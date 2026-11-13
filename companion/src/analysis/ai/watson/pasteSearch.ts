// Bounded search over analyst-pasted text. Pure and streaming: one pass over the
// string by line offsets, no array of all lines, no regex built from model input.

export const WATSON_PASTE_MAX_BYTES = 50 * 1024 * 1024;

const DEFAULT_MAX_LINES = 200;
const DEFAULT_CONTEXT = 1;
const EXCERPT_MAX_CHARS = 24000;
const LINE_MAX_CHARS = 2000;
const CLIP_MARK = " …[clipped]";

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
  const needles = terms.map((t) => t.trim().toLowerCase()).filter((t) => t.length > 0);
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
    let body = text.slice(s.start, s.end);
    if (body.length > LINE_MAX_CHARS) {
      body = body.slice(0, LINE_MAX_CHARS) + CLIP_MARK;
      truncated = true;
    }
    const row = `${s.n}: ${body}`;
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
  while (pos < text.length) {
    let end = text.indexOf("\n", pos);
    if (end === -1) end = text.length;
    n++;
    const contentEnd = end > pos && text[end - 1] === "\r" ? end - 1 : end;
    const span: Span = { n, start: pos, end: contentEnd };
    const lower = text.slice(pos, contentEnd).toLowerCase();
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
  const out: string[] = [];
  let used = 0;
  let pos = 0;
  let n = 0;
  while (pos < text.length) {
    let end = text.indexOf("\n", pos);
    if (end === -1) end = text.length;
    n++;
    const contentEnd = end > pos && text[end - 1] === "\r" ? end - 1 : end;
    const row = `${n}: ${text.slice(pos, Math.min(contentEnd, pos + maxChars))}`;
    const cost = row.length + (out.length > 0 ? 1 : 0);
    if (used + cost > maxChars) {
      if (out.length === 0) out.push(row.slice(0, maxChars)); // one over-long first line
      break;
    }
    out.push(row);
    used += cost;
    pos = end + 1;
  }
  return out.join("\n");
}
