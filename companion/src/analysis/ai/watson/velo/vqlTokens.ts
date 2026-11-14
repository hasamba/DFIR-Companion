// A small VQL tokenizer for Watson's launch allowlist (vqlAllowed.ts). It exists so the safety
// check reads VQL the way Velociraptor's lexer does: a call inside a string or a comment is not a
// call, and a call after a closing `*/` is. It FAILS CLOSED: anything it cannot read with certainty
// (an unterminated string or comment, a backtick, a non-ASCII or control character outside a
// string, a quoted string whose end depends on whether backslashes escape) is an error, and the
// caller blocks the VQL.
//
// Comments: `--` and `//` to end of line, `/* … */` (not nested — the first `*/` closes).
// Strings: '''…''' (raw, no escapes), '…' and "…" (backslash escapes).

export type VqlTokenKind = "ident" | "number" | "string" | "punct";

export interface VqlToken {
  kind: VqlTokenKind;
  /** The source text of the token (a string token keeps its quotes). */
  text: string;
  /** For a string token: the decoded contents. */
  value?: string;
  start: number;
  end: number;
}

export type VqlTokenResult = { ok: true; tokens: VqlToken[] } | { ok: false; reason: string };

const TRIPLE = "'''";
const IDENT_START = /[A-Za-z_]/;
const IDENT_PART = /[A-Za-z0-9_]/;
const NUMBER = /^(?:0[xX][0-9a-fA-F]+|[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/;
const MULTI_PUNCT = ["<=", ">=", "!=", "=~", "==", "=>"];
const ALLOWED_WS = new Set(["\t", "\n", "\r", " "]);

class TokenError extends Error {}

/** Is this character something the tokenizer refuses outside a string literal? */
function badChar(c: string): string | null {
  const code = c.charCodeAt(0);
  if (code > 0x7e) return "non-ASCII character outside a string literal";
  if (code < 0x20 && !ALLOWED_WS.has(c)) return "control character in the VQL";
  if (c === "`") return "backtick-quoted name";
  return null;
}

/** Index just past a quoted string starting at `start`, reading backslashes as escapes or not. */
function quotedEnd(src: string, start: number, escapes: boolean): number {
  const q = src[start];
  for (let i = start + 1; i < src.length; i++) {
    if (escapes && src[i] === "\\") {
      i++;
      continue;
    }
    if (src[i] === q) return i + 1;
  }
  return -1;
}

const ESCAPES: Record<string, string> = { n: "\n", t: "\t", r: "\r" };

function decodeEscaped(body: string): string {
  return body.replace(/\\(.)/gs, (_m, ch: string) => ESCAPES[ch] ?? ch);
}

function readString(src: string, start: number): VqlToken {
  if (src.startsWith(TRIPLE, start)) {
    const close = src.indexOf(TRIPLE, start + TRIPLE.length);
    if (close < 0) throw new TokenError("unterminated ''' string");
    const end = close + TRIPLE.length;
    return { kind: "string", text: src.slice(start, end), value: src.slice(start + 3, close), start, end };
  }
  const escaped = quotedEnd(src, start, true);
  const raw = quotedEnd(src, start, false);
  if (escaped < 0 || raw < 0) throw new TokenError("unterminated string literal");
  if (escaped !== raw) throw new TokenError("a string literal whose end depends on backslash escapes");
  const text = src.slice(start, escaped);
  return { kind: "string", text, value: decodeEscaped(text.slice(1, -1)), start, end: escaped };
}

/** Index past a comment starting at `i`, or -1 when no comment starts there. Checks the comment's characters. */
function skipComment(src: string, i: number): number {
  let end = -1;
  if (src.startsWith("--", i) || src.startsWith("//", i)) {
    const nl = src.indexOf("\n", i);
    end = nl < 0 ? src.length : nl + 1;
  } else if (src.startsWith("/*", i)) {
    const close = src.indexOf("*/", i + 2);
    if (close < 0) throw new TokenError("unterminated /* comment");
    end = close + 2;
  }
  if (end < 0) return -1;
  for (let k = i; k < end; k++) {
    const c = src[k];
    if (c === "`") continue; // a backtick in a comment is just text
    const bad = badChar(c);
    if (bad) throw new TokenError(bad.replace("outside a string literal", "in a comment"));
  }
  return end;
}

function readIdent(src: string, start: number): VqlToken {
  let i = start + 1;
  while (i < src.length && IDENT_PART.test(src[i])) i++;
  return { kind: "ident", text: src.slice(start, i), start, end: i };
}

function readPunct(src: string, start: number): VqlToken {
  const two = src.slice(start, start + 2);
  const text = MULTI_PUNCT.includes(two) ? two : src[start];
  return { kind: "punct", text, start, end: start + text.length };
}

function nextToken(src: string, i: number): VqlToken {
  const c = src[i];
  if (c === "'" || c === '"') return readString(src, i);
  if (IDENT_START.test(c)) return readIdent(src, i);
  const num = NUMBER.exec(src.slice(i, i + 64));
  if (num) return { kind: "number", text: num[0], start: i, end: i + num[0].length };
  const bad = badChar(c);
  if (bad) throw new TokenError(bad);
  return readPunct(src, i);
}

/** Tokenize VQL, skipping whitespace and comments. Any doubt is an error. */
export function tokenizeVql(src: string): VqlTokenResult {
  const tokens: VqlToken[] = [];
  try {
    let i = 0;
    while (i < src.length) {
      if (ALLOWED_WS.has(src[i])) {
        i++;
        continue;
      }
      const afterComment = skipComment(src, i);
      if (afterComment >= 0) {
        i = afterComment;
        continue;
      }
      const tok = nextToken(src, i);
      tokens.push(tok);
      i = tok.end;
    }
  } catch (err) {
    if (err instanceof TokenError) return { ok: false, reason: err.message };
    throw err;
  }
  return { ok: true, tokens };
}
