// Value parsing for the keyed one-way secret pass (anonSecretKeys.ts). Hand-written rather than a
// regex: a quoted value with backslash escapes is exactly the shape where overlapping regex
// alternatives backtrack catastrophically, and case text is attacker-influenced. Every scan here
// walks forward once, so the whole pass stays linear.

/** A half-open [start, end) range of text to replace with the secret placeholder. The optional
 *  flag marks a BARE (unquoted) value, which needs a quoted placeholder when it sits in JSON. */
export type Span = [number, number, boolean?];

// Unquoted values in an assignment never carry a secret when they are one of these words. Only a
// BARE value is checked: a quoted "none" can be a real password, so it is always redacted.
const FLAG_VALUE = /^(?:true|false|null|none|yes|no|on|off|-)$/i;

// A bare value ends at whitespace or at the punctuation that closes it in JSON, a query string, a
// key=value log line or a Python repr.
const BARE_STOP = new Set([",", ";", "}", "]", ")", "&", "<", ">", '"', "'"]);
// On a command line, a bare value also ends at shell punctuation.
const SHELL_STOP = new Set([";", "|", "&", ")", "<", ">", '"', "'"]);

function isSpace(ch: string): boolean {
  return ch === " " || ch === "\t" || ch === "\n" || ch === "\r";
}

function lineEnd(text: string, from: number): number {
  const nl = text.indexOf("\n", from);
  return nl === -1 ? text.length : nl;
}

function backslashesBefore(text: string, at: number, floor: number): number {
  let r = 0;
  while (at - 1 - r >= floor && text[at - 1 - r] === "\\") r += 1;
  return r;
}

/**
 * A quoted value starting at `i`: `"…"`, `'…'`, or the escaped `\"…\"` of JSON nested inside a
 * JSON string. Returns the content span and the index after the closing quote, or null when `i`
 * does not open a quoted value. An unterminated value runs to the end of the line, so a truncated
 * log line still loses its whole secret rather than keeping the tail.
 */
export function readQuoted(text: string, i: number): { span: Span; after: number } | null {
  const escaped = text.startsWith('\\"', i);
  const q = escaped ? '"' : text[i];
  if (!escaped && q !== '"' && q !== "'") return null;
  const start = i + (escaped ? 2 : 1);
  for (let j = start; j < text.length && text[j] !== "\n"; j += 1) {
    if (text[j] !== q) continue;
    const r = backslashesBefore(text, j, start);
    if (!escaped) {
      if (r % 2 === 0) return { span: [start, j], after: j + 1 };
      continue;
    }
    // Inside an escaped string the outer layer turns r backslashes + quote into floor(r/2)
    // backslashes + quote (r odd). The inner value ends when that inner quote is unescaped. An
    // even r is the OUTER string's own closing quote, which ends the value too.
    if (r % 2 === 0) return { span: [start, j - r], after: j - r };
    if (((r - 1) / 2) % 2 === 0) return { span: [start, j - 1], after: j + 1 };
  }
  const end = lineEnd(text, start);
  return { span: [start, end], after: end };
}

/** A bare (unquoted) value starting at `i`, or null when it is empty. */
export function readBare(text: string, i: number, shell = false): Span | null {
  const stop = shell ? SHELL_STOP : BARE_STOP;
  let j = i;
  while (j < text.length && !isSpace(text[j]) && !stop.has(text[j])) j += 1;
  return j > i ? [i, j] : null;
}

export function isFlagValue(text: string, span: Span): boolean {
  return FLAG_VALUE.test(text.slice(span[0], span[1]));
}

export function skipSpaces(text: string, i: number): number {
  let j = i;
  while (j < text.length && (text[j] === " " || text[j] === "\t")) j += 1;
  return j;
}

function skipBlank(text: string, i: number): number {
  let j = i;
  while (j < text.length && isSpace(text[j])) j += 1;
  return j;
}

/**
 * Every scalar VALUE inside the array that starts at `i` (a `[`) under a secret-named key,
 * including values inside nested arrays and objects (object keys are kept). Multi-line
 * (pretty-printed) arrays are walked too. The walk stops when the array closes or when the text
 * stops looking like an array — a scalar not followed by `,` `:` or a closing bracket — so a
 * truncated `tokens: [abc` cannot swallow the log lines after it. Forward-only: linear.
 */
export function readSecretArray(text: string, i: number): { spans: Span[]; after: number } {
  const spans: Span[] = [];
  const stack: string[] = [];
  let j = i;
  let expectKey = false;
  let needSep = false;
  while (j < text.length) {
    j = skipBlank(text, j);
    const ch = text[j];
    if (ch === "[" || ch === "{") {
      if (needSep) break;
      stack.push(ch);
      expectKey = ch === "{";
      j += 1;
      continue;
    }
    if (ch === "]" || ch === "}") {
      stack.pop();
      j += 1;
      if (!stack.length) return { spans, after: j };
      expectKey = false;
      needSep = true;
      continue;
    }
    if (ch === "," || ch === ":") {
      expectKey = ch === "," && stack[stack.length - 1] === "{";
      needSep = false;
      j += 1;
      continue;
    }
    if (needSep || ch === undefined) break;
    const quoted = readQuoted(text, j);
    const span = quoted ? quoted.span : readBare(text, j);
    if (!span) break;
    if (!expectKey && (quoted || !isFlagValue(text, span)))
      spans.push(quoted ? span : [span[0], span[1], true]);
    j = quoted ? quoted.after : span[1];
    needSep = true;
  }
  return { spans, after: j };
}
