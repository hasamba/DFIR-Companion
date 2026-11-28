import { readQuoted, type Span } from "./anonSecretValues.js";

// PowerShell quoting for the registry command reader (anonSecretRegPairs.ts): the escapes that keep
// a quoted value open, and here-strings. Every reader walks forward once and is bounded by the
// caller's window, so the registry pass stays linear on attacker-influenced case text.

export interface QuotedValue {
  span: Span;
  after: number;
}

/** How a quoted value is read: `ps` allows the backtick escape (PowerShell grammars only, never
 *  `reg add` or a C# call); `nested` means the command sits inside an outer `"…"` string. */
export interface QuoteMode {
  ps?: boolean;
  nested?: boolean;
  /** false: only the `''` escape (#3047), as a command is walked token by token. */
  escapes?: boolean;
}

function oddBackticks(text: string, at: number, floor: number): boolean {
  let r = 0;
  while (at - 1 - r >= floor && text[at - 1 - r] === "`") r += 1;
  return r % 2 === 1;
}

// Where the value goes on after the quote that closed it at `stop` (`after` is past that quote), or -1.
//   'a''b'      a single-quoted string doubles a quote to escape it (#3047)
//   "a""b"      a double-quoted one does too, except inside an outer quoted string, where `""` is
//               that string's own closing quote (`cmd /c "… /d "pw""`); the JSON form `\"\"` always
//   "a`"b"      a backtick escapes the quote after it (PowerShell only; `` a`` `` is a backtick)
function continuation(
  text: string,
  open: string,
  start: number,
  stop: number,
  after: number,
  mode: QuoteMode,
) {
  if (open === "'") return text[after] === "'" ? after : -1;
  if (mode.escapes === false) return -1;
  if (open === '"' ? text[after] === '"' && !mode.nested : text.startsWith('\\"', after)) return after;
  return mode.ps && oddBackticks(text, stop, start) ? stop : -1;
}

/**
 * A quoted value at `at` read across its escapes (#3047, #3051). A continuation that does not close is
 * not taken, so the closed part before it stays the value. Returns readQuoted's result otherwise.
 */
export function readValueQuoted(text: string, at: number, mode: QuoteMode = {}): QuotedValue | null {
  const q = readQuoted(text, at);
  if (!q || q.after <= q.span[1]) return q;
  const open = text.startsWith('\\"', at) ? '\\"' : text[at];
  let after = q.after;
  let stop = q.span[1];
  for (let from = continuation(text, open, q.span[0], stop, after, mode); from >= 0;) {
    const next = readQuoted(text, from);
    if (!next || next.after <= next.span[1]) break;
    after = next.after;
    stop = next.span[1];
    from = continuation(text, open, q.span[0], stop, after, mode);
  }
  return { span: [q.span[0], stop], after };
}

// A here-string opener: `@'` / `@"` (or the JSON-escaped `@\"`), then the line break, raw or the
// JSON-escaped `\n` / `\r\n`. The terminator is the same quote + `@` at the start of a line.
const HERE_OPEN = /@(\\"|"|')[ \t]*(\r?\n|(?:\\r)?\\n)/y;
export const PS_QUOTE_PATTERNS: readonly RegExp[] = [HERE_OPEN];

/**
 * A here-string at `at` within `end` (#3051): its content between the opener's line break and the
 * terminator's, and the index after the terminator. An unterminated one (a truncated log) gives its
 * first content line, so the value is hidden without swallowing the rest of the script.
 */
export function readHereString(text: string, at: number, end: number): QuotedValue | null {
  HERE_OPEN.lastIndex = at;
  const m = HERE_OPEN.exec(text);
  if (!m || HERE_OPEN.lastIndex > end) return null;
  const start = HERE_OPEN.lastIndex;
  const nl = m[2].startsWith("\\") ? "\\n" : "\n";
  const cr = nl === "\n" ? "\r" : "\\r";
  const close = nl + m[1] + "@";
  // From the opener's own line break, so an empty here-string closes at once.
  const k = text.slice(start - nl.length, end).indexOf(close);
  const lineEnd = k < 0 ? text.slice(start, end).indexOf(nl) : -1;
  let stop = k >= 0 ? start - nl.length + k : start + (lineEnd < 0 ? end - start : lineEnd);
  if (text.startsWith(cr, stop - cr.length)) stop -= cr.length;
  if (stop <= start) return null;
  return { span: [start, stop], after: k >= 0 ? start - nl.length + k + close.length : stop };
}
