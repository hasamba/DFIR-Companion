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
// JSON-escaped `\n` / `\r\n`. The terminator is the same quote + `@` at the start of a line. A value
// written right after a tab (`@'\t<pw>\n'@`, raw or JSON-escaped) is read to that terminator too (#3063).
const HERE_OPEN = /@(\\"|"|')(?:[ \t]|\\t)*(\r?\n|(?:\\r)?\\n|(?<=\t|\\t))/y;
// A here-string may run past the command window: its terminator is searched this far from the opener
// (#3057). The terminators of a text are listed once per form and found by binary search, so many
// openers stay linear.
const HERE_WINDOW = 16384;
let closeCache: { text: string; lists: Map<string, number[]> } | null = null;

function firstClose(text: string, close: string, from: number): number {
  if (closeCache?.text !== text) closeCache = { text, lists: new Map() };
  let list = closeCache.lists.get(close);
  if (!list) {
    list = [];
    for (let k = text.indexOf(close); k >= 0; k = text.indexOf(close, k + 1)) list.push(k);
    closeCache.lists.set(close, list);
  }
  let lo = 0;
  let hi = list.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (list[mid] < from) lo = mid + 1;
    else hi = mid;
  }
  return lo < list.length ? list[lo] : -1;
}

/**
 * A here-string opened at `at` within `end` (#3051): its content between the opener's line break and
 * the terminator's (within HERE_WINDOW), and the index after the terminator. An unterminated one (a
 * truncated log) gives its first content line within `end`, so the value is hidden without swallowing
 * the rest of the script.
 */
export function readHereString(text: string, at: number, end: number): QuotedValue | null {
  HERE_OPEN.lastIndex = at;
  const m = HERE_OPEN.exec(text);
  if (!m || HERE_OPEN.lastIndex > end) return null;
  const start = HERE_OPEN.lastIndex;
  const nl = m[2].startsWith("\\") || (m[2] === "" && m[0].endsWith("\\t")) ? "\\n" : "\n";
  const cr = nl === "\n" ? "\r" : "\\r";
  const close = nl + m[1] + "@";
  // From the opener's own line break, so an empty here-string closes at once.
  const found = firstClose(text, close, start - nl.length);
  const within = found >= 0 && found + close.length <= Math.min(text.length, at + HERE_WINDOW);
  const k = within ? found - (start - nl.length) : -1;
  const lineEnd = k < 0 ? text.slice(start, end).indexOf(nl) : -1;
  let stop = k >= 0 ? start - nl.length + k : start + (lineEnd < 0 ? end - start : lineEnd);
  if (text.startsWith(cr, stop - cr.length)) stop -= cr.length;
  if (stop <= start) return null;
  return { span: [start, stop], after: k >= 0 ? start - nl.length + k + close.length : stop };
}

/**
 * A quoted value walked with `''` only (`span`, opened at `open`), widened across its `""` / backtick
 * escapes when the widened value still ends inside its call or hashtable (`ends` after it, within
 * `limit`); the walked span otherwise.
 */
export function widen(
  text: string,
  open: number,
  span: Span,
  mode: QuoteMode,
  ends: string,
  limit: number,
): Span {
  const q = readValueQuoted(text, open, mode);
  if (!q || q.span[0] !== span[0] || q.span[1] <= span[1] || q.span[1] > limit) return span;
  let k = q.after;
  while (text[k] === " " || text[k] === "\t") k += 1;
  return ends.includes(text[k] ?? "") ? q.span : span;
}

// --- Concatenated literals (#3057) -------------------------------------------------------------
// `'Hunt' + 'er2…'` in expression mode (an assignment, a method argument, a hashtable value) is one
// value: after a closed literal that ends at `after`, every following `+ '<literal>'` is taken, and
// a `+ $name` operand is passed over. Any other operand ends the run, so an encoded-command
// expression (`+ [Convert]::FromBase64String(…)`) is never hidden. Returns where the last literal's
// content ends and the index after it, or null when no literal follows.
const CONCAT_PLUS = /[ \t]*\+[ \t]*/y;
const CONCAT_VAR = /\$[A-Za-z_][\w:]{0,63}(?![\w.[({])/y;

export function concatEnd(text: string, after: number, end: number): QuotedValue | null {
  let stop = -1;
  let next = after;
  for (let at = after; ;) {
    CONCAT_PLUS.lastIndex = at;
    if (!CONCAT_PLUS.test(text)) break;
    const k = CONCAT_PLUS.lastIndex;
    CONCAT_VAR.lastIndex = k;
    if (CONCAT_VAR.test(text)) {
      at = CONCAT_VAR.lastIndex;
      continue;
    }
    if (text[k] !== "'" && text[k] !== '"' && !text.startsWith('\\"', k)) break;
    const q = readValueQuoted(text, k, { escapes: false });
    if (!q || q.after <= q.span[1] || q.after > end) break;
    stop = q.span[1];
    next = q.after;
    at = q.after;
  }
  return stop < 0 ? null : { span: [after, stop], after: next };
}

// --- cmd-doubled quotes (#3054) ----------------------------------------------------------------
// Inside an outer `"…"` (`powershell -c "sp ""K"" DefaultPassword ""v"""`), cmd writes a quote as
// `""` (`\"\"` in a JSON string). An argument opened by one after a space runs to the next one on
// the line, and only when that close is followed by a space, the outer quote, a separator or the
// end, so a malformed close never moves where the command's next token starts.
const DOUBLED_CLOSE_NEXT = /^(?:[ \t\r\n;|&]|\\"|"|\\[nrt]|$)/;

export function readDoubled(text: string, at: number, end: number): QuotedValue | null {
  const pair = text.startsWith('\\"\\"', at) ? '\\"\\"' : text.startsWith('""', at) ? '""' : null;
  if (!pair || !/[ \t]/.test(text[at - 1] ?? "")) return null;
  const start = at + pair.length;
  if (start >= end || /[\s"\\]/.test(text[start])) return null;
  const k = text.slice(start, end).indexOf(pair);
  if (k < 0) return null;
  const stop = start + k;
  const content = text.slice(start, stop);
  if (content.includes('"') || content.includes("\n")) return null;
  const after = stop + pair.length;
  return DOUBLED_CLOSE_NEXT.test(text.slice(after, after + 2)) ? { span: [start, stop], after } : null;
}

// --- Backtick escapes in a value name (#3054) --------------------------------------------------
// `"Default`Password"` is DefaultPassword to PowerShell, and so is the name the walk reads from
// `"DefaultPassword`"`. A backtick before a special escape (`n, `t, `0 …) makes another character,
// so it is kept there. A single-quoted name keeps its backticks.
const ESCAPE_BACKTICK = /`([^0abefnrtuv]|$)/g;

/** The value name in `span` as PowerShell reads it, for the credential-name test only. */
export function psNameText(text: string, span: Span, ps: boolean): string {
  const name = text.slice(span[0], span[1]);
  return ps && text[span[0] - 1] !== "'" ? name.replace(ESCAPE_BACKTICK, "$1") : name;
}

// --- Variable flow (#3054) ---------------------------------------------------------------------
//   $v = @'⏎<pw>⏎'@; Set-ItemProperty <key> DefaultPassword $v
// A whole `$name` (`${name}`, or a script:/global:/local:/private: scope) passed as the value of a
// credential name is followed to the nearest `$name = <literal>` before it, case-insensitively, when
// that literal ends within VAR_WINDOW of the use (a long here-string still counts, #3057). Only that assignment counts: when it is not a literal, nothing is taken. A
// property, index or `$env:` reference is never followed. The assignments are listed in one pass,
// only once a use is seen, and each literal is read once within its own window.
const VAR_NAME = String.raw`\$(?:\{([A-Za-z_]\w{0,63})\}|(?:(?:script|global|local|private):)?([A-Za-z_]\w{0,63}))`;
const VAR_REF = new RegExp(String.raw`${VAR_NAME}(?![\w.[:({])`, "iy");
const VAR_ASSIGN = new RegExp(String.raw`(?<=^|[\s;{("\]]|\\[nrt])${VAR_NAME}[ \t]*=(?!=)[ \t]*`, "gi");
const VAR_WINDOW = 4096;
const LITERAL_WINDOW = 1024;
const BARE_NUMBER = /\d{1,64}(?=[\s;|)}]|\\[nrt]|$)/y;

export const PS_QUOTE_PATTERNS: readonly RegExp[] = [
  HERE_OPEN,
  DOUBLED_CLOSE_NEXT,
  ESCAPE_BACKTICK,
  VAR_REF,
  VAR_ASSIGN,
  BARE_NUMBER,
  CONCAT_PLUS,
  CONCAT_VAR,
];

// The literal assigned at `at` (the index after `=`): a here-string, a closed quoted value (widened
// across its escapes when it then ends the statement), or a bare number; null for anything else.
function assignedLiteral(text: string, at: number): Span | null {
  const end = Math.min(text.length, at + LITERAL_WINDOW);
  if (text[at] === "@") return readHereString(text, at, end)?.span ?? null;
  if (text[at] === "'" || text[at] === '"' || text.startsWith('\\"', at)) {
    const view = text.slice(0, end);
    const q = readValueQuoted(view, at, { escapes: false });
    if (!q || q.after <= q.span[1]) return null;
    const span = widen(view, at, q.span, { ps: true }, ";})|\r\n\\", end);
    const more = span[1] === q.span[1] ? concatEnd(view, q.after, end) : null;
    return more ? [span[0], more.span[1]] : span;
  }
  BARE_NUMBER.lastIndex = at;
  const m = BARE_NUMBER.exec(text);
  return m ? [at, at + m[0].length] : null;
}

// Each assigned name mapped to the value starts of its assignments, in text order.
function assignments(text: string): Map<string, number[]> {
  const byName = new Map<string, number[]>();
  for (const m of text.matchAll(VAR_ASSIGN)) {
    const name = (m[1] ?? m[2]).toLowerCase();
    const list = byName.get(name) ?? [];
    // Built in place: copying the list per assignment would be quadratic in their number.
    list.push(m.index + m[0].length);
    byName.set(name, list);
  }
  return byName;
}

/** Resolves a variable passed as a credential value to the literal assigned to it (see above). */
export interface PsVariables {
  literal(at: number): Span | null;
}

/** `cut` is applied once to each literal found (the caller's cue cut). */
export function psVariables(text: string, cut: (span: Span) => Span = (span) => span): PsVariables {
  let byName: Map<string, number[]> | null = null;
  const read = new Map<number, Span | null>();
  const literalAt = (value: number): Span | null => {
    if (!read.has(value)) {
      const span = assignedLiteral(text, value);
      read.set(value, span && cut(span));
    }
    return read.get(value) ?? null;
  };
  return {
    literal(at: number): Span | null {
      VAR_REF.lastIndex = at;
      const ref = VAR_REF.exec(text);
      if (!ref) return null;
      const name = (ref[1] ?? ref[2]).toLowerCase();
      byName ??= assignments(text);
      // The last assignment to this name whose `=` ends before the use.
      const list = byName.get(name) ?? [];
      let lo = 0;
      let hi = list.length;
      while (lo < hi) {
        const mid = (lo + hi) >> 1;
        if (list[mid] <= at) lo = mid + 1;
        else hi = mid;
      }
      if (lo === 0) return null;
      const span = literalAt(list[lo - 1]);
      return span && span[1] <= at && at - span[1] <= VAR_WINDOW ? span : null;
    },
  };
}
