// Inline neutralisation of untrusted case text for the Markdown report: HTML-significant characters
// and link syntax. Split out of mdText.ts, which composes these into its line, cell and block helpers.

// A whole backslash run with the HTML-significant character (`<`, `>`, `&`) that may follow it.
const BACKSLASH_RUN_OR_HTML = /\\+[<>&]?|[<>&]/g;
// The `]` that closes link text, right before `(` (an inline link or image) or `:` (a reference
// definition, which would turn every matching `[label]` in the report into a link). An inline target
// that starts, as written, with an absolute http(s):// or mailto: scheme is left live — the same
// allow-list the HTML and DOCX exports apply (linkPolicy.ts). Judged on the literal characters, so
// an escaped, entity-encoded, spaced or bracketed scheme does not qualify and is broken.
const LINK_CLOSE = /\](?=\((?!(?:https?:\/\/|mailto:))|:)/gi;

/**
 * A backslash run directly before an escaped character is doubled first, so every original
 * backslash stays literal and the character itself is still escaped: `\<b>` must not become
 * `\\<b>`, an escaped backslash followed by a LIVE tag. A run before anything else is left alone.
 */
export function escapeRunBeforeChar(match: string): string {
  const last = match[match.length - 1];
  if (last === "\\") return match;
  const run = match.slice(0, -1);
  return `${run}${run}\\${last}`;
}

/**
 * `<`, `>` and `&` from case text, backslash-escaped. A Markdown viewer that renders raw HTML would
 * otherwise run an `<img onerror>` from a filename; `&lt;` in evidence is the four characters the
 * attacker typed, not a less-than sign. A backslash escape (not an entity) is used because it is the
 * form every CommonMark reader shows as the plain character, and marked hands the DOCX export an
 * escape token carrying that character — an entity would reach the DOCX as literal `&lt;`.
 */
export function escapeHtmlMd(value: string): string {
  return value.replace(BACKSLASH_RUN_OR_HTML, escapeRunBeforeChar);
}

/**
 * Indices of every `]` that closes an image's text (`![…]`) and is followed by `(`. Brackets nest as
 * in CommonMark; a bracket or `!` after an odd backslash run is literal and opens nothing.
 */
function imageTargetCloses(value: string): number[] {
  const stack: boolean[] = []; // one entry per open `[`: true when it opened an image
  const closes: number[] = [];
  for (let i = 0; i < value.length; i++) {
    const ch = value[i];
    if (ch === "\\") {
      i++; // the escaped character is literal
    } else if (ch === "[") {
      stack.push(i > 0 && value[i - 1] === "!" && !isEscapedAt(value, i - 1));
    } else if (ch === "]" && stack.length > 0) {
      if (stack.pop() && value[i + 1] === "(") closes.push(i);
    }
  }
  return closes;
}

/** True when the character at `at` follows an odd backslash run (so it is escaped). */
function isEscapedAt(value: string, at: number): boolean {
  let n = 0;
  for (let j = at - 1; j >= 0 && value[j] === "\\"; j--) n++;
  return n % 2 === 1;
}

/** Escapes the `(` after every image's closing `]`, whatever its target's scheme. */
function breakImageTargets(value: string): string {
  const closes = imageTargetCloses(value);
  if (closes.length === 0) return value;
  let out = "";
  let from = 0;
  for (const at of closes) {
    out += value.slice(from, at + 1) + "\\";
    from = at + 1;
  }
  return out + value.slice(from);
}

/**
 * Breaks Markdown link and image syntax: the character after a link-closing `]` is backslash-escaped,
 * so `[x](javascript:…)` and `[x]: javascript:…` render as the literal text and never as a link,
 * whatever the scheme is spelled as (only a literal http(s):// or mailto: target stays a link). An
 * IMAGE is broken whatever its scheme: a viewer loads `![x](https://…)` on open, a beacon that tells
 * the attacker who read the report. The escape renders as the plain character, so the reader sees
 * exactly what was written. Idempotent: an escaped `](` no longer matches.
 */
export function breakLinkSyntaxMd(value: string): string {
  return breakImageTargets(value).replace(LINK_CLOSE, "]\\");
}

/** Text outside any code span: HTML escaped, link syntax broken. */
function escapeProseText(text: string): string {
  return breakLinkSyntaxMd(escapeHtmlMd(text));
}

/** Every maximal backtick run on the line, by length → start offsets in order. */
function backtickRuns(line: string): Map<number, number[]> {
  const runs = new Map<number, number[]>();
  for (const m of line.matchAll(/`+/g)) {
    const list = runs.get(m[0].length) ?? [];
    list.push(m.index ?? 0);
    runs.set(m[0].length, list);
  }
  return runs;
}

/**
 * One line of prose made inert, with its code spans kept literal. A code span counts only when it
 * opens and closes on this line (CommonMark pairing: the next backtick run of the same length; a
 * backtick after an odd backslash run is literal). Every backtick run that is NOT paired here is
 * backslash-escaped, so a later line can never pair with it and turn text this pass escaped into
 * code, or code it kept into text. Everything outside the spans goes through escapeProseText.
 * Linear: each length's closer list is walked forward once.
 */
export function proseLineMd(line: string): string {
  const runs = backtickRuns(line);
  const cursor = new Map<number, number>();
  const closerAt = (from: number, n: number): number => {
    const list = runs.get(n) ?? [];
    let k = cursor.get(n) ?? 0;
    while (k < list.length && list[k] < from) k++;
    cursor.set(n, k);
    return k < list.length ? list[k] : -1;
  };
  let out = "";
  let text = "";
  let i = 0;
  while (i < line.length) {
    const ch = line[i];
    if (ch === "\\") {
      let j = i;
      while (line[j] === "\\") j++;
      // An odd run escapes the backtick right after it: that backtick is plain text.
      const end = (j - i) % 2 === 1 && line[j] === "`" ? j + 1 : j;
      text += line.slice(i, end);
      i = end;
    } else if (ch === "`") {
      let j = i;
      while (line[j] === "`") j++;
      const n = j - i;
      const close = closerAt(j, n);
      if (close < 0) text += "\\`".repeat(n);
      else {
        out += escapeProseText(text) + line.slice(i, close + n);
        text = "";
        j = close + n;
      }
      i = j;
    } else {
      text += ch;
      i++;
    }
  }
  return out + escapeProseText(text);
}
