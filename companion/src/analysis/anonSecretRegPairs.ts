import { isRegistryCredentialName } from "./anonSecretKeys.js";
import { isEncodedCue, readQuoted, type Span } from "./anonSecretValues.js";

// One-way redaction of a stored-credential registry value whose NAME and DATA sit in separate
// fields (#3021). The keyed pass sees `…\DefaultPassword=<pw>`, but importers write the pair apart:
//   Hayabusa:        TgtObj=…\Winlogon\DefaultPassword Details=<pw> Proc=…
//   Sysmon message:  TargetObject: …\Winlogon\DefaultPassword\nDetails: <pw>
//   Velociraptor:    Key=…\Winlogon - ValueName=DefaultPassword - ValueData=<pw> - Type=REG_SZ
//   reg query:       DefaultPassword    REG_SZ    <pw>
// The name test is the one #3017 applies after "\" (isRegistryCredentialName), so a security
// setting or persistence value (LimitBlankPasswordUse, UseLogonCredential, Run\PasswordManager)
// keeps its data visible. Only the data goes; the name and the fields around it stay.

// A field that names the value: a key path ending in "\<Name>", or the bare value name.
const ANCHOR_RE =
  /(?<![\w.-])(\\"|"|')?(TargetObject|TgtObj|ValueName|RegValueName|RegistryValueName)\1[ \t]*([:=])/gi;
const PATH_LABELS = new Set(["targetobject", "tgtobj"]);
// A field that holds the value's data.
const DATA_RE = /(?<![\w.-])(\\"|"|')?(Details|ValueData|RegStringValue|RegistryValueData)\1[ \t]*([:=])/gi;

// What ends a bare NAME value (a key path may hold spaces: `Windows NT`): a line break, the
// Hayabusa cell separator, the host suffix, or the next `Field=` / `Field: ` / ` - Field=` (the
// shape genericSysmonRegistry.ts reads keys with).
const FIELD_END = /\r|\n| ¦ | @ |[ \t]+(?:- )?[A-Za-z][A-Za-z0-9_]{0,63}(?:=|: )/;

// A bare DATA value is its first word, cut at a "|" or before a glued option (`x·-enc`), plus each
// following word joined by one space or tab that is a plain word with a letter in it: a password
// with single spaces stays whole. A word with `@ \ / : . =` or brackets is not taken (an address,
// account, path or `Field=`), nor an all-digit group (a card number's next block), nor a word
// starting `-` (an option, or the ` - ` separator). Hiding any of those here would break the
// entity, or stop the anonymizer from learning it, so its other parts or occurrences would go out
// in clear. When the value then ends in a digit, every following word that starts with a digit is
// taken whole, so a digit-group run (a card number) is hidden entirely rather than split.
const DATA_FIRST = /[^\s]+/y;
const GLUED_OPTION = /\||(?<=[^A-Za-z0-9])-(?=-?[A-Za-z])/;
const DATA_MORE = /[ \t](?![-¦])(?=[^\s]*[A-Za-z])[^\s@\\/:.=,;|'"<>(){}[\]¦]+(?=\s|$)/y;
const DIGIT_MORE = /[ \t]\d[^\s]*/y;

// Extend `end` while `re` matches right at it.
function extend(text: string, end: number, re: RegExp): number {
  let at = end;
  for (re.lastIndex = at; re.exec(text); re.lastIndex = at) at = re.lastIndex;
  return at;
}

function readBareData(text: string, at: number): number {
  DATA_FIRST.lastIndex = at;
  const first = DATA_FIRST.exec(text);
  if (!first) return at;
  const cut = GLUED_OPTION.exec(first[0]);
  if (cut) return at + cut.index;
  const end = extend(text, at + first[0].length, DATA_MORE);
  return /\d/.test(text[end - 1] ?? "") ? extend(text, end, DIGIT_MORE) : end;
}

// How far after the name the data field may start: one record, never the next event's fields.
const PAIR_WINDOW = 512;

interface FieldValue {
  span: Span;
  after: number;
}

function nameEnd(text: string, at: number): number {
  const rest = text.slice(at, at + 4096);
  const end = FIELD_END.exec(rest);
  return at + (end ? end.index : rest.length);
}

// The value of the field whose separator ends at `i`: quoted, or bare (a name up to FIELD_END, data
// by readBareData). An `=` followed by a space, or a `:` followed by a line break, is an empty field.
function readFieldValue(text: string, i: number, sep: string, data: boolean): FieldValue | null {
  let at = i;
  if (sep === "=") {
    if (text[at] === " " || text[at] === "\t") return null;
  } else {
    while (text[at] === " " || text[at] === "\t") at += 1;
  }
  const quoted = readQuoted(text, at);
  if (quoted) return quoted;
  const stop = data ? readBareData(text, at) : nameEnd(text, at);
  const value = text.slice(at, stop).trimEnd();
  return value ? { span: [at, at + value.length], after: stop } : null;
}

function valueName(label: string, value: string): string {
  if (!PATH_LABELS.has(label.toLowerCase())) return value.trim();
  const parts = value.trim().split(/[\\/]/);
  return parts[parts.length - 1] ?? "";
}

// Where the search for this name's data field stops: the next name field, the window, and a line
// break unless the record is the multi-line rendered message (`TargetObject: …` unquoted).
function pairLimit(text: string, from: number, quote: string | undefined, sep: string): number {
  let limit = Math.min(text.length, from + PAIR_WINDOW);
  const next = new RegExp(ANCHOR_RE.source, "gi");
  next.lastIndex = from;
  const n = next.exec(text);
  if (n && n.index < limit) limit = n.index;
  const multiLine = !quote && sep === ":";
  const stop = text.indexOf(multiLine ? "\n\n" : "\n", from);
  return stop !== -1 && stop < limit ? stop : limit;
}

function dataSpan(text: string, from: number, limit: number, placeholder: string): Span | null {
  const re = new RegExp(DATA_RE.source, "gi");
  re.lastIndex = from;
  const m = re.exec(text);
  if (!m || m.index >= limit) return null;
  const value = readFieldValue(text, re.lastIndex, m[3], true);
  if (!value || text.startsWith(placeholder, value.span[0])) return null;
  return value.span[1] > value.span[0] ? value.span : null;
}

// --- JSON records (#3031) ---------------------------------------------------------------------
// A `"`-quoted name field is a JSON member, and its object is the record: the data field may come
// before or after the name, but never from the next or previous object. The walks below are
// quote-aware (a `{` or `}` inside a string value does not count) and bounded by PAIR_WINDOW.

const escapedAt = (text: string, j: number): boolean => {
  let r = 0;
  while (text[j - 1 - r] === "\\") r += 1;
  return r % 2 === 1;
};

// Where the object holding position `from` closes, or `limit` when it does not close before it.
function objectEnd(text: string, from: number, limit: number): number {
  let inString = false;
  let depth = 0;
  for (let j = from; j < limit; j += 1) {
    const ch = text[j];
    if (ch === '"' && !escapedAt(text, j)) inString = !inString;
    else if (inString || (ch !== "{" && ch !== "}")) continue;
    else if (ch === "{") depth += 1;
    else if (depth === 0) return j;
    else depth -= 1;
  }
  return limit;
}

// Where the object holding position `at` (outside any string) opens, or -1 within the window.
function objectStart(text: string, at: number): number {
  const floor = Math.max(0, at - PAIR_WINDOW);
  let inString = false;
  let depth = 0;
  for (let j = at - 1; j >= floor && text[j] !== "\n"; j -= 1) {
    const ch = text[j];
    if (ch === '"' && !escapedAt(text, j)) inString = !inString;
    else if (inString || (ch !== "{" && ch !== "}")) continue;
    else if (ch === "}") depth += 1;
    else if (depth === 0) return j;
    else depth -= 1;
  }
  return -1;
}

// The positions in [start, end) that sit directly in the object opened at `start` (not inside a
// string or a nested object).
function topLevel(text: string, start: number, end: number): Uint8Array {
  const flags = new Uint8Array(end - start);
  let inString = false;
  let depth = 0;
  for (let j = start + 1; j < end; j += 1) {
    const ch = text[j];
    if (!inString && depth === 0) flags[j - start] = 1;
    if (ch === '"' && !escapedAt(text, j)) inString = !inString;
    else if (!inString && ch === "{") depth += 1;
    else if (!inString && ch === "}") depth -= 1;
  }
  return flags;
}

// The data field BEFORE a JSON name field at `at`, in the same object. When another name field sits
// earlier in the object, the data is that field's, so nothing is taken.
function dataBefore(text: string, at: number, placeholder: string): Span | null {
  const start = objectStart(text, at);
  if (start < 0) return null;
  const other = new RegExp(ANCHOR_RE.source, "gi");
  other.lastIndex = start;
  const o = other.exec(text);
  if (o && o.index < at) return null;
  const flags = topLevel(text, start, at);
  const re = new RegExp(DATA_RE.source, "gi");
  re.lastIndex = start;
  let found: Span | null = null;
  for (let m = re.exec(text); m && m.index < at; m = re.exec(text)) {
    if (m[1] !== '"' || !flags[m.index - start]) continue;
    const value = readFieldValue(text, re.lastIndex, m[3], true);
    if (value && value.span[1] <= at && value.span[1] > value.span[0]) found = value.span;
  }
  return found && !text.startsWith(placeholder, found[0]) ? found : null;
}

function pairedFieldSpans(text: string, placeholder: string): Span[] {
  const spans: Span[] = [];
  const re = new RegExp(ANCHOR_RE.source, "gi");
  for (let m = re.exec(text); m; m = re.exec(text)) {
    const name = readFieldValue(text, re.lastIndex, m[3], false);
    if (!name) continue;
    re.lastIndex = Math.max(re.lastIndex, name.after);
    if (!isRegistryCredentialName(valueName(m[2], text.slice(name.span[0], name.span[1])))) continue;
    const json = m[1] === '"';
    let limit = pairLimit(text, name.after, m[1], m[3]);
    if (json) limit = objectEnd(text, name.after, limit);
    const span =
      dataSpan(text, name.after, limit, placeholder) ??
      (json ? dataBefore(text, m.index, placeholder) : null);
    if (span) spans.push(span);
  }
  return spans;
}

// `reg query` output: `<Name>  REG_<TYPE>  <data>`, one value per line, or flattened onto one line.
const REG_QUERY_RE = /(?<![^\s"'])([A-Za-z][\w.-]{0,127})(?:[ \t]{2,}|\t)REG_[A-Z_]{2,24}(?:[ \t]{2,}|\t)/g;
// The data ends at the line end, or where the next flattened `<Name>  REG_` entry or key begins.
const REG_QUERY_DATA_END = /\r|\n|[ \t]{2,}(?=[^\s]{1,128}(?:[ \t]{2,}|\t)REG_[A-Z_]{2,24}\b|HKEY_)/;

function regQuerySpans(text: string, placeholder: string): Span[] {
  const spans: Span[] = [];
  const re = new RegExp(REG_QUERY_RE.source, "g");
  for (let m = re.exec(text); m; m = re.exec(text)) {
    if (!isRegistryCredentialName(m[1])) continue;
    const at = re.lastIndex;
    if (text.startsWith(placeholder, at)) continue;
    const rest = text.slice(at, at + 4096);
    const end = REG_QUERY_DATA_END.exec(rest);
    const value = rest.slice(0, end ? end.index : rest.length).trimEnd();
    if (value) spans.push([at, at + value.length]);
  }
  return spans;
}

// --- Commands that set the value (#3031) ------------------------------------------------------
//   reg add "HKLM\…\Winlogon" /v DefaultPassword /t REG_SZ /d <pw> /f
//   Set-ItemProperty -Path HKLM:\… -Name DefaultPassword -Value <pw>   (and New-ItemProperty)
// The command is read token by token, so a flag inside a quoted path is not a flag, `/ve` is not
// `/v`, and the flags may come in either order. It ends at a line break, a shell separator, or the
// closing quote when the command itself sits inside a quoted string (`cmd /c "reg add …"`, a JSON
// CommandLine field). The data is one token: quoted, or one word that stops at a quote or separator,
// so it never swallows a following `-enc <blob>` (#3005) or the next command.
interface CommandGrammar {
  start: RegExp;
  name: RegExp;
  data: RegExp;
  stops: string;
}
const REG_ADD: CommandGrammar = {
  start: /(?<![\w.-])reg(?:\.exe)?(?:\\?")?[ \t]+add(?=[ \t])/gi,
  name: /^[/-]v$/i,
  data: /^[/-]d$/i,
  stops: "&|<>",
};
const PS_SET_PROPERTY: CommandGrammar = {
  start: /(?<![\w.-])(?:Set|New)-ItemProperty(?=[ \t])/gi,
  name: /^-Name$/i,
  data: /^-Value$/i,
  stops: ";|",
};
const COMMAND_WINDOW = 1024;

interface Token {
  span: Span;
  after: number;
  quoted: boolean;
}

// An odd number of unescaped `"` before `at` on its line: the command sits inside a quoted string.
function insideQuotes(text: string, at: number): boolean {
  let odd = false;
  for (let j = at - 1; j >= Math.max(0, at - 4096) && text[j] !== "\n"; j -= 1)
    if (text[j] === '"' && !escapedAt(text, j)) odd = !odd;
  return odd;
}

function bareToken(text: string, at: number, end: number, stops: string): Token {
  let k = at;
  while (k < end && !/\s/.test(text[k]) && text[k] !== '"' && !stops.includes(text[k])) k += 1;
  // `pw\"` inside a JSON string: the backslash escapes the closing quote, it is not data.
  const stop = text[k] === '"' && escapedAt(text, k) ? k - 1 : k;
  return { span: [at, stop], after: stop, quoted: false };
}

function nextToken(text: string, i: number, end: number, nested: boolean, stops: string): Token | null {
  let at = i;
  while (at < end && (text[at] === " " || text[at] === "\t")) at += 1;
  if (at >= end || text[at] === "\r" || text[at] === "\n" || stops.includes(text[at])) return null;
  const escapedQuote = text.startsWith('\\"', at);
  // Inside `cmd /c "…"` a quote after a space that is followed by text opens a quoted argument
  // (`cmd /c "reg add "HKLM\…\Windows NT\…" /v …"`); any other bare quote closes the command.
  if (text[at] === '"' && nested && !(/\s/.test(text[at - 1] ?? "") && /[^\s"]/.test(text[at + 1] ?? "")))
    return null;
  if (escapedQuote || text[at] === '"' || text[at] === "'") {
    const q = readQuoted(text, at);
    if (!q) return null;
    // An unclosed quote would run to the line end and hide what follows (an address the anonymizer
    // must learn, an encoded command): take one word after the quote instead.
    const closed = q.after > q.span[1] || text[q.after] === '"';
    return closed ? { span: q.span, after: q.after, quoted: true } : bareToken(text, q.span[0], end, stops);
  }
  return bareToken(text, at, end, stops);
}

// A PowerShell `$variable` or `(subexpression)` is not the literal value.
const isLiteral = (value: string): boolean => value !== "" && !/^[$(@]/.test(value);

// The data stops before an encoded-command cue inside it (#3005): `-Value '… FromBase64String('`
// closes the quote at the cue's own `'`, and hiding the cue would send the blob after it in clear.
function beforeCue(text: string, span: Span): Span {
  for (let j = span[0] + 1; j < span[1]; j += 1) {
    if (!isEncodedCue(text, j)) continue;
    let end = j;
    while (end > span[0] && /\s/.test(text[end - 1])) end -= 1;
    return [span[0], end];
  }
  return span;
}

// A bare value ending in a digit takes each following digit-starting word, so a card number given
// as the data (`/d 4111 1111 …`) is hidden whole rather than split (#3021's rule for paired fields).
function withDigitRun(text: string, span: Span, end: number, stops: string): Span {
  let stop = span[1];
  while (/\d/.test(text[stop - 1] ?? "") && /[ \t]/.test(text[stop] ?? "") && /\d/.test(text[stop + 1] ?? ""))
    stop = bareToken(text, stop + 1, end, stops).span[1];
  return [span[0], stop];
}

function commandSpan(text: string, from: number, g: CommandGrammar): { span: Span | null; after: number } {
  const nested = insideQuotes(text, from);
  const end = Math.min(text.length, from + COMMAND_WINDOW);
  let name: string | null = null;
  let data: Span | null = null;
  let pending: "name" | "data" | null = null;
  let i = from;
  let t: Token | null = nextToken(text, i, end, nested, g.stops);
  while (t && t.after > i) {
    i = t.after;
    const value = text.slice(t.span[0], t.span[1]);
    if (pending === "name") name ??= value;
    else if (pending === "data")
      data ??= beforeCue(text, t.quoted ? t.span : withDigitRun(text, t.span, end, g.stops));
    const flag: boolean = pending === null && !t.quoted;
    pending = flag && g.name.test(value) ? "name" : flag && g.data.test(value) ? "data" : null;
    t = nextToken(text, i, end, nested, g.stops);
  }
  const ok = name !== null && data !== null && isRegistryCredentialName(name);
  return { span: ok && data && isLiteral(text.slice(data[0], data[1])) ? data : null, after: i };
}

function commandSpans(text: string, placeholder: string): Span[] {
  const spans: Span[] = [];
  for (const g of [REG_ADD, PS_SET_PROPERTY]) {
    const re = new RegExp(g.start.source, "gi");
    for (let m = re.exec(text); m; m = re.exec(text)) {
      const { span, after } = commandSpan(text, re.lastIndex, g);
      re.lastIndex = Math.max(re.lastIndex, after);
      if (span && !text.startsWith(placeholder, span[0])) spans.push(span);
    }
  }
  return spans;
}

/** Redact the data of a stored-credential registry value written as separate name and data fields. */
export function redactRegistryCredentialPairs(text: string, placeholder: string): string {
  const spans = [
    ...pairedFieldSpans(text, placeholder),
    ...regQuerySpans(text, placeholder),
    ...commandSpans(text, placeholder),
  ]
    .sort((a, b) => a[0] - b[0])
    .filter((s, i, all) => i === 0 || s[0] >= all[i - 1][1]);
  if (!spans.length) return text;
  let out = "";
  let last = 0;
  for (const [s, e] of spans) {
    out += text.slice(last, s) + placeholder;
    last = e;
  }
  return out + text.slice(last);
}
