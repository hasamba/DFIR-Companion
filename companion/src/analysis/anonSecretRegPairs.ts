import { isRegistryCredentialName } from "./anonSecretKeys.js";
import { commandSpans, objectEnd, quoteAt, quoteLevel, readQuotedField } from "./anonSecretRegCommands.js";
import type { QuoteLevel } from "./anonSecretRegCommands.js";
import { regFileSpans } from "./anonSecretRegFile.js";
import type { Span } from "./anonSecretValues.js";

// One-way redaction of a stored-credential registry value whose NAME and DATA sit in separate
// fields (#3021). The keyed pass sees `…\DefaultPassword=<pw>`, but importers write the pair apart:
//   Hayabusa:        TgtObj=…\Winlogon\DefaultPassword Details=<pw> Proc=…
//   Sysmon message:  TargetObject: …\Winlogon\DefaultPassword\nDetails: <pw>
//   Velociraptor:    Key=…\Winlogon - ValueName=DefaultPassword - ValueData=<pw> - Type=REG_SZ
//   reg query:       DefaultPassword    REG_SZ    <pw>
// The name test is the one #3017 applies after "\" (isRegistryCredentialName), so a security
// setting or persistence value (LimitBlankPasswordUse, UseLogonCredential, Run\PasswordManager)
// keeps its data visible. Only the data goes; the name and the fields around it stay.

// A field that names the value: a key path ending in "\<Name>", or the bare value name. A quote is
// its own boundary, so a quoted label glued to the character before it (`}5"ValueName"`) still counts.
// A JSON quote may be escaped once (`\"`) or, in a string inside a JSON string, again (3 or 7
// backslashes, #3061); the whole run is the quote, never its tail (`\"` read out of `\\\"`).
const ANCHOR_RE =
  /(?:((?<!\\)\\{7}"|(?<!\\)\\{3}"|(?<!\\)\\"|"|')|(?<![\w.-]))(TargetObject|TgtObj|ValueName|RegValueName|RegistryValueName)\1[ \t]*([:=])/gi;
const PATH_LABELS = new Set(["targetobject", "tgtobj"]);
// A field that holds the value's data.
const DATA_RE =
  /(?:((?<!\\)\\{7}"|(?<!\\)\\{3}"|(?<!\\)\\"|"|')|(?<![\w.-]))(Details|ValueData|RegStringValue|RegistryValueData)\1[ \t]*([:=])/gi;

// What ends a bare NAME value (a key path may hold spaces: `Windows NT`): a line break, the
// Hayabusa cell separator, the host suffix, or the next `Field=` / `Field: ` / ` - Field=` (the
// shape genericSysmonRegistry.ts reads keys with).
const FIELD_END = /\r|\n| ¦ | @ |[ \t]+(?:- )?[A-Za-z][A-Za-z0-9_]{0,63}(?:=|: )/;
// A quoted name or data field (a JSON record on the same line) also ends a bare name (#3056): read
// on, the name would swallow the record, and the record's own fields would be skipped.
const QUOTED_FIELD =
  /(?:\\{7}|\\{3}|\\)?"(?:TargetObject|TgtObj|ValueName|RegValueName|RegistryValueName|Details|ValueData|RegStringValue|RegistryValueData)(?:\\{7}|\\{3}|\\)?"[ \t]*[:=]/i;

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
  // A bare name that ran into a quoted field: the data after it belongs to that record (#3056).
  beforeQuoted?: boolean;
}

// Where a bare name ends, and whether a quoted field ended it (the `{`, `[`, `,` or `;` that opens
// that record is not part of the name).
function nameEnd(text: string, at: number): { end: number; quoted: boolean } {
  const rest = text.slice(at, at + 4096);
  // The quoted field is found first, so a run of glued `x"ValueName":` fields is not rescanned to
  // the window's end for a field end on every name.
  const q = QUOTED_FIELD.exec(rest);
  const head = q ? rest.slice(0, q.index) : rest;
  const end = FIELD_END.exec(head);
  if (end || !q) return { end: at + (end ? end.index : head.length), quoted: false };
  let stop = at + q.index;
  while (stop > at && /[\s{[,;]/.test(text[stop - 1])) stop -= 1;
  return { end: stop, quoted: true };
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
  const quoted = readQuotedField(text, at);
  if (quoted) return quoted;
  if (data) {
    const stop = readBareData(text, at);
    const value = text.slice(at, stop).trimEnd();
    return value ? { span: [at, at + value.length], after: stop } : null;
  }
  const bare = nameEnd(text, at);
  const value = text.slice(at, bare.end).trimEnd();
  return value ? { span: [at, at + value.length], after: bare.end, beforeQuoted: bare.quoted } : null;
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
  // Searched within the limit only, so a long text with no blank line stays linear.
  const stop = text.slice(from, limit).indexOf(multiLine ? "\n\n" : "\n");
  return stop !== -1 ? from + stop : limit;
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

// --- JSON records (#3031, #3040) --------------------------------------------------------------
// A `"`-quoted name field is a JSON member, and its object is the record: the data field may come
// before or after the name, but never from the next or previous object. The walks below are
// quote-aware (a `{` or `}` inside a string value does not count) and bounded by PAIR_WINDOW. A
// pretty-printed record spans lines; a raw line break never sits inside a JSON string, so each one
// resets the string state, and one stray quote cannot flip the parity of the lines after it. A record
// inside a JSON string (`{\"ValueData\":…}`) is read the same way at quote level 1, where `\"` is its
// quote and a plain `"` ends it (#3059), and at levels 2 and 3 likewise (#3061). quoteAt and objectEnd live in anonSecretRegCommands.ts (the
// splat reader walks a hashtable with them too).

// Where the object holding position `at` (outside any string) opens, or -1 within the window. The
// backward walk is checked forward: `at` must sit directly in the object found (topLevel).
function objectStart(text: string, at: number, level: QuoteLevel): number {
  const floor = Math.max(0, at - PAIR_WINDOW);
  let inString = false;
  let depth = 0;
  for (let j = at - 1; j >= floor; j -= 1) {
    const ch = text[j];
    const quote = quoteAt(text, j, level);
    if (quote === "end") return -1;
    if (ch === "\n") inString = false;
    else if (quote) inString = !inString;
    else if (inString || (ch !== "{" && ch !== "}")) continue;
    else if (ch === "}") depth += 1;
    else if (depth === 0) return topLevel(text, j, at + 1, level)[at - j] ? j : -1;
    else depth -= 1;
  }
  return -1;
}

// The positions in [start, end) that sit directly in the object opened at `start` (not inside a
// string or a nested object).
function topLevel(text: string, start: number, end: number, level: QuoteLevel): Uint8Array {
  const flags = new Uint8Array(end - start);
  let inString = false;
  let depth = 0;
  for (let j = start + 1; j < end; j += 1) {
    const ch = text[j];
    const quote = quoteAt(text, j, level);
    if (quote === "end") break;
    if (!inString && depth === 0) flags[j - start] = 1;
    if (ch === "\n") inString = false;
    else if (quote) inString = !inString;
    else if (!inString && ch === "{") depth += 1;
    else if (!inString && ch === "}") depth -= 1;
  }
  return flags;
}

// The data field BEFORE a JSON name field at `at`, in the same object. When another name field sits
// earlier in the object, the data is that field's, so nothing is taken, except a key path
// (`"TargetObject":"…\\Winlogon"`) before a bare value name: the path is the key, the name is the
// value's (#3040).
function dataBefore(
  text: string,
  at: number,
  quote: string,
  label: string,
  placeholder: string,
): Span | null {
  const level = jsonLevel(quote);
  const start = objectStart(text, at, level);
  if (start < 0) return null;
  const other = new RegExp(ANCHOR_RE.source, "gi");
  other.lastIndex = start;
  const bareName = !PATH_LABELS.has(label.toLowerCase());
  for (let o = other.exec(text); o && o.index < at; o = other.exec(text))
    if (!(bareName && PATH_LABELS.has(o[2].toLowerCase()))) return null;
  const flags = topLevel(text, start, at, level);
  const re = new RegExp(DATA_RE.source, "gi");
  re.lastIndex = start;
  let found: Span | null = null;
  for (let m = re.exec(text); m && m.index < at; m = re.exec(text)) {
    if (m[1] !== quote || !flags[m.index - start]) continue;
    const value = readFieldValue(text, re.lastIndex, m[3], true);
    if (value && value.span[1] <= at && value.span[1] > value.span[0]) found = value.span;
  }
  return found && !text.startsWith(placeholder, found[0]) ? found : null;
}

// A JSON name field's data search stops at its object's `}`, across line breaks (a pretty-printed
// record), or at the next name field. An object that does not close within the window keeps the
// one-line bound.
function jsonLimit(text: string, from: number, quote: string): number {
  const level = jsonLevel(quote);
  const windowEnd = Math.min(text.length, from + PAIR_WINDOW);
  const close = objectEnd(text, from, windowEnd, level);
  if (close === windowEnd) return objectEnd(text, from, pairLimit(text, from, quote, ":"), level);
  const next = new RegExp(ANCHOR_RE.source, "gi");
  next.lastIndex = from;
  const n = next.exec(text);
  return n && n.index < close ? n.index : close;
}

// A name field's quote: `"` is a JSON member, `\"` a member of a record inside a JSON string (#3059),
// 3 or 7 backslashes and `"` a record nested one or two strings deeper (#3061).
const jsonLevel = (quote: string): QuoteLevel => quoteLevel(quote);
const isJsonQuote = (quote: string | undefined): quote is string => quote?.endsWith('"') === true;

// --- Flat data-first lines (#3040) -------------------------------------------------------------
// `ValueData=<pw> - ValueName=DefaultPassword - Type=REG_SZ`. On a flat line forward pairing cannot
// tell which name owns which data, so a line is read data-first only when its fields go strictly
// data, name, data, name … (all unquoted; a leading key path such as `TargetObject=…\Winlogon`
// that names no credential is skipped). Name k then owns data k. Any other line keeps forward
// pairing unchanged. Returns undefined when the line is not strictly data-first.
interface FlatField {
  at: number;
  end: number;
  name: boolean;
  label: string;
  sep: string;
}

function flatFields(text: string, start: number, end: number): FlatField[] | null {
  const fields: FlatField[] = [];
  for (const [re, name] of [
    [new RegExp(ANCHOR_RE.source, "gi"), true],
    [new RegExp(DATA_RE.source, "gi"), false],
  ] as const) {
    re.lastIndex = start;
    for (let m = re.exec(text); m && m.index < end; m = re.exec(text)) {
      if (m[1]) return null;
      fields.push({ at: m.index, end: re.lastIndex, name, label: m[2], sep: m[3] });
    }
  }
  return fields.sort((a, b) => a.at - b.at);
}

// One line, read once: on a strictly data-first line, each name field's start mapped to the data
// field before it; null for any other line.
interface FlatLine {
  end: number;
  owners: Map<number, FlatField> | null;
}

function readFlatLine(text: string, at: number): FlatLine {
  const ls = text.lastIndexOf("\n", at - 1) + 1;
  const nl = text.indexOf("\n", at);
  const end = nl === -1 ? text.length : nl;
  let fields = flatFields(text, ls, end);
  if (!fields) return { end, owners: null };
  while (fields.length && fields[0].name && PATH_LABELS.has(fields[0].label.toLowerCase())) {
    const v = readFieldValue(text, fields[0].end, fields[0].sep, false);
    if (!v || isRegistryCredentialName(valueName(fields[0].label, text.slice(v.span[0], v.span[1]))))
      return { end, owners: null };
    fields = fields.slice(1);
  }
  const strict =
    fields.length >= 2 && fields.length % 2 === 0 && fields.every((f, k) => f.name === (k % 2 === 1));
  if (!strict) return { end, owners: null };
  return { end, owners: new Map(fields.filter((f) => f.name).map((f, k) => [f.at, fields[2 * k]])) };
}

function flatDataBefore(
  text: string,
  at: number,
  line: FlatLine,
  placeholder: string,
): Span | null | undefined {
  const owner = line.owners?.get(at);
  if (!owner) return undefined;
  const data = readFieldValue(text, owner.end, owner.sep, true);
  if (!data || data.span[1] > at || text.startsWith(placeholder, data.span[0])) return null;
  return data.span[1] > data.span[0] ? data.span : null;
}

// --- Multi-line colon records, data line first (#3047) ----------------------------------------
// `ValueData: <pw>⏎ValueName: DefaultPassword`. Used only when forward pairing found nothing for the
// name, so it never changes a pairing that already hides something. The record is one block of
// lines up to a blank line, within the window. The bare value name starts its line, the data field
// starts the line right before it, and nothing else in the block before that line is a data field or
// a name field, except a key path (`TargetObject: …\Winlogon`). A `Details` line is never taken:
// Sysmon pairs Details with TargetObject, so it is that value's data, not this name's.
const COLON_DATA_LINE = /^[ \t]*(ValueData|RegStringValue|RegistryValueData)[ \t]*:/i;
const BLANK_LINE = /\n[ \t\r]*\n/g;

function colonDataBefore(text: string, at: number, label: string, placeholder: string): Span | null {
  const ls = text.lastIndexOf("\n", at - 1) + 1;
  if (PATH_LABELS.has(label.toLowerCase()) || ls === 0 || text.slice(ls, at).trim() !== "") return null;
  const prevStart = text.lastIndexOf("\n", ls - 2) + 1;
  const head = COLON_DATA_LINE.exec(text.slice(prevStart, ls - 1));
  if (!head) return null;
  const floor = Math.max(0, at - PAIR_WINDOW);
  const before = text.slice(floor, prevStart + 1);
  let blockStart = floor === 0 ? 0 : -1;
  for (const b of before.matchAll(BLANK_LINE)) blockStart = floor + b.index + b[0].length;
  if (blockStart < 0) return null;
  const other = new RegExp(ANCHOR_RE.source, "gi");
  other.lastIndex = blockStart;
  for (let o = other.exec(text); o && o.index < prevStart; o = other.exec(text))
    if (o[1] || !PATH_LABELS.has(o[2].toLowerCase())) return null;
  const data = new RegExp(DATA_RE.source, "gi");
  data.lastIndex = blockStart;
  const first = data.exec(text);
  if (!first || first.index < prevStart) return null;
  const value = readFieldValue(text, prevStart + head[0].length, ":", true);
  if (!value || value.span[1] >= ls || text.startsWith(placeholder, value.span[0])) return null;
  return value.span[1] > value.span[0] ? value.span : null;
}

function pairedFieldSpans(text: string, placeholder: string): Span[] {
  const spans: Span[] = [];
  const re = new RegExp(ANCHOR_RE.source, "gi");
  let line: FlatLine = { end: -1, owners: null };
  for (let m = re.exec(text); m; m = re.exec(text)) {
    const name = readFieldValue(text, re.lastIndex, m[3], false);
    if (!name) continue;
    re.lastIndex = Math.max(re.lastIndex, name.after);
    if (!isRegistryCredentialName(valueName(m[2], text.slice(name.span[0], name.span[1])))) continue;
    const json = isJsonQuote(m[1]);
    if (!m[1] && m.index > line.end) line = readFlatLine(text, m.index);
    const flat = m[1] ? undefined : flatDataBefore(text, m.index, line, placeholder);
    if (flat !== undefined) {
      if (flat) spans.push(flat);
      continue;
    }
    if (name.beforeQuoted) continue;
    const limit = json ? jsonLimit(text, name.after, m[1]) : pairLimit(text, name.after, m[1], m[3]);
    const span =
      dataSpan(text, name.after, limit, placeholder) ??
      (json ? dataBefore(text, m.index, m[1], m[2], placeholder) : null) ??
      (!m[1] && m[3] === ":" ? colonDataBefore(text, m.index, m[2], placeholder) : null);
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

export const REG_PAIR_PATTERNS: readonly RegExp[] = [
  ANCHOR_RE,
  DATA_RE,
  FIELD_END,
  QUOTED_FIELD,
  DATA_FIRST,
  GLUED_OPTION,
  DATA_MORE,
  DIGIT_MORE,
  REG_QUERY_RE,
  REG_QUERY_DATA_END,
  COLON_DATA_LINE,
  BLANK_LINE,
];

/** Redact the data of a stored-credential registry value written as separate name and data fields. */
export function redactRegistryCredentialPairs(text: string, placeholder: string): string {
  const spans = [
    ...pairedFieldSpans(text, placeholder),
    ...regQuerySpans(text, placeholder),
    ...commandSpans(text, placeholder),
    ...regFileSpans(text, placeholder),
  ]
    .sort((a, b) => a[0] - b[0])
    // Overlapping spans merge into one, so no part of either is left out or written twice.
    // Built in place: copying the list per span was quadratic in the number of spans (#3054).
    .reduce<Span[]>((kept, s) => {
      const last = kept[kept.length - 1];
      if (!last || s[0] >= last[1]) kept.push(s);
      else kept[kept.length - 1] = [last[0], Math.max(last[1], s[1])];
      return kept;
    }, []);
  if (!spans.length) return text;
  let out = "";
  let last = 0;
  for (const [s, e] of spans) {
    out += text.slice(last, s) + placeholder;
    last = e;
  }
  return out + text.slice(last);
}
