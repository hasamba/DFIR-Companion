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

// A field that names the value: a key path ending in "\<Name>", or the bare value name. A quote is
// its own boundary, so a quoted label glued to the character before it (`}5"ValueName"`) still counts.
const ANCHOR_RE =
  /(?:(\\"|"|')|(?<![\w.-]))(TargetObject|TgtObj|ValueName|RegValueName|RegistryValueName)\1[ \t]*([:=])/gi;
const PATH_LABELS = new Set(["targetobject", "tgtobj"]);
// A field that holds the value's data.
const DATA_RE =
  /(?:(\\"|"|')|(?<![\w.-]))(Details|ValueData|RegStringValue|RegistryValueData)\1[ \t]*([:=])/gi;

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

// --- JSON records (#3031, #3040) --------------------------------------------------------------
// A `"`-quoted name field is a JSON member, and its object is the record: the data field may come
// before or after the name, but never from the next or previous object. The walks below are
// quote-aware (a `{` or `}` inside a string value does not count) and bounded by PAIR_WINDOW. A
// pretty-printed record spans lines; a raw line break never sits inside a JSON string, so each one
// resets the string state, and one stray quote cannot flip the parity of the lines after it.

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
    if (ch === "\n") inString = false;
    else if (ch === '"' && !escapedAt(text, j)) inString = !inString;
    else if (inString || (ch !== "{" && ch !== "}")) continue;
    else if (ch === "{") depth += 1;
    else if (depth === 0) return j;
    else depth -= 1;
  }
  return limit;
}

// Where the object holding position `at` (outside any string) opens, or -1 within the window. The
// backward walk is checked forward: `at` must sit directly in the object found (topLevel).
function objectStart(text: string, at: number): number {
  const floor = Math.max(0, at - PAIR_WINDOW);
  let inString = false;
  let depth = 0;
  for (let j = at - 1; j >= floor; j -= 1) {
    const ch = text[j];
    if (ch === "\n") inString = false;
    else if (ch === '"' && !escapedAt(text, j)) inString = !inString;
    else if (inString || (ch !== "{" && ch !== "}")) continue;
    else if (ch === "}") depth += 1;
    else if (depth === 0) return topLevel(text, j, at + 1)[at - j] ? j : -1;
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
    if (ch === "\n") inString = false;
    else if (ch === '"' && !escapedAt(text, j)) inString = !inString;
    else if (!inString && ch === "{") depth += 1;
    else if (!inString && ch === "}") depth -= 1;
  }
  return flags;
}

// The data field BEFORE a JSON name field at `at`, in the same object. When another name field sits
// earlier in the object, the data is that field's, so nothing is taken, except a key path
// (`"TargetObject":"…\\Winlogon"`) before a bare value name: the path is the key, the name is the
// value's (#3040).
function dataBefore(text: string, at: number, label: string, placeholder: string): Span | null {
  const start = objectStart(text, at);
  if (start < 0) return null;
  const other = new RegExp(ANCHOR_RE.source, "gi");
  other.lastIndex = start;
  const bareName = !PATH_LABELS.has(label.toLowerCase());
  for (let o = other.exec(text); o && o.index < at; o = other.exec(text))
    if (!(bareName && PATH_LABELS.has(o[2].toLowerCase()))) return null;
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

// A JSON name field's data search stops at its object's `}`, across line breaks (a pretty-printed
// record), or at the next name field. An object that does not close within the window keeps the
// one-line bound.
function jsonLimit(text: string, from: number): number {
  const windowEnd = Math.min(text.length, from + PAIR_WINDOW);
  const close = objectEnd(text, from, windowEnd);
  if (close === windowEnd) return objectEnd(text, from, pairLimit(text, from, '"', ":"));
  const next = new RegExp(ANCHOR_RE.source, "gi");
  next.lastIndex = from;
  const n = next.exec(text);
  return n && n.index < close ? n.index : close;
}

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

function pairedFieldSpans(text: string, placeholder: string): Span[] {
  const spans: Span[] = [];
  const re = new RegExp(ANCHOR_RE.source, "gi");
  let line: FlatLine = { end: -1, owners: null };
  for (let m = re.exec(text); m; m = re.exec(text)) {
    const name = readFieldValue(text, re.lastIndex, m[3], false);
    if (!name) continue;
    re.lastIndex = Math.max(re.lastIndex, name.after);
    if (!isRegistryCredentialName(valueName(m[2], text.slice(name.span[0], name.span[1])))) continue;
    const json = m[1] === '"';
    if (!m[1] && m.index > line.end) line = readFlatLine(text, m.index);
    const flat = m[1] ? undefined : flatDataBefore(text, m.index, line, placeholder);
    if (flat !== undefined) {
      if (flat) spans.push(flat);
      continue;
    }
    const limit = json ? jsonLimit(text, name.after) : pairLimit(text, name.after, m[1], m[3]);
    const span =
      dataSpan(text, name.after, limit, placeholder) ??
      (json ? dataBefore(text, m.index, m[2], placeholder) : null);
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
// PowerShell binds a parameter by any unique prefix (`-N`, `-Va`; a bare `-V` is ambiguous with
// -Verbose and fails) and by position: Path, then Name, then Value (#3040). `sp` is the alias.
const PS_SET_PROPERTY: CommandGrammar = {
  start: /(?<![\w.-])(?:(?:Set|New)-ItemProperty|sp)(?=[ \t])/gi,
  name: /^-n(?:a(?:me?)?)?$/i,
  data: /^-va(?:l(?:ue?)?)?$/i,
  stops: ";|",
};
const PS_PATH = /^-(?:p|pat?h?|pspath|lp|l(?:i(?:t(?:e(?:r(?:a(?:l(?:p(?:a(?:th?)?)?)?)?)?)?)?)?)?)$/i;
// Switches take no argument.
const PS_SWITCH =
  /^-(?:fo(?:r(?:ce?)?)?|pas\w*|whatif|wi|confirm|cf|usetransaction|usetx|verbose|vb|debug|db)$/i;
// The other parameters of the two cmdlets (and the common ones) that take one argument. Any other
// option stops positional binding for the command: its arity is unknown, so a position cannot be
// trusted, and a Name/Value given by name still counts.
const PS_VALUED =
  /^-(?:pr\w*|t(?:y(?:pe?)?)?|cr\w*|fi\w*|inc\w*|ex\w*|erroraction|ea|warningaction|wa|informationaction|infa|errorvariable|ev|warningvariable|wv|informationvariable|iv|outvariable|ov|outbuffer|ob|pipelinevariable|pv)$/i;
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

type PsSlot = "path" | "name" | "value";
const PS_COMMAND_WORD = /^(?:(?:Set|New)-ItemProperty|sp)$/i;

function psSlot(param: string): PsSlot | "switch" | "other" | null {
  if (PS_SET_PROPERTY.name.test(param)) return "name";
  if (PS_SET_PROPERTY.data.test(param)) return "value";
  if (PS_PATH.test(param)) return "path";
  if (PS_SWITCH.test(param)) return "switch";
  return PS_VALUED.test(param) ? "other" : null;
}

// The value token as data: a quoted value whole, a bare one with its digit run, cut before a cue.
function psData(text: string, t: Token, end: number): Span {
  return beforeCue(text, t.quoted ? t.span : withDigitRun(text, t.span, end, PS_SET_PROPERTY.stops));
}

// `-Name:DefaultPassword` / `-Value:'<pw>'`: the argument glued to the parameter by a colon.
function psInline(text: string, t: Token, colon: number, end: number): Token | null {
  const at = t.span[0] + colon + 1;
  if (at >= t.span[1]) return null;
  if (text[at] !== "'" && text[at] !== '"') return { span: [at, t.span[1]], after: t.after, quoted: false };
  const q = readQuoted(text, at);
  return q && q.span[1] <= end ? { span: q.span, after: Math.max(q.after, t.after), quoted: true } : null;
}

interface PsResult {
  span: Span | null;
  after: number;
  // A Name or Value given twice: a second command glued to this one (`…'0Set-ItemProperty …`)
  // starts at `after`, so the caller binds from there again.
  more: boolean;
}

function psBind(
  text: string,
  named: Partial<Record<PsSlot, Token>>,
  positional: Token[],
  end: number,
): Span | null {
  const bound = { ...named };
  for (const s of (["path", "name", "value"] as const).filter((x) => !named[x]))
    bound[s] ??= positional.shift();
  const { name, value } = bound;
  if (!name || !value || !isRegistryCredentialName(text.slice(name.span[0], name.span[1]))) return null;
  const data = psData(text, value, end);
  return isLiteral(text.slice(data[0], data[1])) ? data : null;
}

// Set-ItemProperty / New-ItemProperty / sp: Name and Value by name, prefix, `-P:v` or position.
function psCommandSpan(text: string, from: number): PsResult {
  const nested = insideQuotes(text, from);
  const end = Math.min(text.length, from + COMMAND_WINDOW);
  const named: Partial<Record<PsSlot, Token>> = {};
  const positional: Token[] = [];
  let positionalOk = true;
  let pending: PsSlot | "other" | null = null;
  let more = false;
  let i = from;
  for (let t = nextToken(text, i, end, nested, PS_SET_PROPERTY.stops); t && t.after > i;) {
    const raw = text.slice(t.span[0], t.span[1]);
    // An option of unknown arity may be a switch (`-Zork`, an abbreviated `-wh`): a following
    // `-option` is then a parameter, never its argument.
    const flag: boolean = (!pending || pending === "other") && !t.quoted && /^-[A-Za-z]/.test(raw);
    if (flag) pending = null;
    const colon: number = flag ? raw.indexOf(":") : -1;
    const slot: ReturnType<typeof psSlot> = flag ? psSlot(colon < 0 ? raw : raw.slice(0, colon)) : null;
    // The next cmdlet on the same line without a `;` starts a new command: it is not this one's.
    if (!pending && !t.quoted && PS_COMMAND_WORD.test(raw)) break;
    if ((slot === "name" || slot === "value") && named[slot]) {
      more = true;
      break;
    }
    i = t.after;
    if (pending) {
      if (pending !== "other") named[pending] = t;
      pending = null;
    } else if (flag) {
      if (slot === null) positionalOk = false;
      const inline = colon < 0 ? null : psInline(text, t, colon, end);
      if (inline) i = inline.after;
      if (inline && slot && slot !== "switch" && slot !== "other") named[slot] = inline;
      else if (!inline && colon < 0 && slot !== "switch") pending = slot ?? "other";
    } else positional.push(t);
    t = nextToken(text, i, end, nested, PS_SET_PROPERTY.stops);
  }
  return { span: psBind(text, named, positionalOk ? positional : [], end), after: i, more };
}

// --- .NET calls and splatting (#3040) ----------------------------------------------------------
//   [Microsoft.Win32.Registry]::SetValue('<key>', 'DefaultPassword', '<pw>'[, kind])
//   $key.SetValue('DefaultPassword', '<pw>'[, kind])
//   $p = @{ Path = '…'; Name = 'DefaultPassword'; Value = '<pw>' }; Set-ItemProperty @p
// Only a quoted literal is data; a `$variable` or an expression is left.
const SET_VALUE_RE = /(\]::|\.)SetValue\(/gi;

// The quoted arguments of a call whose `(` ends at `at`, up to its `)`: null for a non-literal one.
function callArgs(text: string, at: number): (Span | null)[] {
  const args: (Span | null)[] = [];
  let i = at;
  for (let n = 0; n < 4; n += 1) {
    while (text[i] === " " || text[i] === "\t") i += 1;
    const q = text[i] === '"' || text[i] === "'" || text.startsWith('\\"', i) ? readQuoted(text, i) : null;
    if (q && q.after > q.span[1]) {
      args.push(q.span);
      i = q.after;
    } else {
      args.push(null);
      while (i < text.length && !",)\n".includes(text[i])) i += 1;
    }
    while (text[i] === " " || text[i] === "\t") i += 1;
    if (text[i] !== ",") break;
    i += 1;
  }
  return args;
}

function setValueSpans(text: string): Span[] {
  const spans: Span[] = [];
  const re = new RegExp(SET_VALUE_RE.source, "gi");
  for (let m = re.exec(text); m; m = re.exec(text)) {
    const args = callArgs(text, re.lastIndex);
    const first = m[1] === "." ? 0 : 1;
    const name = args[first];
    const value = args[first + 1];
    if (name && value && isRegistryCredentialName(text.slice(name[0], name[1])))
      spans.push(beforeCue(text, value));
  }
  return spans;
}

// A hashtable entry `Name = …` or `Value = …` (key bare or quoted), after `{`, `;` or a line break.
// The separator is matched, not looked behind for: a lookbehind over `[ \t]*` would rescan a long
// run of spaces from every position in it.
const HASH_ENTRY_RE = /[{;\n][ \t]*(["']?)(Name|Value)\1[ \t]*=[ \t]*/gi;

// The hashtables worth reading: the nearest `@{` before each `Name =` entry, within the window. The
// search starts from the entries, so a long script with many hashtables and no Name stays linear.
function splatStarts(text: string): number[] {
  const starts = new Set<number>();
  const re = new RegExp(HASH_ENTRY_RE.source, "gi");
  for (let m = re.exec(text); m; m = re.exec(text)) {
    if (m[2].toLowerCase() !== "name") continue;
    const at = text.lastIndexOf("@{", m.index);
    if (at !== -1 && m.index - at <= COMMAND_WINDOW) starts.add(at);
  }
  return [...starts];
}

function splatSpans(text: string): Span[] {
  const spans: Span[] = [];
  for (const at of splatStarts(text)) {
    const end = objectEnd(text, at + 2, Math.min(text.length, at + COMMAND_WINDOW));
    // The entries are searched inside this hashtable only.
    const body = text.slice(at + 1, end);
    const re = new RegExp(HASH_ENTRY_RE.source, "gi");
    let name: string | null = null;
    let value: Span | null = null;
    for (let m = re.exec(body); m; m = re.exec(body)) {
      const q = readQuoted(text, at + 1 + re.lastIndex);
      const span = q && q.after > q.span[1] && q.span[1] <= end ? q.span : null;
      if (m[2].toLowerCase() === "name") name ??= span ? text.slice(span[0], span[1]) : "";
      else value ??= span;
    }
    if (name && value && isRegistryCredentialName(name)) spans.push(beforeCue(text, value));
  }
  return spans;
}

function commandSpans(text: string, placeholder: string): Span[] {
  const spans: Span[] = [];
  for (const g of [REG_ADD, PS_SET_PROPERTY]) {
    const re = new RegExp(g.start.source, "gi");
    for (let m = re.exec(text); m; m = re.exec(text)) {
      let r: PsResult = { span: null, after: re.lastIndex, more: true };
      while (r.more) {
        const at = r.after;
        r = g === REG_ADD ? { ...commandSpan(text, at, g), more: false } : psCommandSpan(text, at);
        if (r.span) spans.push(r.span);
        if (r.after <= at) break;
      }
      re.lastIndex = Math.max(re.lastIndex, r.after);
    }
  }
  return [...spans, ...setValueSpans(text), ...splatSpans(text)].filter(
    (s) => s[1] > s[0] && !text.startsWith(placeholder, s[0]),
  );
}

/** Redact the data of a stored-credential registry value written as separate name and data fields. */
export function redactRegistryCredentialPairs(text: string, placeholder: string): string {
  const spans = [
    ...pairedFieldSpans(text, placeholder),
    ...regQuerySpans(text, placeholder),
    ...commandSpans(text, placeholder),
  ]
    .sort((a, b) => a[0] - b[0])
    // Overlapping spans merge into one, so no part of either is left out or written twice.
    .reduce<Span[]>((kept, s) => {
      const last = kept[kept.length - 1];
      if (!last || s[0] >= last[1]) return [...kept, s];
      return [...kept.slice(0, -1), [last[0], Math.max(last[1], s[1])]];
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
