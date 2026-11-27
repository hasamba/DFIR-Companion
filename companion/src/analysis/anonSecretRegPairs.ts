import { isRegistryCredentialName } from "./anonSecretKeys.js";
import { readQuoted, type Span } from "./anonSecretValues.js";

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

function pairedFieldSpans(text: string, placeholder: string): Span[] {
  const spans: Span[] = [];
  const re = new RegExp(ANCHOR_RE.source, "gi");
  for (let m = re.exec(text); m; m = re.exec(text)) {
    const name = readFieldValue(text, re.lastIndex, m[3], false);
    if (!name) continue;
    re.lastIndex = Math.max(re.lastIndex, name.after);
    if (!isRegistryCredentialName(valueName(m[2], text.slice(name.span[0], name.span[1])))) continue;
    const span = dataSpan(text, name.after, pairLimit(text, name.after, m[1], m[3]), placeholder);
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

/** Redact the data of a stored-credential registry value written as separate name and data fields. */
export function redactRegistryCredentialPairs(text: string, placeholder: string): string {
  const spans = [...pairedFieldSpans(text, placeholder), ...regQuerySpans(text, placeholder)]
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
