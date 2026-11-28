import { isRegistryCredentialName } from "./anonSecretKeys.js";
import {
  concatEnd,
  psNameText,
  psVariables,
  readDoubled,
  readHereString,
  readValueQuoted,
  widen,
  type PsVariables,
  type QuoteMode,
} from "./anonSecretPsQuote.js";
import { isEncodedCue, readQuoted, type Span } from "./anonSecretValues.js";

// The command readers of the registry-credential pass (anonSecretRegPairs.ts): reg add,
// Set-/New-ItemProperty, .NET SetValue calls and splatted hashtables that set a stored-credential
// value (#3031, #3040, #3047, #3051, #3054). Split out of anonSecretRegPairs.ts for size.

// A quote preceded by an odd number of backslashes is escaped (JSON `\"`).
export const escapedAt = (text: string, j: number): boolean => {
  let r = 0;
  while (text[j - 1 - r] === "\\") r += 1;
  return r % 2 === 1;
};

// How a quote at `j` acts in a record at quote level L: plain quotes (level 0), quotes escaped once
// inside a JSON string (level 1, `{\"ValueData\":…}`, #3059), or escaped again inside a string in
// that string (levels 2 and 3: 3 and 7 backslashes, #3061): it opens or closes a string ("toggle"),
// it is an outer string's quote, so the record ends there ("end"), or it is text (null).
export type QuoteLevel = 0 | 1 | 2 | 3;
const MAX_QUOTE_LEVEL = 3;

// The level a quote after `r` backslashes belongs to. One JSON layer turns an even run into half as
// many backslashes before a real quote (this level), and an odd run into an escaped quote one level
// down, with (r - 1) / 2 backslashes before it.
export function levelOfRun(r: number): number {
  let level = 0;
  for (let n = r; n % 2 === 1; n = (n - 1) / 2) level += 1;
  return level;
}

function runBefore(text: string, j: number, floor = 0): number {
  let r = 0;
  while (j - 1 - r >= floor && text[j - 1 - r] === "\\") r += 1;
  return r;
}

export function quoteAt(text: string, j: number, level: QuoteLevel): "toggle" | "end" | null {
  if (text[j] !== '"') return null;
  const at = levelOfRun(runBefore(text, j));
  if (at === level) return "toggle";
  return at < level ? "end" : null;
}

/** The quote level a field's quote (`"`, `\"`, 3 or 7 backslashes and `"`) stands for. */
export const quoteLevel = (quote: string): QuoteLevel =>
  Math.min(MAX_QUOTE_LEVEL, levelOfRun(quote.length - 1)) as QuoteLevel;

// A quoted value at `i`. Levels 0 and 1 are readQuoted's. A value opened by 3 or 7 backslashes and a
// quote (#3061) ends at the next quote of its own level (the backslashes of that quote are not part
// of the value) or at an outer string's quote, and never runs past a line break.
export function readQuotedField(text: string, i: number): { span: Span; after: number } | null {
  let b = 0;
  while (text[i + b] === "\\") b += 1;
  if (b < 3 || text[i + b] !== '"') return readQuoted(text, i);
  const level = levelOfRun(b);
  if (b !== 2 ** level - 1 || level > MAX_QUOTE_LEVEL) return null;
  const start = i + b + 1;
  for (let j = start; j < text.length && text[j] !== "\n"; j += 1) {
    if (text[j] !== '"') continue;
    const r = runBefore(text, j, start);
    const at = levelOfRun(r);
    if (at === level) return { span: [start, j - b], after: j + 1 };
    if (at < level) return { span: [start, j - r], after: j - r };
  }
  const nl = text.indexOf("\n", start);
  const end = nl === -1 ? text.length : nl;
  return { span: [start, end], after: end };
}

// Where the object holding position `from` closes, or `limit` when it does not close before it.
export function objectEnd(text: string, from: number, limit: number, level: QuoteLevel = 0): number {
  let inString = false;
  let depth = 0;
  for (let j = from; j < limit; j += 1) {
    const ch = text[j];
    const quote = quoteAt(text, j, level);
    if (quote === "end") return j;
    if (ch === "\n") inString = false;
    else if (quote) inString = !inString;
    else if (inString || (ch !== "{" && ch !== "}")) continue;
    else if (ch === "{") depth += 1;
    else if (depth === 0) return j;
    else depth -= 1;
  }
  return limit;
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
  start: /(?:(?<![\w.-])|(?<=\\[nrt]))reg(?:\.exe)?(?:\\?")?[ \t]+add(?=[ \t])/gi,
  name: /^[/-]v$/i,
  data: /^[/-]d$/i,
  stops: "&|<>",
};
// PowerShell binds a parameter by any unique prefix (`-N`, `-Va`; a bare `-V` is ambiguous with
// -Verbose and fails) and by position: Path, then Name, then Value (#3040). `sp` is the alias.
const PS_SET_PROPERTY: CommandGrammar = {
  start: /(?:(?<![\w.-])|(?<=\\[nrt]))(?:(?:Set|New)-ItemProperty|sp)(?=[ \t])/gi,
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
  // A quoted token is walked with the `''` escape only, so a stray `""` or backtick never moves the
  // command's token boundaries (#3051). Taken as data, it is read again across its escapes (reread).
  open?: number;
  // A here-string: the command ends after it, as it ended at the line break before (#3051), so the
  // walk never runs on into the lines after it.
  last?: boolean;
  mode?: QuoteMode;
}

// A quoted data token read across its `""` / backtick escapes; the walked span otherwise.
function reread(text: string, t: Token): Span {
  if (t.open === undefined) return t.span;
  const q = readValueQuoted(text, t.open, t.mode);
  return q && q.span[0] === t.span[0] && q.span[1] > t.span[1] ? q.span : t.span;
}

// An odd number of unescaped `"` before `at` on its line: the command sits inside a quoted string.
function insideQuotes(text: string, at: number): boolean {
  let odd = false;
  for (let j = at - 1; j >= Math.max(0, at - 4096) && text[j] !== "\n"; j -= 1)
    if (text[j] === '"' && !escapedAt(text, j)) odd = !odd;
  return odd;
}

// --- A JSON-escaped line break before the next command (#3057) ---------------------------------
// In a JSON string (a 4104 ScriptBlockText) a script's lines are joined by `\n`. A command may start
// right after one (the start patterns accept a `\n`, `\r` or `\t` before it, when its backslash is
// not itself escaped: `C:\\nsp` is a path), and a token stops before one that is followed by another
// registry command, so the walk never runs on into that command. Nothing else is cut there: a value
// that holds a backslash and a letter (`ab\nq9`, `HKLM\x\new`) stays one token, as before.
const NEXT_COMMAND = /(?:(?:Set|New)-ItemProperty|sp|reg(?:\.exe)?(?:\\?")?[ \t]+add)(?=[ \t])/iy;

const escapedBreakAt = (text: string, k: number): boolean =>
  text[k] === "\\" && "nrt".includes(text[k + 1] ?? "x") && !escapedAt(text, k);

function startOk(text: string, at: number): boolean {
  return !/\w/.test(text[at - 1] ?? "") || ("nrt".includes(text[at - 1]) && escapedBreakAt(text, at - 2));
}

function breaksBeforeCommand(text: string, k: number): boolean {
  if (!escapedBreakAt(text, k)) return false;
  NEXT_COMMAND.lastIndex = k + 2;
  return NEXT_COMMAND.test(text);
}

function bareToken(text: string, at: number, end: number, stops: string): Token {
  let k = at;
  while (
    k < end &&
    !/\s/.test(text[k]) &&
    text[k] !== '"' &&
    !stops.includes(text[k]) &&
    !(k > at && breaksBeforeCommand(text, k))
  )
    k += 1;
  // `pw\"` inside a JSON string: the backslash escapes the closing quote, it is not data.
  const stop = text[k] === '"' && escapedAt(text, k) ? k - 1 : k;
  return { span: [at, stop], after: stop, quoted: false };
}

function nextToken(
  text: string,
  i: number,
  end: number,
  nested: boolean,
  stops: string,
  ps = false,
): Token | null {
  let at = i;
  while (at < end && (text[at] === " " || text[at] === "\t")) at += 1;
  if (at >= end || text[at] === "\r" || text[at] === "\n" || stops.includes(text[at])) return null;
  if (breaksBeforeCommand(text, at)) return null;
  const escapedQuote = text.startsWith('\\"', at);
  // Inside `cmd /c "…"` a quote after a space that is followed by text opens a quoted argument
  // (`cmd /c "reg add "HKLM\…\Windows NT\…" /v …"`); any other bare quote closes the command.
  // A PowerShell here-string (`@'…'@`, `@"…"@`) is one value across its lines (#3051).
  const here = ps && text[at] === "@" ? readHereString(text, at, end) : null;
  if (here) return { span: here.span, after: here.after, quoted: true, last: true };
  // `""v""` inside `powershell -c "…"` or `cmd /c "reg add …"`: cmd's doubled quote around one
  // argument (#3054, #3057).
  const doubled = nested ? readDoubled(text, at, end) : null;
  if (doubled) return { span: doubled.span, after: doubled.after, quoted: true };
  if (text[at] === '"' && nested && !(/\s/.test(text[at - 1] ?? "") && /[^\s"]/.test(text[at + 1] ?? "")))
    return null;
  if (escapedQuote || text[at] === '"' || text[at] === "'") {
    const q = readValueQuoted(text, at, { escapes: false });
    if (!q) return null;
    // An unclosed quote would run to the line end and hide what follows (an address the anonymizer
    // must learn, an encoded command): take one word after the quote instead.
    const closed = q.after > q.span[1] || text[q.after] === '"';
    if (!closed) return bareToken(text, q.span[0], end, stops);
    return { span: q.span, after: q.after, quoted: true, open: at, mode: { ps, nested } };
  }
  return bareToken(text, at, end, stops);
}

// A PowerShell `$variable` or `(subexpression)` is not the literal value.
const isLiteral = (value: string): boolean => value !== "" && !/^[$(@]/.test(value);

// The data stops before an encoded-command cue inside it (#3005): `-Value '… FromBase64String('`
// closes the quote at the cue's own `'`, and hiding the cue would send the blob after it in clear.
// A cue whose quote is escaped (`FromBase64String(''<blob>'')` inside a '-quoted value, `""`, a
// backtick) is not one the CMD pass tokenizes (anonymize.ts FROM_B64_RE needs the blob right after
// ONE quote), so cutting before it would send the blob in clear: the value is hidden whole (#3051).
const ESCAPED_CUE = /FromBase64String\(\s*(?:''|""|`|\\"\\")/iy;

function cmdMasksCue(text: string, j: number): boolean {
  ESCAPED_CUE.lastIndex = j;
  return !ESCAPED_CUE.test(text);
}

function beforeCue(text: string, span: Span): Span {
  for (let j = span[0] + 1; j < span[1]; j += 1) {
    if (!isEncodedCue(text, j) || !cmdMasksCue(text, j)) continue;
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

// A token that launches reg (`reg`, `reg.exe`, a path or quoted path ending in it) followed by an
// `add` token. A `reg add` inside one quoted token is a value, not a launcher.
const REG_LAUNCHER = /(?:^|[\\/])reg(?:\.exe)?$/i;

function isRegLauncher(text: string, value: string, t: Token, end: number, nested: boolean): boolean {
  if (!REG_LAUNCHER.test(value)) return false;
  const next = nextToken(text, t.after, end, nested, REG_ADD.stops);
  return next !== null && !next.quoted && /^add$/i.test(text.slice(next.span[0], next.span[1]));
}

function commandSpan(
  text: string,
  from: number,
  g: CommandGrammar,
  vars: PsVariables,
): { span: Span | null; after: number } {
  const nested = insideQuotes(text, from);
  const end = Math.min(text.length, from + COMMAND_WINDOW);
  let name: string | null = null;
  let data: Span | null = null;
  let pending: "name" | "data" | null = null;
  let i = from;
  let t: Token | null = nextToken(text, i, end, nested, g.stops);
  while (t && t.after > i) {
    const value = text.slice(t.span[0], t.span[1]);
    // The next `reg add` on the same line starts a new command: stop before its launcher (#3047).
    if (pending === null && isRegLauncher(text, value, t, end, nested)) break;
    i = t.after;
    if (pending === "name") name ??= value;
    else if (pending === "data")
      data ??= beforeCue(text, t.quoted ? reread(text, t) : withDigitRun(text, t.span, end, g.stops));
    const flag: boolean = pending === null && !t.quoted;
    pending = flag && g.name.test(value) ? "name" : flag && g.data.test(value) ? "data" : null;
    t = nextToken(text, i, end, nested, g.stops);
  }
  const ok = name !== null && data !== null && isRegistryCredentialName(name);
  if (!ok || !data) return { span: null, after: i };
  if (isLiteral(text.slice(data[0], data[1]))) return { span: data, after: i };
  // `/d $v` from PowerShell: the literal assigned to `$v` (#3057), never a single-quoted `'$v'`.
  const assigned = text[data[0] - 1] === "'" ? null : vars.literal(data[0]);
  return { span: assigned, after: i };
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
  return beforeCue(text, t.quoted ? reread(text, t) : withDigitRun(text, t.span, end, PS_SET_PROPERTY.stops));
}

// `-Name:DefaultPassword` / `-Value:'<pw>'`: the argument glued to the parameter by a colon.
function psInline(text: string, t: Token, colon: number, end: number): Token | null {
  const at = t.span[0] + colon + 1;
  if (at >= t.span[1]) return null;
  if (text[at] !== "'" && text[at] !== '"') return { span: [at, t.span[1]], after: t.after, quoted: false };
  const q = readValueQuoted(text, at, { escapes: false });
  if (!q || q.span[1] > end) return null;
  return { span: q.span, after: Math.max(q.after, t.after), quoted: true, open: at, mode: { ps: true } };
}

interface PsResult {
  span: Span | null;
  after: number;
  // A Name or Value given twice: a second command glued to this one (`…'0Set-ItemProperty …`)
  // starts at `after`, so the caller binds from there again.
  more: boolean;
  // The command ended on a here-string: the scan resumes inside its body, so a command written in
  // it is still read (#3057; the body may now run far past the window).
  resume?: number;
}

function psBind(
  text: string,
  named: Partial<Record<PsSlot, Token>>,
  positional: Token[],
  end: number,
  vars: PsVariables,
): Span | null {
  const bound = { ...named };
  for (const s of (["path", "name", "value"] as const).filter((x) => !named[x]))
    bound[s] ??= positional.shift();
  const { name, value } = bound;
  if (!name || !value || !isRegistryCredentialName(psNameText(text, name.span, true))) return null;
  const data = psData(text, value, end);
  if (isLiteral(text.slice(data[0], data[1]))) return data;
  // A `$variable` (or `"$variable"`): the literal assigned to it (#3054).
  return text[value.span[0] - 1] === "'" ? null : vars.literal(value.span[0]);
}

// Set-ItemProperty / New-ItemProperty / sp: Name and Value by name, prefix, `-P:v` or position.
function psCommandSpan(text: string, from: number, vars: PsVariables): PsResult {
  const nested = insideQuotes(text, from);
  const end = Math.min(text.length, from + COMMAND_WINDOW);
  const named: Partial<Record<PsSlot, Token>> = {};
  const positional: Token[] = [];
  let positionalOk = true;
  let pending: PsSlot | "other" | null = null;
  let more = false;
  let resume: number | undefined;
  let i = from;
  for (let t = nextToken(text, i, end, nested, PS_SET_PROPERTY.stops, true); t && t.after > i;) {
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
    if (t.last) resume = t.span[0];
    t = t.last ? null : nextToken(text, i, end, nested, PS_SET_PROPERTY.stops, true);
  }
  return { span: psBind(text, named, positionalOk ? positional : [], end, vars), after: i, more, resume };
}

// --- .NET calls and splatting (#3040) ----------------------------------------------------------
//   [Microsoft.Win32.Registry]::SetValue('<key>', 'DefaultPassword', '<pw>'[, kind])
//   $key.SetValue('DefaultPassword', '<pw>'[, kind])
//   $p = @{ Path = '…'; Name = 'DefaultPassword'; Value = '<pw>' }; Set-ItemProperty @p
// Only a quoted literal is data; a `$variable` or an expression is left.
const SET_VALUE_RE = /(\]::|\.)SetValue\(/gi;

// The quoted arguments of a call whose `(` ends at `at`, up to its `)`: null for a non-literal one.
// A non-literal argument is skipped within the window, so many unclosed calls stay linear.
// The arguments are found with the `''` escape only, so a stray escape never shifts them; each is
// then widened on its own (#3051).
function callArgs(text: string, at: number, mode: QuoteMode, starts: number[] = []): (Span | null)[] {
  const args: (Span | null)[] = [];
  const end = Math.min(text.length, at + COMMAND_WINDOW);
  let i = at;
  for (let n = 0; n < 4; n += 1) {
    while (text[i] === " " || text[i] === "\t") i += 1;
    starts.push(i);
    const quote = text[i] === '"' || text[i] === "'" || text.startsWith('\\"', i);
    const here = mode.ps && text[i] === "@" ? readHereString(text, i, end) : null;
    const q = here ?? (quote ? readValueQuoted(text, i, { escapes: false }) : null);
    if (q && q.after > q.span[1]) {
      const span = here ? q.span : widen(text, i, q.span, mode, ",)", end);
      // `'a' + 'b'`: one value (#3057).
      const more = span === q.span && !here ? concatEnd(text, q.after, end) : null;
      args.push(more ? [span[0], more.span[1]] : span);
      i = more ? more.after : q.after;
    } else {
      args.push(null);
      while (i < end && !",)\n".includes(text[i])) i += 1;
    }
    while (text[i] === " " || text[i] === "\t") i += 1;
    if (text[i] !== ",") break;
    i += 1;
  }
  return args;
}

// A registry key path as the first argument: the static form even when written with a dot.
const KEY_PATH_RE = /^(?:HKEY_|HK(?:LM|CU|CR|CC|U)(?:\\|:|$))/i;

// `::SetValue(key, name, value)` is the static form. `.SetValue(name, value)` is a key object's, but
// the static call is also written with a dot (`Registry.SetValue(…)`, C#): it is read as
// (key, name, value) as well when its first argument is not a literal or is a key path (#3047).
function setValueSpans(text: string, vars: PsVariables): Span[] {
  const spans: Span[] = [];
  const re = new RegExp(SET_VALUE_RE.source, "gi");
  for (let m = re.exec(text); m; m = re.exec(text)) {
    // `]::` and `$key.` are PowerShell (backtick escapes); a bare dotted call may be C#.
    const ps = m[1] !== "." || /\$[\w:]+$/.test(text.slice(Math.max(0, m.index - 64), m.index));
    const starts: number[] = [];
    const args = callArgs(text, re.lastIndex, { ps }, starts);
    const firsts = m[1] === "." ? [0] : [1];
    if (m[1] === "." && (!args[0] || KEY_PATH_RE.test(text.slice(args[0][0], args[0][1])))) firsts.push(1);
    for (const first of firsts) {
      const name = args[first];
      // A non-literal value may be a `$variable` assigned a literal earlier (#3054).
      const arg = args[first + 1];
      const value = arg
        ? beforeCue(text, arg)
        : ps && starts[first + 1]
          ? vars.literal(starts[first + 1])
          : null;
      if (name && value && isRegistryCredentialName(psNameText(text, name, ps))) spans.push(value);
    }
  }
  return spans;
}

// A hashtable entry `Name = …` or `Value = …` (key bare or quoted), after `{`, `;` or a line break.
// The separator is matched, not looked behind for: a lookbehind over `[ \t]*` would rescan a long
// run of spaces from every position in it.
// A JSON-escaped `\n` / `\r` separates entries too (a hashtable in a ScriptBlockText, #3057).
const HASH_ENTRY_RE = /(?:[{;\n]|\\[nr])[ \t]*(["']?)(Name|Value)\1[ \t]*=[ \t]*/gi;

// The hashtables worth reading: the nearest `@{` before each `Name =` entry, within the window. The
// search starts from the entries, so a long script with many hashtables and no Name stays linear.
function splatStarts(text: string): number[] {
  const starts = new Set<number>();
  const re = new RegExp(HASH_ENTRY_RE.source, "gi");
  // The last `@{` before each entry, found by walking the openers forward with the entries: a
  // backward search per entry rescanned a long hashtable once per entry (#3057).
  let at = -1;
  let next = text.indexOf("@{");
  for (let m = re.exec(text); m; m = re.exec(text)) {
    if (m[2].toLowerCase() !== "name") continue;
    while (next !== -1 && next <= m.index) {
      at = next;
      next = text.indexOf("@{", next + 1);
    }
    if (at !== -1 && m.index - at <= COMMAND_WINDOW) starts.add(at);
  }
  return [...starts];
}

function splatSpans(text: string, vars: PsVariables): Span[] {
  const spans: Span[] = [];
  for (const at of splatStarts(text)) {
    const end = objectEnd(text, at + 2, Math.min(text.length, at + COMMAND_WINDOW));
    // The entries are searched inside this hashtable only.
    const body = text.slice(at + 1, end);
    const re = new RegExp(HASH_ENTRY_RE.source, "gi");
    let name: string | null = null;
    let value: Span | null = null;
    let valueAt = -1;
    for (let m = re.exec(body); m; m = re.exec(body)) {
      const v = at + 1 + re.lastIndex;
      const here = text[v] === "@" ? readHereString(text, v, end) : null;
      const q = here ?? readValueQuoted(text, v, { escapes: false });
      // A here-string may run past the window (#3057); a quoted value ends inside the hashtable.
      const walked = q && q.after > q.span[1] && (here || q.span[1] <= end) ? q.span : null;
      const widened = walked && !here ? widen(text, v, walked, { ps: true }, ";}\r\n", end) : walked;
      const more = q && widened && widened === walked && !here ? concatEnd(text, q.after, end) : null;
      const span: Span | null = more && widened ? [widened[0], more.span[1]] : widened;
      if (m[2].toLowerCase() === "name") name ??= span ? psNameText(text, span, true) : "";
      else if (!(value ??= span) && valueAt < 0) valueAt = v;
    }
    const data = value ? beforeCue(text, value) : valueAt < 0 ? null : vars.literal(valueAt);
    if (name && data && isRegistryCredentialName(name)) spans.push(data);
  }
  return spans;
}

export const REG_COMMAND_PATTERNS: readonly RegExp[] = [
  REG_ADD.start,
  REG_ADD.name,
  REG_ADD.data,
  PS_SET_PROPERTY.start,
  PS_SET_PROPERTY.name,
  PS_SET_PROPERTY.data,
  PS_PATH,
  PS_SWITCH,
  PS_VALUED,
  NEXT_COMMAND,
  ESCAPED_CUE,
  SET_VALUE_RE,
  KEY_PATH_RE,
  HASH_ENTRY_RE,
];

export function commandSpans(text: string, placeholder: string): Span[] {
  const spans: Span[] = [];
  // A variable's literal is cut before a cue once, however many uses it has.
  const vars = psVariables(text, (span) => beforeCue(text, span));
  for (const g of [REG_ADD, PS_SET_PROPERTY]) {
    const re = new RegExp(g.start.source, "gi");
    for (let m = re.exec(text); m; m = re.exec(text)) {
      if (!startOk(text, m.index)) continue;
      let r: PsResult = { span: null, after: re.lastIndex, more: true };
      while (r.more) {
        const at = r.after;
        r =
          g === REG_ADD ? { ...commandSpan(text, at, g, vars), more: false } : psCommandSpan(text, at, vars);
        if (r.span) spans.push(r.span);
        if (r.after <= at) break;
      }
      // A command read ends at its value: a later one quoted on the same line is read too (#3060).
      const done = r.span && r.span[1] > re.lastIndex ? Math.min(r.after, r.span[1]) : r.after;
      re.lastIndex = Math.max(re.lastIndex, r.resume ?? done);
    }
  }
  return [...spans, ...setValueSpans(text, vars), ...splatSpans(text, vars)].filter(
    (s) => s[1] > s[0] && !text.startsWith(placeholder, s[0]),
  );
}
