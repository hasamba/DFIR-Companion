import { isRegistryCredentialName } from "./anonSecretKeys.js";
import { readQuotedField } from "./anonSecretRegCommands.js";
import type { Span } from "./anonSecretValues.js";

// `.reg` export bodies (`reg export` / `reg import`) under a section header (#3051):
//   [HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon]
//   "DefaultPassword"="<pw>"
//   "DefaultPassword"=hex(1):48,00,75,00,\
//     6e,00,74,00
// The keyed pass already hides the plain `"DefaultPassword"="<pw>"` line. It does not read the same
// body inside a JSON string (`\"DefaultPassword\"=\"<pw>\"`, lines joined by `\n`), and it takes
// only `hex(1` of a hex value, leaving the UTF-16 bytes of the password in clear. Each value line is
// one record: the data is that line's string, or its hex bytes through the `\` continuations, never
// the next value line or section. The name test is isRegistryCredentialName, so a security setting
// or persistence value keeps its data here.

// A section header at a line start (raw, or a JSON-escaped `\n`, or the start of a JSON string).
const SECTION_RE = /(?:^|\n|\\n|")[ \t]*\[-?(?:HKEY_|HK(?:LM|CU|CR|CC|U)\\)/g;
// A value line: the quoted name at a line start, then `=`.
// The quote may be escaped once (`\"`) or twice or three times (3 or 7 backslashes, #3061).
const VALUE_LINE_RE =
  /(?:^|\n|\\n)[ \t]*((?<!\\)\\{7}"|(?<!\\)\\{3}"|(?<!\\)\\"|")([^"\\\r\n]{1,255})\1[ \t]*=[ \t]*/g;
// Hex data: `hex:` / `hex(n):`, or what the keyed pass left of it (`"<placeholder>"):` for hex(n),
// `"<placeholder>",` for hex:), then the bytes, a continuation being `,\` + a line break (raw, or
// `\\` + `\n` in a JSON string).
const HEX_BYTE = /[0-9A-Fa-f]{2}/y;
const HEX_NEXT = /,[ \t]*(?:\\{1,2}(?:\r?\n|(?:\\r)?\\n)[ \t]*)?[0-9A-Fa-f]{2}/y;
const escapeRe = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

export const REG_FILE_PATTERNS: readonly RegExp[] = [SECTION_RE, VALUE_LINE_RE, HEX_BYTE, HEX_NEXT];

function hexHead(placeholder: string): RegExp {
  return new RegExp(
    `hex(?:\\([0-9A-Fa-f]{1,2}\\))?:|"?${escapeRe(placeholder)}"?(?:\\):|,(?=[0-9A-Fa-f]{2}))`,
    "y",
  );
}

function hexSpan(text: string, at: number, head: RegExp): Span | null {
  head.lastIndex = at;
  if (!head.exec(text)) return null;
  HEX_BYTE.lastIndex = head.lastIndex;
  if (!HEX_BYTE.exec(text)) return null;
  let end = HEX_BYTE.lastIndex;
  for (HEX_NEXT.lastIndex = end; HEX_NEXT.exec(text); HEX_NEXT.lastIndex = end) end = HEX_NEXT.lastIndex;
  return [at, text[end] === "," ? end + 1 : end];
}

/** The data spans of stored-credential values in `.reg` bodies that sit under a section header. */
export function regFileSpans(text: string, placeholder: string): Span[] {
  const spans: Span[] = [];
  const re = new RegExp(VALUE_LINE_RE.source, "g");
  const section = new RegExp(SECTION_RE.source, "g");
  const head = hexHead(placeholder);
  let firstSection: number | null = null;
  for (let m = re.exec(text); m; m = re.exec(text)) {
    if (!isRegistryCredentialName(m[2])) continue;
    firstSection ??= section.exec(text)?.index ?? text.length;
    if (firstSection >= m.index) continue;
    const at = re.lastIndex;
    // A string value (an unterminated one runs to its line end, as readQuoted reads it), unless the
    // keyed pass already hid it; then the hex bytes after the keyed pass's placeholder, if any.
    const quoted = text.startsWith(m[1], at) ? readQuotedField(text, at) : null;
    const str = quoted && !text.startsWith(placeholder, quoted.span[0]) ? quoted.span : null;
    const span = str ?? hexSpan(text, at, head);
    if (span && span[1] > span[0]) spans.push(span);
  }
  return spans;
}
