// The two transforms every Velociraptor launch applies to VQL before it is sent (launchHunt,
// collectOnClient). They live here, not in integrations/, so Watson's launch check
// (analysis/ai/watson/velo/launchCheck.ts) can check exactly the statements that will run.

// Velociraptor VQL has no duration-suffix literals (30d, 7h, 2w, etc.). AI models sometimes
// generate them by analogy with other query languages. Rewrite any that appear in arithmetic
// context (after + or -) to seconds so artifact_set does not reject the query at parse time.
// Never inside a string literal or a comment (Watson Task 9 review I-2): the rewrite once turned an
// approved argv "…/report-1h" into "…/report- 1 * 3600", so the text run was not the text approved.
const rewriteDurations = (code: string): string =>
  code
    .replace(/([-+])\s*(\d+)w\b/g, "$1 $2 * 604800")
    .replace(/([-+])\s*(\d+)d\b/g, "$1 $2 * 86400")
    .replace(/([-+])\s*(\d+)h\b/g, "$1 $2 * 3600")
    .replace(/([-+])\s*(\d+)m\b/g, "$1 $2 * 60");

/** End index of the string literal or comment starting at `i`, or -1 when none starts there. */
function opaqueEnd(src: string, i: number): number {
  const until = (close: string, from: number, keep: number): number => {
    const at = src.indexOf(close, from);
    return at < 0 ? src.length : at + keep;
  };
  if (src.startsWith("'''", i)) return until("'''", i + 3, 3);
  if (src.startsWith("--", i) || src.startsWith("//", i)) return until("\n", i + 2, 0);
  if (src.startsWith("/*", i)) return until("*/", i + 2, 2);
  const q = src[i];
  if (q !== "'" && q !== '"') return -1;
  let j = i + 1;
  while (j < src.length && src[j] !== q) j += src[j] === "\\" ? 2 : 1;
  return Math.min(j + 1, src.length);
}

export function sanitizeVqlDurations(vql: string): string {
  const src = String(vql || "");
  let out = "";
  let code = 0; // start of the current code run
  for (let i = 0; i < src.length;) {
    const end = opaqueEnd(src, i);
    if (end < 0) {
      i++;
      continue;
    }
    out += rewriteDurations(src.slice(code, i)) + src.slice(i, end);
    code = i = end;
  }
  return out + rewriteDurations(src.slice(code));
}

// Split a VQL blob (e.g. the notebook pivots, separated by blank lines) into individual statements
// and STRIP comment lines. Critical for the CLI: a query passed to `velociraptor query` that begins
// with a `-- comment` is parsed by the flag lexer as an unknown long flag ("--"), so each statement
// must start with real VQL. Comment-only chunks are dropped. Each statement becomes its own
// positional `query` arg (the command is variadic), so multiple pivots run in one invocation.
export function splitVqlStatements(vql: string): string[] {
  return String(vql || "")
    .split(/\n\s*\n/)
    .map((chunk) =>
      chunk
        .split(/\r?\n/)
        .filter((line) => line.trim() && !line.trim().startsWith("--")) // drop pure-comment lines
        .join("\n")
        .trim(),
    )
    .filter(Boolean);
}

// Characters a launch refuses ANYWHERE, inside string literals too (final re-review I-1): every C0
// control except tab and newline, DEL, every C1 control (U+0080-U+009F, NEL among them), the Unicode
// line and paragraph separators, and the zero-width / byte-order marks. YAML reads U+0085, U+2028
// and U+2029 as line breaks, but the artifact builder indents only after "\n", so one of them in a
// string would end the `query: |` block and let the rest of the line become artifact YAML.
// Also every Unicode format character (\p{Cf}: bidi overrides and isolates, LRM/RLM, soft hyphen,
// word joiner, tag characters…), the Hangul fillers, the Mongolian vowel separator and every
// variation selector: each is invisible or reorders text, so the query an analyst reads on a card
// could differ from the one that runs ("Trojan Source"; Watson Task 9 review I-1).
const UNSAFE_CHAR =
  /[\u0000-\u0008\u000B-\u001F\u007F-\u009F\u2028\u2029\p{Cf}\u115F\u180E\u3164\uFFA0]|\u1160|\p{Variation_Selector}/u;

/** The plain-English refusal for VQL holding such a character, or null when it has none. */
export function unsafeVqlCharProblem(vql: string): string | null {
  const m = UNSAFE_CHAR.exec(String(vql ?? ""));
  if (!m) return null;
  const code = `U+${(m[0].codePointAt(0) ?? 0).toString(16).toUpperCase().padStart(4, "0")}`;
  return (
    `the VQL contains an invisible control or line-break character (${code}) that Velociraptor ` +
    "could read differently from what was checked; retype the query without it"
  );
}
