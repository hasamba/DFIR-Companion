// The two transforms every Velociraptor launch applies to VQL before it is sent (launchHunt,
// collectOnClient). They live here, not in integrations/, so Watson's launch check
// (analysis/ai/watson/velo/launchCheck.ts) can check exactly the statements that will run.

// Velociraptor VQL has no duration-suffix literals (30d, 7h, 2w, etc.). AI models sometimes
// generate them by analogy with other query languages. Rewrite any that appear in arithmetic
// context (after + or -) to seconds so artifact_set does not reject the query at parse time.
// Only operates in operator context to avoid touching unrelated "d"/"h" inside string literals
// such as file paths (e.g. "C:/logs/30day_archive/").
export function sanitizeVqlDurations(vql: string): string {
  return String(vql || "")
    .replace(/([-+])\s*(\d+)w\b/g, "$1 $2 * 604800")
    .replace(/([-+])\s*(\d+)d\b/g, "$1 $2 * 86400")
    .replace(/([-+])\s*(\d+)h\b/g, "$1 $2 * 3600")
    .replace(/([-+])\s*(\d+)m\b/g, "$1 $2 * 60");
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
const UNSAFE_CHAR = /[\u0000-\u0008\u000B-\u001F\u007F-\u009F\u200B-\u200D\u2028\u2029\uFEFF]/u;

/** The plain-English refusal for VQL holding such a character, or null when it has none. */
export function unsafeVqlCharProblem(vql: string): string | null {
  const m = UNSAFE_CHAR.exec(String(vql ?? ""));
  if (!m) return null;
  const code = `U+${m[0].charCodeAt(0).toString(16).toUpperCase().padStart(4, "0")}`;
  return (
    `the VQL contains an invisible control or line-break character (${code}) that Velociraptor ` +
    "could read differently from what was checked; retype the query without it"
  );
}
