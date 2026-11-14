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
