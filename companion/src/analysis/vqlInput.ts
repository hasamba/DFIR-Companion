// Limits and containment checks for analyst-authored VQL before it reaches a program or the CLI.
//
// ── An inlined WHERE expression ──────────────────────────────────────────────────────────────────
// Two callers inline such an expression into a query they build themselves, as `WHERE (${where})`:
// the bundle store persists one per artifact (POST /velociraptor/bundles), and the Velociraptor
// client reads it back into hunt_results()/source() programs. The parentheses are what keep the
// expression a single operand of the query — but only if the expression cannot close them. Both
// callers used to strip newlines and a TRAILING semicolon and stop there, so a value could carry
// `x) LIMIT 1; SELECT * FROM execve(argv=['sh', '-c', 'id']) WHERE (1=1` and the wrapper became
// a multi-statement program (#843, #853).
//
// The check is structural, not a grammar: it walks the text once, tracking VQL string literals so
// a quote INSIDE a literal is fine, and outside literals it requires that
//   - every `(` is closed and no `)` closes more than was opened (depth never dips below zero);
//   - no statement separator `;` appears anywhere, not just at the end;
//   - no comment marker (`--`, `/*`) can hide a trailing fragment from the reader;
//   - every literal is closed, so a lone quote cannot swallow the wrapper's `)` and `LIMIT`.
// VQL has three literal forms and the scanner has to see each the way VQL's own lexer does, or its
// idea of "inside a string" drifts from the parser's and the wrapper-closing `)` hides in the gap:
//   - `'…'` and `"…"`, where a backslash escapes the next character (so `\'` does not close);
//   - `'''…'''`, a RAW string: no escapes at all, a backslash is a byte and only the next `'''`
//     ends it. Treating a backslash inside one as an escape let `'''a\'''` swallow the closing
//     delimiter and desynchronize the scanner, so `'''a\''' = "x" OR 1=1) SELECT … WHERE ('''b'''`
//     read as balanced and the smuggled statement went through.
// A backtick-quoted identifier is opaque the same way: a `)` inside `` `odd)name` `` is part of
// the name, not a parenthesis.
// A legitimate filter — `NOT OSPath =~ 'pagefile'`, `Size > 1024 AND (Name =~ 'a' OR Name =~ 'b')`
// — passes untouched. The check refuses; it never rewrites, because a rewritten filter would
// silently match a different set of rows than the analyst asked for.

export const MAX_WHERE_LENGTH = 1000;

/** The refusal both callers raise; the bundle store prefixes the artifact it applies to. */
export const INVALID_WHERE_FILTER =
  "invalid WHERE filter: must be one boolean expression — balanced parentheses and quotes, no ';' or comment markers";

// ── A whole VQL program ──────────────────────────────────────────────────────────────────────────
// The most VQL one request may carry (#825, #828). The program reaches the Velociraptor CLI as
// argv, and Linux caps a single argument at 128 KiB — so anything past that could never run, and
// used to fail only deep inside the spawn with an E2BIG nobody could act on. Well above any
// compiled Sigma hunt or pivot program; the only thing it refuses is the body-parser limit
// (256 MB by default) being spent on one query.
//
// Measured in UTF-8 BYTES, which is what the kernel counts: a JavaScript `length` is UTF-16 code
// units, so 50,000 three-byte characters read as "50,000 long" while weighing 150,000 bytes —
// past the ceiling and still through a character-counted check.
export const MAX_VQL_BYTES = 100_000;
export const VQL_TOO_LONG = `vql is too long (limit ${MAX_VQL_BYTES} bytes of UTF-8)`;

/** The refusal for a VQL program a request carries, or null when its size is fine. */
export function vqlSizeProblem(vql: string): string | null {
  return Buffer.byteLength(vql, "utf8") > MAX_VQL_BYTES ? VQL_TOO_LONG : null;
}

/** Newline-collapsed, trailing-`;` trimmed, length-capped — the normalization both callers apply. */
export function normalizeWhereText(where: string): string {
  return where
    .replace(/[\r\n]+/g, " ")
    .replace(/;+\s*$/, "")
    .trim()
    .slice(0, MAX_WHERE_LENGTH);
}

const RAW = "'''";

/**
 * Is `where` safe to inline as `WHERE (${where})` — one contained boolean expression, with no way
 * to close the wrapper, start another statement, or comment the rest of the query away?
 */
export function isContainedWhereExpression(where: string): boolean {
  let depth = 0;
  // The delimiter that closes the literal we are inside: `'`, `"`, `'''` or a backtick.
  let closer: string | null = null;
  for (let i = 0; i < where.length; i++) {
    const c = where[i];
    if (closer !== null) {
      if (closer === RAW || closer === "`") {
        // Raw: a backslash is a byte; only the delimiter itself ends the literal.
        if (where.startsWith(closer, i)) {
          i += closer.length - 1;
          closer = null;
        }
        continue;
      }
      if (c === "\\") {
        i++; // the escaped character, whatever it is, stays inside the literal
        continue;
      }
      if (c === closer) closer = null;
      continue;
    }
    if (where.startsWith(RAW, i)) {
      closer = RAW;
      i += RAW.length - 1;
      continue;
    }
    if (c === "'" || c === '"' || c === "`") {
      closer = c;
      continue;
    }
    if (c === ";") return false;
    if (c === "(") depth++;
    else if (c === ")") {
      depth--;
      if (depth < 0) return false;
    } else if (c === "-" && where[i + 1] === "-") return false;
    else if (c === "/" && where[i + 1] === "*") return false;
  }
  return depth === 0 && closer === null;
}

/**
 * Normalize and check in one step: the text safe to inline, or a throw whose message starts with
 * `label` (the bundle store names the artifact the filter applies to).
 */
export function containedWhereOrThrow(where: string, label = "invalid WHERE filter"): string {
  const w = normalizeWhereText(where);
  if (w && !isContainedWhereExpression(w)) {
    throw new Error(INVALID_WHERE_FILTER.replace("invalid WHERE filter", label));
  }
  return w;
}
