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
// The check is structural, not a grammar: it walks the text once, tracking VQL string literals
// (single- or double-quoted, backslash escapes honored) so a quote INSIDE a literal is fine, and
// outside literals it requires that
//   - every `(` is closed and no `)` closes more than was opened (depth never dips below zero);
//   - no statement separator `;` appears anywhere, not just at the end;
//   - no comment marker (`--`, `/*`) can hide a trailing fragment from the reader;
//   - every literal is closed, so a lone quote cannot swallow the wrapper's `)` and `LIMIT`.
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
export const MAX_VQL_LENGTH = 100_000;
export const VQL_TOO_LONG = `vql is too long (limit ${MAX_VQL_LENGTH} characters)`;

/** Newline-collapsed, trailing-`;` trimmed, length-capped — the normalization both callers apply. */

export function normalizeWhereText(where: string): string {
  return where
    .replace(/[\r\n]+/g, " ")
    .replace(/;+\s*$/, "")
    .trim()
    .slice(0, MAX_WHERE_LENGTH);
}

/**
 * Is `where` safe to inline as `WHERE (${where})` — one contained boolean expression, with no way
 * to close the wrapper, start another statement, or comment the rest of the query away?
 */
export function isContainedWhereExpression(where: string): boolean {
  let depth = 0;
  let quote: string | null = null;
  for (let i = 0; i < where.length; i++) {
    const c = where[i];
    if (quote) {
      if (c === "\\") {
        i++; // the escaped character, whatever it is, stays inside the literal
        continue;
      }
      if (c === quote) quote = null;
      continue;
    }
    if (c === "'" || c === '"') {
      quote = c;
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
  return depth === 0 && quote === null;
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
