// Does a log sink's filter route all four Cloud Audit Logs of this project? (#2314) Pure.
//
// A STRICT ALLOWLIST, never a heuristic. The Logging query language joins adjacent terms with an
// implicit AND (a second line is a second, narrowing condition), and an audit-log hostname can sit
// in any field, so a substring search over the filter proves nothing. Only these shapes are read:
//
//   (empty)                                        every log
//   logName:"cloudaudit.googleapis.com"            a `has` (substring) term on logName
//   logName="projects/<p>/logs/cloudaudit.googleapis.com%2F<log>"   an exact term (%2F or /)
//   logName=("…" OR "…")                           one operator over an OR-group of values
//   T OR T OR …   /   ( T OR T OR … )              an OR-group of the above, optionally parenthesised
//
// Whitespace (newlines included) is normalised first. Anything else — AND, NOT, `-`, another field,
// a comparison other than `=` / `:` — is unprovable, and the sink is rejected.

import type { GcpAuditLog } from "./gcpFilter.js";

export const UNPROVABLE_FILTER = "its filter cannot be proven to keep every audit entry";

interface Term {
  op: "=" | ":";
  value: string;
}

const VALUE = String.raw`(?:"((?:[^"\\]|\\.)*)"|([A-Za-z0-9._%/-]+))`;
const OR = String.raw`\s+OR\s+`;
const TERM = new RegExp(String.raw`^logName\s*(=|:)\s*(?:\(\s*(${VALUE}(?:${OR}${VALUE})*)\s*\)|${VALUE})`);
const ONE_VALUE = new RegExp(`^${VALUE}`);

const unquote = (quoted: string | undefined, bare: string | undefined): string =>
  quoted !== undefined ? quoted.replace(/\\(.)/g, "$1") : (bare ?? "");

/** The values of an OR-group `"a" OR "b" OR c`, or null when it is anything else. */
function groupValues(text: string): string[] | null {
  const out: string[] = [];
  let rest = text;
  for (;;) {
    const m = ONE_VALUE.exec(rest);
    if (!m) return null;
    out.push(unquote(m[1], m[2]));
    rest = rest.slice(m[0].length);
    if (!rest) return out;
    const sep = new RegExp(`^${OR}`).exec(rest);
    if (!sep) return null;
    rest = rest.slice(sep[0].length);
  }
}

/** Parse `T OR T OR …` from the start; null when the whole text is not exactly that. */
function parseTerms(text: string): Term[] | null {
  const terms: Term[] = [];
  let rest = text;
  for (;;) {
    const m = TERM.exec(rest);
    if (!m) return null;
    const op = m[1] as Term["op"];
    // Groups: 1 op, 2 a parenthesised value group (3–6 inside it), 7/8 a single quoted/bare value.
    const values = m[2] !== undefined ? groupValues(m[2]) : [unquote(m[7], m[8])];
    if (!values) return null;
    terms.push(...values.map((value) => ({ op, value })));
    rest = rest.slice(m[0].length);
    if (!rest) return terms;
    const sep = new RegExp(`^${OR}`).exec(rest);
    if (!sep) return null;
    rest = rest.slice(sep[0].length);
  }
}

function parseFilter(normalised: string): Term[] | null {
  const direct = parseTerms(normalised);
  if (direct) return direct;
  const wrapped = /^\(\s*(.*?)\s*\)$/.exec(normalised);
  return wrapped ? parseTerms(wrapped[1]) : null;
}

/** Does one term keep every entry of `log`? */
function termCovers(term: Term, projectId: string, log: GcpAuditLog): boolean {
  const names = [
    `projects/${projectId}/logs/cloudaudit.googleapis.com%2F${log}`,
    `projects/${projectId}/logs/cloudaudit.googleapis.com/${log}`,
  ];
  if (term.op === "=") return names.includes(term.value);
  // `has` on a string: a value that is part of the log's full name keeps all of that log.
  return term.value.length > 0 && names.some((n) => n.includes(term.value));
}

/** Which audit logs the filter does not route; `unprovable` when it is not an allowlisted shape. */
export function sinkFilterMisses(
  filter: string | undefined,
  projectId: string,
  logs: readonly GcpAuditLog[],
): { missing: GcpAuditLog[]; unprovable?: string } {
  const normalised = (filter ?? "").replace(/\s+/g, " ").trim();
  if (!normalised) return { missing: [] };
  const terms = parseFilter(normalised);
  if (!terms) return { missing: [...logs], unprovable: UNPROVABLE_FILTER };
  return { missing: logs.filter((log) => !terms.some((t) => termCovers(t, projectId, log))) };
}
