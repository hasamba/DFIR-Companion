import type { VqlToken } from "./vqlTokens.js";
import { has, isPunct, lc, type LetDef } from "./vqlHelpers.js";
import {
  ALLOWED_ACCESSORS,
  BLOCKED_ARG,
  FILE_READ_CALLS,
  PATH_ARGS,
  QUERY_ARGS,
  VQL_KEYWORDS,
  WMI_CLASSES,
  isCredentialName,
} from "./vqlAllowlist.js";

// Argument- and literal-level checks for Watson's VQL allowlist (security review round 1). Every
// argument of every call must be `name=value` (positional arguments are refused until vfilter's
// handling is verified); paths given to file reads and every artifact argument must be plain
// literals; query-like arguments may not be strings; wmi takes one literal SELECT from a reviewed
// class; and no string literal may look like a network path, a delegate pathspec or a lambda.

interface Arg {
  name: VqlToken | null;
  value: VqlToken[];
}

const OPEN = ["(", "[", "{"];
const CLOSE = [")", "]", "}"];

/** The dotted callee name whose last segment is token `i`. */
function calleeName(toks: readonly VqlToken[], i: number): string {
  const parts = [toks[i].text];
  let j = i;
  while (
    isPunct(toks[j - 1], ".") &&
    toks[j - 2]?.kind === "ident" &&
    toks[j - 1].start === toks[j - 2].end
  ) {
    parts.unshift(toks[j - 2].text);
    j -= 2;
  }
  return parts.join(".");
}

/** The arguments of the call whose `(` is token `k`, or null when the brackets do not balance. */
function splitArgs(toks: readonly VqlToken[], k: number): Arg[] | null {
  const slices: VqlToken[][] = [[]];
  let depth = 0;
  for (let i = k + 1; i < toks.length; i++) {
    const t = toks[i];
    if (depth === 0 && isPunct(t, ")")) {
      const empty = slices.length === 1 && slices[0].length === 0;
      return empty ? [] : slices.map(toArg);
    }
    if (depth === 0 && isPunct(t, ",")) {
      slices.push([]);
      continue;
    }
    if (OPEN.some((o) => isPunct(t, o))) depth++;
    if (CLOSE.some((c) => isPunct(t, c))) depth--;
    if (depth < 0) return null;
    slices[slices.length - 1].push(t);
  }
  return null;
}

function toArg(slice: VqlToken[]): Arg {
  const named = slice.length >= 3 && slice[0].kind === "ident" && isPunct(slice[1], "=");
  return named ? { name: slice[0], value: slice.slice(2) } : { name: null, value: slice };
}

const isLiteral = (v: readonly VqlToken[]): boolean => v.length === 1 && v[0].kind === "string";

/** One string literal, or `[ 'a', 'b' ]` of string literals. */
function isLiteralList(v: readonly VqlToken[]): boolean {
  if (isLiteral(v)) return true;
  if (v.length < 3 || !isPunct(v[0], "[") || !isPunct(v[v.length - 1], "]")) return false;
  const inner = v.slice(1, -1);
  if (inner.length % 2 === 0) return false; // empty, or a trailing comma
  return inner.every((t, i) => (i % 2 === 0 ? t.kind === "string" : isPunct(t, ",")));
}

const literalValues = (v: readonly VqlToken[]): string[] =>
  v.filter((t) => t.kind === "string").map((t) => t.value ?? "");

/**
 * A path literal that could reach another machine anywhere in it: two separators in a row of either
 * kind (`//`, `\\\\`, `/\\`, `\\/` — Windows reads `/` and `\\` alike), or a
 * `{a,b}` glob alternation holding a path separator (which can hide a UNC root).
 */
function pathLiteralProblem(v: readonly VqlToken[], name: string): string | null {
  for (const s of literalValues(v)) {
    if (/[\\/]{2}/.test(s)) return `${name} holds two path separators in a row (a possible network path)`;
    if (/^[\\/]+$/.test(s)) return `${name} is a bare separator (it could join into a network path)`;
    if (/\[[^\]]*[\\/][^\]]*\]/.test(s)) return `${name} has a [...] class holding a path separator`;
    if (/\{[^}]*[\\/][^}]*\}/.test(s)) return `${name} has a {…} alternation holding a path separator`;
  }
  return null;
}

/** `{ … }` spanning the whole value. */
function isSubquery(v: readonly VqlToken[]): boolean {
  if (!isPunct(v[0], "{") || !isPunct(v[v.length - 1], "}")) return false;
  let depth = 0;
  for (let i = 0; i < v.length; i++) {
    if (OPEN.some((o) => isPunct(v[i], o))) depth++;
    if (CLOSE.some((c) => isPunct(v[i], c))) depth--;
    if (depth === 0 && i < v.length - 1) return false;
  }
  return true;
}

const WQL = /^\s*select\s+[\s\S]+?\s+from\s+([A-Za-z0-9_]+)\s*(?:where\b[\s\S]*)?$/i;

function wmiProblem(value: readonly VqlToken[]): string | null {
  const bad = "wmi needs one quoted WQL SELECT from a reviewed read-only class";
  if (!isLiteral(value)) return bad;
  const q = value[0].value ?? "";
  const m = WQL.exec(q);
  if (!m || (q.match(/\bfrom\b/gi) ?? []).length !== 1) return bad;
  return has(WMI_CLASSES, m[1]) ? null : `wmi class ${m[1]} is not on Watson's read-only list`;
}

function argProblem(callee: string, arg: Arg, lets: ReadonlyMap<string, LetDef>): string | null {
  if (!arg.name) return `${callee} has a positional argument (every argument must be name=value)`;
  const name = arg.name.text;
  const lname = lc(name);
  const v = arg.value;
  const isArtifact = lc(callee).startsWith("artifact.");
  if (BLOCKED_ARG.test(name)) return `argument ${name} is refused (uploads, dumps and lambdas)`;
  if (lname === "accessor") {
    const ok = isLiteral(v) && has(ALLOWED_ACCESSORS, v[0].value ?? "");
    return ok ? null : `accessor must be one quoted local accessor (${ALLOWED_ACCESSORS.join(", ")})`;
  }
  if (lname === "namespace") return "a namespace argument is refused";
  if (lc(callee) === "wmi" && lname === "query") return wmiProblem(v);
  if (has(QUERY_ARGS, lname)) {
    const letName = v.length === 1 && v[0].kind === "ident" && lets.get(v[0].text)?.callable === true;
    return isSubquery(v) || letName ? null : `argument ${name} must be a {subquery} or a LET query name`;
  }
  if (isArtifact) {
    if (isCredentialName(name)) return `argument ${name} would set a config or credential variable`;
    if (!isLiteralList(v)) return `artifact argument ${name} must be a plain quoted value`;
    return pathLiteralProblem(v, name);
  }
  if (lc(callee) === "yara" && lname === "rules") {
    if (!isLiteralList(v)) return "yara rules must be a plain quoted value";
    return literalValues(v).some((s) => /\binclude\b/i.test(s))
      ? "yara rules may not include other files"
      : null;
  }
  if (has(FILE_READ_CALLS, callee) && has(PATH_ARGS, lname)) {
    if (!isLiteralList(v))
      return `${callee} argument ${name} must be a plain quoted path (no paths built at run time)`;
    return pathLiteralProblem(v, name);
  }
  return null;
}

/** glob(root='/', globs='/host/s') joins to `//host/s`. */
function rootJoinProblem(args: readonly Arg[]): boolean {
  const values = (n: string): string[] =>
    args.filter((a) => a.name && lc(a.name.text) === n).flatMap((a) => literalValues(a.value));
  const roots = values("root");
  if (roots.length === 0) return false;
  const rootEnds = roots.some((r) => r === "" || /[\\/]$/.test(r));
  return rootEnds && values("globs").some((g) => /^[\\/]/.test(g));
}

/** Checks the arguments of every call. `defSites` are LET definition names (their `(` is a parameter list). */
export function checkCallArgs(
  toks: readonly VqlToken[],
  lets: ReadonlyMap<string, LetDef>,
  defSites: ReadonlySet<number>,
  reasons: Set<string>,
): void {
  for (let k = 1; k < toks.length; k++) {
    const prev = toks[k - 1];
    if (
      !isPunct(toks[k], "(") ||
      prev.kind !== "ident" ||
      has(VQL_KEYWORDS, prev.text) ||
      defSites.has(k - 1)
    ) {
      continue;
    }
    const callee = calleeName(toks, k - 1);
    const args = splitArgs(toks, k);
    if (!args) {
      reasons.add(`${callee}( has unbalanced brackets`);
      continue;
    }
    if (args.some((a) => a.value.length === 0)) reasons.add(`${callee} has an empty argument`);
    for (const arg of args) {
      const problem = argProblem(callee, arg, lets);
      if (problem) reasons.add(problem);
    }
    if (lc(callee) === "glob" && rootJoinProblem(args)) {
      reasons.add(
        "glob root ending in a separator joined to globs starting with one (a possible network path)",
      );
    }
    if (lc(callee) === "wmi" && !args.some((a) => a.name && lc(a.name.text) === "query")) {
      reasons.add("wmi needs one quoted WQL SELECT from a reviewed read-only class");
    }
  }
}

const NETWORK_START = /^(?:[\\/]{2}|(?:file|smb|https?|ftp):)/i;
const UNC_INFIX = /\\\\[?.]\\unc/i;

function stringProblem(t: VqlToken): string | null {
  const texts = [t.value ?? "", t.text.replace(/^('''|'|")/, "")];
  if (t.text.includes("=>")) return "a lambda string (=>), which VQL evaluates as code";
  for (const s of texts) {
    if (/delegate/i.test(s)) return "a string naming a delegate pathspec";
    if (/^\s*\{\s*"/.test(s)) return "a string holding a JSON pathspec";
    if (NETWORK_START.test(s.replace(/^[\s'"]+/, "")) || UNC_INFIX.test(s))
      return "a string that looks like a network path";
  }
  return null;
}

/** Checks every string literal. */
export function checkStrings(toks: readonly VqlToken[], reasons: Set<string>): void {
  for (const t of toks) {
    if (t.kind !== "string") continue;
    const problem = stringProblem(t);
    if (problem) reasons.add(problem);
  }
}
