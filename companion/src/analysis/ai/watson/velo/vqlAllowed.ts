import { vqlFingerprint } from "../../../huntOutcomes.js";
import { tokenizeVql, type VqlToken } from "./vqlTokens.js";
import {
  ALLOWED_ACCESSORS,
  ALLOWED_ARTIFACTS,
  ALLOWED_CALLS,
  BLOCKED_ARG,
  DENIED_NAMES,
  DYNAMIC_CALLS,
  VQL_KEYWORDS,
} from "./vqlAllowlist.js";

// Watson's launch gate for VQL (phase 3, decision P2): VQL is launched only when every call in it
// is on a reviewed read-only allowlist. Parsed, not pattern-matched — see vqlTokens.ts. Anything the
// check cannot classify with certainty is BLOCKED; the reasons name what was refused, for the turn.

export type VqlAllowed = { ok: true } | { ok: false; reasons: string[] };

const lc = (s: string): string => s.toLowerCase();
const has = (list: readonly string[], name: string): boolean => list.some((x) => lc(x) === lc(name));
const isPunct = (t: VqlToken | undefined, text: string): boolean => t?.kind === "punct" && t.text === text;
const isWord = (t: VqlToken | undefined, word: string): boolean => t?.kind === "ident" && lc(t.text) === word;

/** A WMI namespace on this machine: `root` or `root\<name>…`, one or two backslashes or `/`. */
const LOCAL_NAMESPACE = /^root(?:(?:\\{1,2}|\/)[a-z0-9_]+)*$/i;

interface NameUnit {
  segments: string[];
  first: number; // token index of the first segment
  last: number; // token index of the last segment
}

interface LetDef {
  callable: boolean;
}

/** `a.b.c` with no whitespace or comment around the dots, starting at token `i`. */
function readUnit(toks: readonly VqlToken[], i: number): NameUnit {
  const segments = [toks[i].text];
  let last = i;
  while (
    isPunct(toks[last + 1], ".") &&
    toks[last + 2]?.kind === "ident" &&
    toks[last + 1].start === toks[last].end &&
    toks[last + 2].start === toks[last + 1].end
  ) {
    segments.push(toks[last + 2].text);
    last += 2;
  }
  return { segments, first: i, last };
}

/** Index past a LET's `(p1, p2)` parameter list starting at `i`, or -1 when it is malformed. */
function skipParams(toks: readonly VqlToken[], i: number): number {
  let k = i + 1;
  while (k < toks.length && !isPunct(toks[k], ")")) {
    const ok = toks[k].kind === "ident" || isPunct(toks[k], ",");
    if (!ok) return -1;
    k++;
  }
  return k < toks.length ? k + 1 : -1;
}

/** Every `LET name [ (params) ] =|<= body`. Records definition sites so they are not read as calls. */
function collectLets(
  toks: readonly VqlToken[],
  reasons: Set<string>,
  defSites: Set<number>,
): Map<string, LetDef> {
  const lets = new Map<string, LetDef>();
  for (let i = 0; i < toks.length; i++) {
    if (!isWord(toks[i], "let")) continue;
    const nameTok = toks[i + 1];
    if (nameTok?.kind !== "ident" || isPunct(toks[i + 2], ".") || has(VQL_KEYWORDS, nameTok.text)) {
      reasons.add("a LET statement without a plain name");
      continue;
    }
    let k = i + 2;
    const hasParams = isPunct(toks[k], "(");
    if (hasParams) k = skipParams(toks, k);
    if (k < 0 || !(isPunct(toks[k], "=") || isPunct(toks[k], "<="))) {
      reasons.add(`LET ${nameTok.text} is malformed`);
      continue;
    }
    if (has(DENIED_NAMES, nameTok.text)) reasons.add(`LET ${nameTok.text} reuses the name of a built-in`);
    defSites.add(i + 1);
    lets.set(nameTok.text, { callable: hasParams || isWord(toks[k + 1], "select") });
  }
  return lets;
}

function artifactProblem(unit: NameUnit): string | null {
  const idx = unit.segments.findIndex((s) => lc(s) === "artifact");
  if (idx < 0) return null;
  if (idx > 0) return `${unit.segments.join(".")} reaches an artifact through another name`;
  const rest = unit.segments.slice(1).join(".");
  if (!rest) return "Artifact must be followed directly by .<Name>";
  if (!has(ALLOWED_ARTIFACTS, rest))
    return `the VQL calls artifact ${rest}, which is not on Watson's read-only list`;
  return null;
}

/** Why calling a single name is refused, or null when it is allowed. */
function callProblem(name: string, lets: ReadonlyMap<string, LetDef>): string | null {
  const def = lets.get(name);
  if (def) {
    if (!def.callable) return `LET ${name} is called but does not define a query`;
    if (!/[A-Z]/.test(name))
      return `LET ${name} is called but its name has no capital letter, so it could shadow a built-in`;
    return null;
  }
  if (has(ALLOWED_CALLS, name)) return null;
  if (has(DYNAMIC_CALLS, name))
    return `${name} is dynamic invocation (it evaluates a string or computed name as VQL)`;
  return `the VQL calls ${name}, which is not on Watson's read-only list`;
}

function checkNames(
  toks: readonly VqlToken[],
  lets: ReadonlyMap<string, LetDef>,
  defSites: ReadonlySet<number>,
  reasons: Set<string>,
): void {
  for (let i = 0; i < toks.length; i++) {
    if (toks[i].kind !== "ident") continue;
    const unit = readUnit(toks, i);
    i = unit.last;
    const afterFrom = isWord(toks[unit.first - 1], "from");
    if (isWord(toks[unit.first], "from") && toks[unit.first + 1]?.kind !== "ident") {
      reasons.add("FROM must name a plugin");
    }
    const artifact = artifactProblem(unit);
    if (artifact) reasons.add(artifact);
    if (defSites.has(unit.first)) continue;
    const isCall = isPunct(toks[unit.last + 1], "(") || afterFrom;
    if (!isCall || artifact || lc(unit.segments[0]) === "artifact") continue;
    const name = unit.segments.join(".");
    if (unit.segments.length > 1) {
      reasons.add(`the VQL calls ${name}, a dotted name that is not an allowed artifact`);
    } else if (has(VQL_KEYWORDS, name)) {
      if (afterFrom) reasons.add("FROM must name a plugin");
    } else {
      const problem = callProblem(name, lets);
      if (problem) reasons.add(problem);
    }
  }
}

/** `(x)(…)`, `'name'(…)`: calling the result of an expression. */
function checkCallTargets(toks: readonly VqlToken[], reasons: Set<string>): void {
  for (let k = 1; k < toks.length; k++) {
    if (!isPunct(toks[k], "(")) continue;
    const prev = toks[k - 1];
    if (prev.kind === "string" || prev.kind === "number" || [")", "]", "}"].some((p) => isPunct(prev, p))) {
      reasons.add("the VQL calls the result of an expression");
    }
  }
}

function literalArg(toks: readonly VqlToken[], k: number, accept: (v: string) => boolean): boolean {
  const v = toks[k + 2];
  const after = toks[k + 3];
  return v?.kind === "string" && accept(v.value ?? "") && (isPunct(after, ",") || isPunct(after, ")"));
}

/** Named arguments: `name=` right after `(` or `,`. */
function checkArgs(toks: readonly VqlToken[], reasons: Set<string>): void {
  for (let k = 1; k < toks.length; k++) {
    const t = toks[k];
    if (t.kind !== "ident" || !isPunct(toks[k + 1], "=")) continue;
    if (!(isPunct(toks[k - 1], "(") || isPunct(toks[k - 1], ","))) continue;
    if (BLOCKED_ARG.test(t.text)) reasons.add(`argument ${t.text} is refused (uploads, dumps and lambdas)`);
    if (lc(t.text) === "accessor" && !literalArg(toks, k, (v) => has(ALLOWED_ACCESSORS, v))) {
      reasons.add(`accessor must be one quoted local accessor (${ALLOWED_ACCESSORS.join(", ")})`);
    }
    if (lc(t.text) === "namespace" && !literalArg(toks, k, (v) => LOCAL_NAMESPACE.test(v))) {
      reasons.add("namespace must be one quoted local root namespace");
    }
  }
}

function checkStrings(toks: readonly VqlToken[], reasons: Set<string>): void {
  if (toks.some((t) => t.kind === "string" && t.text.includes("=>"))) {
    reasons.add("a lambda string (=>), which VQL evaluates as code");
  }
}

/** Is this VQL safe for Watson to launch? Every call must be on the read-only allowlist. */
export function vqlAllowed(vql: string): VqlAllowed {
  const tokenized = tokenizeVql(String(vql ?? ""));
  if (!tokenized.ok) return { ok: false, reasons: [`unreadable VQL: ${tokenized.reason}`] };
  const toks = tokenized.tokens;
  const reasons = new Set<string>();
  const defSites = new Set<number>();
  const lets = collectLets(toks, reasons, defSites);
  checkNames(toks, lets, defSites, reasons);
  checkCallTargets(toks, reasons);
  checkArgs(toks, reasons);
  checkStrings(toks, reasons);
  return reasons.size === 0 ? { ok: true } : { ok: false, reasons: [...reasons] };
}

/**
 * A fingerprint that ignores comments, whitespace and keyword case — so a re-run that only adds a
 * comment is still recognised. Prefixed `c` to keep it apart from vqlFingerprint's values.
 * "" when the VQL does not tokenize.
 */
export function canonicalVqlFingerprint(vql: string): string {
  const tokenized = tokenizeVql(String(vql ?? ""));
  if (!tokenized.ok || tokenized.tokens.length === 0) return "";
  const text = tokenized.tokens
    .map((t) => (t.kind === "ident" && has(VQL_KEYWORDS, t.text) ? lc(t.text) : t.text))
    .join(" ");
  return `c${vqlFingerprint(text)}`;
}
