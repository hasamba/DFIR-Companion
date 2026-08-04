// AST analysis of the dashboard's first-party client code (#415).
//
// WHY THIS EXISTS. The state gates in tests/dashboard/dashboardState.test.ts started as regexes over
// public/dashboard.html. An audit of #460 showed both had holes that mattered:
//
//   - they read ONE file. The page loads ten classic scripts and seven modules besides, and tier 3
//     of #415 moves hundreds more functions into modules. A function that gained a second writer or
//     cached a snapshot across a refresh would not have been in the text being scanned.
//   - the function pattern was `\n    function name(`. That misses `async function`, arrow
//     callbacks, object methods and class methods. An `async function` that cached the snapshot and
//     called render() was injected and all 35 tests passed.
//   - "calls the writer" meant a DIRECT call. jumpToEvent reaches render() three hops away through
//     resetTimelineViewFilters -> setExcludeTerms, and the direct check cleared it.
//
// A gate the architecture is supposed to rest on has to see all the code and all the shapes, so
// this parses instead of matching.
//
// WHY THE TYPESCRIPT PARSER rather than acorn or espree: both are present in node_modules but only
// as transitive dependencies, and a gate CI depends on should not rest on a package that any
// unrelated dependency bump can remove. `typescript` is a direct devDependency and parses JS fine.

import { readFileSync } from "node:fs";
import ts from "typescript";

const PUBLIC = new URL("../../../public/", import.meta.url);

/** One parseable unit of the dashboard's client code. */
export interface DashboardScript {
  /** Display name for assertion messages: a filename, or `dashboard.html#inline-3`. */
  name: string;
  source: string;
  ast: ts.SourceFile;
}

/**
 * EVERY first-party script the dashboard loads: its inline blocks plus each /js/ file it tags,
 * whether classic or module.
 *
 * Read from the markup rather than hard-coded, so a script added tomorrow is covered the day it is
 * added — the hard-coded list is exactly what left seven modules unscanned before.
 */
export function dashboardScripts(): DashboardScript[] {
  const html = readFileSync(new URL("dashboard.html", PUBLIC), "utf8");
  const out: DashboardScript[] = [];

  let n = 0;
  for (const m of html.matchAll(/<script(?![^>]*\ssrc=)[^>]*>([\s\S]*?)<\/script>/g)) {
    out.push(makeScript(`dashboard.html#inline-${++n}`, m[1]));
  }

  // Tagged files, THEN everything they import, transitively.
  //
  // js/a11y/modal-autowire.js imports modal.js, which imports focus-trap.js. Neither is named by a
  // script tag, so neither was scanned — the browser fetches them, they run on every page, and a
  // second writer or a stale snapshot in either would have passed every gate. The same reasoning
  // that put the whole import graph in the STATIC_ASSETS check (a transitive import 404s exactly as
  // silently as a direct one) applies here: the gate has to see what the browser executes.
  const seen = new Set<string>();
  const queue = [...html.matchAll(/<script[^>]*\ssrc="\/js\/([^"]+)"/g)].map((m) => `js/${m[1]}`);
  while (queue.length > 0) {
    const rel = queue.shift() as string;
    if (seen.has(rel)) continue;
    seen.add(rel);
    const source = readFileSync(new URL(rel, PUBLIC), "utf8");
    out.push(makeScript(rel, source));
    // Relative specifiers only — a bare specifier would be a bundler dependency, and this page has
    // no bundler, so anything not starting with "." is not ours to scan.
    for (const imp of source.matchAll(/^\s*(?:import|export)\s[^"']*["'](\.[^"']+)["']/gm)) {
      queue.push(new URL(imp[1], `file:///${rel}`).pathname.replace(/^\//, ""));
    }
  }
  return out;
}

function makeScript(name: string, source: string): DashboardScript {
  return {
    name,
    source,
    ast: ts.createSourceFile(name, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.JS),
  };
}

/** Every function-like node, in any form the language offers. */
export interface FunctionInfo {
  script: string;
  /** Declared name where there is one, else `<anonymous@line>`. */
  name: string;
  line: number;
  node: ts.Node;
}

const isFunctionLike = (n: ts.Node): boolean =>
  ts.isFunctionDeclaration(n) ||
  ts.isFunctionExpression(n) ||
  ts.isArrowFunction(n) ||
  ts.isMethodDeclaration(n) ||
  ts.isGetAccessor(n) ||
  ts.isSetAccessor(n) ||
  ts.isConstructorDeclaration(n);

/**
 * Name a function for a failure message.
 *
 * An arrow assigned to a variable or property takes that name, because `const foo = async () => …`
 * is a named function to everyone except the parser, and a message saying `<anonymous@8231>` when
 * the source plainly says `foo` wastes the reader's time.
 */
function nameOf(node: ts.Node, sf: ts.SourceFile): string {
  const named = node as ts.FunctionDeclaration;
  if (named.name && ts.isIdentifier(named.name)) return named.name.text;
  const parent = node.parent;
  if (parent && ts.isVariableDeclaration(parent) && ts.isIdentifier(parent.name)) return parent.name.text;
  if (parent && ts.isPropertyAssignment(parent) && ts.isIdentifier(parent.name)) return parent.name.text;
  const { line } = sf.getLineAndCharacterOfPosition(node.getStart(sf));
  return `<anonymous@${line + 1}>`;
}

export function functionsOf(script: DashboardScript): FunctionInfo[] {
  const out: FunctionInfo[] = [];
  const visit = (n: ts.Node): void => {
    if (isFunctionLike(n)) {
      const { line } = script.ast.getLineAndCharacterOfPosition(n.getStart(script.ast));
      out.push({ script: script.name, name: nameOf(n, script.ast), line: line + 1, node: n });
    }
    ts.forEachChild(n, visit);
  };
  ts.forEachChild(script.ast, visit);
  return out;
}

/** Names called from inside `node`, including from functions nested within it. */
export function callsWithin(node: ts.Node): Set<string> {
  const out = new Set<string>();
  const visit = (n: ts.Node): void => {
    if (ts.isCallExpression(n)) {
      if (ts.isIdentifier(n.expression)) out.add(n.expression.text);
      else if (ts.isPropertyAccessExpression(n.expression)) out.add(n.expression.name.text);
    }
    ts.forEachChild(n, visit);
  };
  ts.forEachChild(node, visit);
  return out;
}

/** One place a protected setter is named, or a way of naming it that defeats the check. */
export interface SetterRef {
  script: string;
  line: number;
  /** `direct-call` is the only allowed form; every other value defeats the single-writer gate. */
  form:
    | "direct-call"
    | "property-reference"
    | "computed-access"
    | "destructured"
    | "namespace-alias"
    | "dynamic-access";
}

/**
 * Every reference to `<namespace>.<member>`, AND every construct that puts the setter out of reach
 * of that question.
 *
 * `namespace` defaults to DfirState because that was the only store when this was written. Tier 2
 * added a second owner with its own namespace (DfirScope), and the alternative to a parameter here
 * was a second copy of the rejection rules below — which is how two gates drift into checking
 * different things while both claiming to check writers.
 *
 * This has been widened twice, and each time by the same discovery: the gate was answering "how
 * many times is it written this one way" while presenting itself as "how many writers are there".
 *
 *   round 1 — only `DfirState.setLastFt(...)` counted, so a destructure, a computed access and a
 *             stashed property reference were three invisible writers.
 *   round 2 — the two below still were:
 *
 *                 const method = "setLastFt"; DfirState[method]([]);   // dynamic access
 *                 const state = DfirState;    state.setLastFt([]);     // namespace alias
 *
 * Following either properly needs binding-aware analysis, which is a large hammer for a page with
 * one legitimate writer per cell. So they are REJECTED rather than resolved: aliasing `DfirState`
 * to another name, or indexing it with anything but a string literal, is reported wherever it
 * appears. Both are one line to avoid and neither has a use here, so the cost of the blunt rule is
 * zero and the alternative is a gate that keeps being almost right.
 *
 *   round 3 — and it still was. `window.DfirScope.confirm(…)` is the SAME namespace by the spelling
 *             the browser itself uses (these are classic scripts publishing onto `window`), and the
 *             matcher required a bare Identifier, so it returned zero references and a fourth writer
 *             would have passed CI. That is exactly the failure the two rounds above describe, found
 *             a third time in review rather than by the gate. Hence `denotesNamespace` below: the
 *             question "does this expression mean the store" now has ONE answer that every check
 *             shares, instead of each check re-deciding it and stopping at a different spelling.
 */
/**
 * The roots a classic script's namespace is reachable through besides its bare name.
 *
 * These files publish onto `window`, so `window.DfirScope` is not a clever bypass — it is the
 * spelling the module itself writes and the one any reader would consider equivalent. A check that
 * accepts only the bare identifier is not being strict, it is being wrong.
 */
const GLOBAL_ROOTS = new Set(["window", "globalThis", "self"]);

/**
 * Does this expression denote the namespace itself?
 *
 * `DfirState` · `window.DfirState` · `globalThis["DfirState"]` — all the same object. ONE definition,
 * shared by every check below, because the last three holes in these gates were each a check that
 * had its own idea of what "the store" looks like.
 */
function denotesNamespace(n: ts.Node, namespace: string): boolean {
  if (ts.isIdentifier(n)) return n.text === namespace;
  if (ts.isPropertyAccessExpression(n)) {
    return ts.isIdentifier(n.expression) && GLOBAL_ROOTS.has(n.expression.text) && n.name.text === namespace;
  }
  if (ts.isElementAccessExpression(n)) {
    const arg = n.argumentExpression;
    return (
      ts.isIdentifier(n.expression) &&
      GLOBAL_ROOTS.has(n.expression.text) &&
      !!arg &&
      ts.isStringLiteral(arg) &&
      arg.text === namespace
    );
  }
  return false;
}

export function setterRefs(scripts: DashboardScript[], member: string, namespace = "DfirState"): SetterRef[] {
  const hits: SetterRef[] = [];
  for (const s of scripts) {
    const at = (n: ts.Node): number => s.ast.getLineAndCharacterOfPosition(n.getStart(s.ast)).line + 1;
    const visit = (n: ts.Node): void => {
      // <namespace>.member — a call, or a bare reference someone can stash.
      if (
        ts.isPropertyAccessExpression(n) &&
        denotesNamespace(n.expression, namespace) &&
        n.name.text === member
      ) {
        const isCallee = n.parent && ts.isCallExpression(n.parent) && n.parent.expression === n;
        hits.push({ script: s.name, line: at(n), form: isCallee ? "direct-call" : "property-reference" });
      }
      if (ts.isElementAccessExpression(n) && denotesNamespace(n.expression, namespace)) {
        const arg = n.argumentExpression;
        if (arg && ts.isStringLiteral(arg) && arg.text === member) {
          hits.push({ script: s.name, line: at(n), form: "computed-access" });
        } else if (arg && !ts.isStringLiteral(arg)) {
          // Cannot be resolved statically, so it could be any member — including this one.
          hits.push({ script: s.name, line: at(n), form: "dynamic-access" });
        }
      }
      // const { member } = DfirState
      if (ts.isVariableDeclaration(n) && n.initializer && denotesNamespace(n.initializer, namespace)) {
        if (ts.isObjectBindingPattern(n.name)) {
          for (const el of n.name.elements) {
            const source = el.propertyName ?? el.name;
            if (ts.isIdentifier(source) && source.text === member) {
              hits.push({ script: s.name, line: at(el), form: "destructured" });
            }
          }
        } else if (ts.isIdentifier(n.name)) {
          // const state = <namespace> — every member is now reachable under another name.
          hits.push({ script: s.name, line: at(n), form: "namespace-alias" });
        }
      }
      ts.forEachChild(n, visit);
    };
    ts.forEachChild(s.ast, visit);
  }
  return hits;
}

/**
 * Every name bound at the TOP LEVEL of a script — `let`/`const`/`var`, destructuring included.
 *
 * For asserting that a migrated binding is GONE rather than merely unused. The first version of that
 * assertion was `expect(html).not.toMatch(/^\s*let scope = \{/m)`, which pinned one spelling of one
 * initialiser: `let scope = null`, `let scope;`, `const scope = …` and `var scope` all sailed
 * through, and any of them re-opens the second source of truth the migration existed to close.
 * A declaration is an AST fact, so ask the AST.
 */
export function topLevelBindings(script: DashboardScript): Array<{ name: string; line: number }> {
  const out: Array<{ name: string; line: number }> = [];
  const at = (n: ts.Node): number =>
    script.ast.getLineAndCharacterOfPosition(n.getStart(script.ast)).line + 1;
  const collect = (name: ts.BindingName): void => {
    if (ts.isIdentifier(name)) {
      out.push({ name: name.text, line: at(name) });
      return;
    }
    for (const el of name.elements) {
      if (ts.isBindingElement(el)) collect(el.name);
    }
  };
  for (const st of script.ast.statements) {
    if (ts.isVariableStatement(st)) {
      for (const d of st.declarationList.declarations) collect(d.name);
    }
  }
  return out;
}

/** A property write through an owner's getter: `DfirScope.get().start = x`. */
export interface GetterMutation {
  script: string;
  line: number;
  /** `direct` is `owner.get().prop = v`; `via-alias` went through a local first. */
  form: "direct" | "via-alias";
  text: string;
}

/**
 * Writes THROUGH an accessor to the object it returned.
 *
 * js/dashboard-scope.js hands back a frozen window and argues that closes the "a reader could mutate
 * it in place" hazard tier 1 documented. Freezing alone does not close it: these are classic
 * scripts, so they are not strict mode, so `DfirScope.get().start = x` silently does NOTHING. The
 * caller's intent is lost and every subsequent read returns the old value — a wrong dashboard with a
 * green CI, which is worse than the throw a strict realm would have given.
 *
 * So the runtime freeze stops the state from being corrupted and this stops the code from being
 * written. Both halves are needed and neither substitutes for the other.
 */
export function getterMutations(
  scripts: DashboardScript[],
  namespace: string,
  accessor: string,
): GetterMutation[] {
  const hits: GetterMutation[] = [];
  const isAccessorCall = (e: ts.Node): boolean =>
    ts.isCallExpression(e) &&
    ts.isPropertyAccessExpression(e.expression) &&
    denotesNamespace(e.expression.expression, namespace) &&
    e.expression.name.text === accessor;

  for (const s of scripts) {
    const at = (n: ts.Node): number => s.ast.getLineAndCharacterOfPosition(n.getStart(s.ast)).line + 1;
    // Locals bound straight to the accessor's result, so the aliased form is reachable too.
    const aliases = new Set<string>();
    const findAliases = (n: ts.Node): void => {
      if (ts.isVariableDeclaration(n) && n.initializer && ts.isIdentifier(n.name)) {
        if (isAccessorCall(n.initializer)) aliases.add(n.name.text);
      }
      ts.forEachChild(n, findAliases);
    };
    ts.forEachChild(s.ast, findAliases);

    const visit = (n: ts.Node): void => {
      if (ts.isBinaryExpression(n) && n.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
        const lhs = n.left;
        if (ts.isPropertyAccessExpression(lhs) || ts.isElementAccessExpression(lhs)) {
          const target = lhs.expression;
          if (isAccessorCall(target)) {
            hits.push({ script: s.name, line: at(n), form: "direct", text: n.getText(s.ast).slice(0, 90) });
          } else if (ts.isIdentifier(target) && aliases.has(target.text)) {
            hits.push({
              script: s.name,
              line: at(n),
              form: "via-alias",
              text: n.getText(s.ast).slice(0, 90),
            });
          }
        }
      }
      ts.forEachChild(n, visit);
    };
    ts.forEachChild(s.ast, visit);
  }
  return hits;
}

/** A local that caches a snapshot: its name, and where it was bound. */
export interface CachedSnapshot {
  name: string;
  pos: number;
}

/**
 * Locals whose initialiser IS `DfirState.<member>()` — optionally with a `|| fallback`.
 *
 * Only the accessor call itself counts. `const caseId = DfirState.lastState() && ….caseId` derives
 * a scalar rather than caching the snapshot, and without that distinction the gate fires on every
 * derived value.
 */
export function cachedSnapshots(node: ts.Node, member: string, namespace = "DfirState"): CachedSnapshot[] {
  const out: CachedSnapshot[] = [];
  const isAccessorCall = (e: ts.Expression): boolean =>
    ts.isCallExpression(e) &&
    ts.isPropertyAccessExpression(e.expression) &&
    denotesNamespace(e.expression.expression, namespace) &&
    e.expression.name.text === member;
  const visit = (n: ts.Node): void => {
    if (ts.isVariableDeclaration(n) && n.initializer && ts.isIdentifier(n.name)) {
      let init: ts.Expression = n.initializer;
      while (
        ts.isBinaryExpression(init) &&
        (init.operatorToken.kind === ts.SyntaxKind.BarBarToken ||
          init.operatorToken.kind === ts.SyntaxKind.QuestionQuestionToken)
      ) {
        init = init.left;
      }
      if (isAccessorCall(init)) out.push({ name: n.name.text, pos: n.end });
    }
    ts.forEachChild(n, visit);
  };
  ts.forEachChild(node, visit);
  return out;
}

/**
 * Calls made within `node` after `pos`, with both bounds.
 *
 * `end` matters as much as `pos`: the arguments of a call sit INSIDE it, so `renderTimelineEvents(ft)`
 * contains a read of `ft` at a position after the call begins. Measuring a later use from the call's
 * END is what distinguishes "passed the cached value into a renderer" — fine, the argument is bound
 * before the callee runs — from "read it again after the renderer replaced it".
 */
export function callsAfter(node: ts.Node, pos: number): Array<{ name: string; pos: number; end: number }> {
  const out: Array<{ name: string; pos: number; end: number }> = [];
  const visit = (n: ts.Node): void => {
    if (n.pos >= pos && ts.isCallExpression(n)) {
      if (ts.isIdentifier(n.expression)) out.push({ name: n.expression.text, pos: n.pos, end: n.end });
      else if (ts.isPropertyAccessExpression(n.expression))
        out.push({ name: n.expression.name.text, pos: n.pos, end: n.end });
    }
    ts.forEachChild(n, visit);
  };
  ts.forEachChild(node, visit);
  return out;
}

/** Positions where the identifier `name` is read within `node`, after `pos`. */
export function usesAfter(node: ts.Node, name: string, pos: number): number[] {
  const out: number[] = [];
  const visit = (n: ts.Node): void => {
    if (ts.isPropertyAccessExpression(n)) {
      visit(n.expression);
      return;
    } // `x.y` reads x, not y
    if (ts.isIdentifier(n) && n.text === name && n.pos >= pos) out.push(n.pos);
    ts.forEachChild(n, visit);
  };
  ts.forEachChild(node, visit);
  return out;
}

/**
 * Is the cache inside a loop body?
 *
 * The positional rule reads a loop as straight-line code, and a loop is exactly where straight-line
 * reasoning fails: `for (…) { const ft = lastFt(); consume(ft); render(…); }` has every use before
 * the refresh IN THE TEXT, while iteration two consumes what iteration one's render replaced. The
 * jump backwards is invisible to a position comparison, so a cache inside a loop with any refresher
 * in the same loop is treated the same way as one captured by a callback: position stops meaning
 * anything, and the refresher alone is the fault.
 */

/**
 * Is `name` captured by a function nested inside `node`?
 *
 * SOURCE ORDER IS NOT EXECUTION ORDER, and the positional check alone believes it is. This passes
 * it:
 *
 *     const ft = DfirState.lastFt();
 *     setTimeout(() => consume(ft), 0);   // captured here, RUNS later
 *     render(lastState);                  // replaces lastFt in between
 *
 * Every use of `ft` precedes the refresh in the text, so nothing is "used after" it — while at
 * runtime the order is cache, refresh, use. A loop body does the same thing by jumping backwards.
 *
 * A captured variable has no knowable execution position, so the honest treatment is to stop
 * reasoning about position for it: if the value escapes into a callback and anything in the
 * enclosing function can refresh the cell, that is a fault. Conservative by design — a deferred
 * read of a snapshot is worth writing differently even when it happens to be safe.
 */
export function insideLoop(node: ts.Node, pos: number): boolean {
  let found = false;
  const visit = (n: ts.Node): void => {
    if (found) return;
    const isLoop =
      ts.isForStatement(n) ||
      ts.isForOfStatement(n) ||
      ts.isForInStatement(n) ||
      ts.isWhileStatement(n) ||
      ts.isDoStatement(n);
    if (isLoop && n.pos <= pos && n.end >= pos) {
      found = true;
      return;
    }
    ts.forEachChild(n, visit);
  };
  ts.forEachChild(node, visit);
  return found;
}

export function capturedByNestedFunction(node: ts.Node, name: string): boolean {
  let captured = false;
  const search = (n: ts.Node, insideNested: boolean): void => {
    if (captured) return;
    const nested = insideNested || (n !== node && isFunctionLike(n));
    if (nested && ts.isIdentifier(n) && n.text === name) {
      captured = true;
      return;
    }
    ts.forEachChild(n, (c) => search(c, nested));
  };
  ts.forEachChild(node, (c) => search(c, false));
  return captured;
}

/**
 * Every name transitively reachable from `roots` through the call graph of named functions.
 *
 * The audit's third point: a direct-call check cleared jumpToEvent, which reaches render() three
 * hops away via resetTimelineViewFilters -> setExcludeTerms. Reachability is the property that
 * matters, because a snapshot cached before ANY of those hops is stale after it.
 */
export function buildCallGraph(scripts: DashboardScript[]): Map<string, Set<string>> {
  const graph = new Map<string, Set<string>>();
  for (const s of scripts) {
    for (const fn of functionsOf(s)) {
      if (fn.name.startsWith("<anonymous")) continue;
      const existing = graph.get(fn.name) ?? new Set<string>();
      for (const c of callsWithin(fn.node)) existing.add(c);
      graph.set(fn.name, existing);
    }
  }
  return graph;
}

export function reachableFrom(graph: Map<string, Set<string>>, start: Iterable<string>): Set<string> {
  const seen = new Set<string>();
  const queue = [...start];
  while (queue.length > 0) {
    const name = queue.shift() as string;
    if (seen.has(name)) continue;
    seen.add(name);
    for (const next of graph.get(name) ?? []) if (!seen.has(next)) queue.push(next);
  }
  return seen;
}
