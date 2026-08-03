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
  // Any `src="/js/…"`, classic or `type="module"` — the distinction is about load semantics, not
  // about whether the code can write the store.
  for (const m of html.matchAll(/<script[^>]*\ssrc="\/js\/([^"]+)"/g)) {
    out.push(makeScript(`js/${m[1]}`, readFileSync(new URL(`js/${m[1]}`, PUBLIC), "utf8")));
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

/** `DfirState.<member>(` call sites, as (script, line) pairs. Comments cannot reach this. */
export function dfirStateCalls(
  scripts: DashboardScript[],
  member: string,
): Array<{ script: string; line: number }> {
  const hits: Array<{ script: string; line: number }> = [];
  for (const s of scripts) {
    const visit = (n: ts.Node): void => {
      if (
        ts.isCallExpression(n) &&
        ts.isPropertyAccessExpression(n.expression) &&
        ts.isIdentifier(n.expression.expression) &&
        n.expression.expression.text === "DfirState" &&
        n.expression.name.text === member
      ) {
        hits.push({ script: s.name, line: s.ast.getLineAndCharacterOfPosition(n.getStart(s.ast)).line + 1 });
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
export function cachedSnapshots(node: ts.Node, member: string): CachedSnapshot[] {
  const out: CachedSnapshot[] = [];
  const isAccessorCall = (e: ts.Expression): boolean =>
    ts.isCallExpression(e) &&
    ts.isPropertyAccessExpression(e.expression) &&
    ts.isIdentifier(e.expression.expression) &&
    e.expression.expression.text === "DfirState" &&
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
