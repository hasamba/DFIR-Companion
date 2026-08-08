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
/**
 * The page's MAIN inline block — the big one features used to be written into.
 *
 * Five test files located it with `blocks.find(m => /\n\s*function render\s*\(/.test(m[1]))`,
 * which ties "which block is the main one" to one function still living in it. #415 is in the
 * business of moving functions out of that block, so that anchor is a tripwire: move render and
 * five suites stop being able to find the script they assert about, with a message about a missing
 * script rather than about what changed.
 *
 * Length is the stable property. The main block is an order of magnitude larger than the four
 * bootstrap blocks around it, and stays so however much comes out of it — it is how
 * scripts/dashboard-inventory.mjs has always located it.
 */
export function mainInlineScript(): DashboardScript {
  const inline = dashboardScripts().filter((s) => s.name.startsWith("dashboard.html#inline-"));
  if (!inline.length) throw new Error("no inline dashboard scripts found");
  return inline.reduce((a, b) => (b.source.length > a.source.length ? b : a));
}

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

/**
 * Parse a snippet as if it were one of the dashboard's scripts.
 *
 * Exported so the ANALYSER can be tested directly. Every hole found in these gates so far — the
 * `async function` shape, the transitive call, the window-rooted namespace, the callback loop — was
 * found by a human reading the code, never by a test, because there was no way to ask "what does
 * this helper say about this snippet". There is now.
 */
export function scriptFromSource(name: string, source: string): DashboardScript {
  return makeScript(name, source);
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
  /**
   * True only for a real `function foo() {}` DECLARATION.
   *
   * `nameOf` gives an arrow its variable or property name, which is right for failure messages and
   * wrong for "was this left behind": the ACTIONS dispatch table is full of
   * `setComplianceDiscovered: (el) => setComplianceDiscovered(el)` entries that must STAY when the
   * function they call moves out. Without this distinction those entries read as leftovers.
   */
  declaration: boolean;
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
      out.push({
        script: script.name,
        name: nameOf(n, script.ast),
        line: line + 1,
        node: n,
        declaration: ts.isFunctionDeclaration(n),
      });
    }
    ts.forEachChild(n, visit);
  };
  ts.forEachChild(script.ast, visit);
  return out;
}

/**
 * EVERY NAME THIS SCRIPT BINDS TO A FUNCTION — the census behind "did the feature move as a unit?"
 *
 * Both halves of that check must ask the same question of the same shapes, or a duplicate slips
 * through the difference. It used to be asked twice, differently: a regex over the module's text
 * and `functionsOf().filter(f => f.declaration)` over the inline script.
 *
 * A DECLARATION IS NOT THE ONLY WAY TO BIND A FUNCTION, and the declaration-only rule missed the
 * one that actually hurts. `const loadAnomalies = () => {}` left behind in the inline script is a
 * top-level lexical binding, so it SHADOWS the module's published `window.loadAnomalies` for every
 * call site in that script — the feature looks moved, its tests pass, and the page runs the stale
 * copy. Restoring exactly that mutation passed the whole suite.
 *
 * WHAT IS DELIBERATELY NOT COUNTED, and why the naive "any function-valued node" rule is wrong: the
 * ACTIONS dispatch table is full of `setComplianceDiscovered: (el) => setComplianceDiscovered(el)`
 * entries, and those must STAY behind when the function they call moves out — they are how a click
 * reaches the module. A property is not a binding; nothing can shadow through one. Same for class
 * and object methods.
 */
export function functionBindingsOf(script: DashboardScript): Array<{ name: string; line: number }> {
  const out: Array<{ name: string; line: number }> = [];
  const at = (n: ts.Node): number =>
    script.ast.getLineAndCharacterOfPosition(n.getStart(script.ast)).line + 1;
  const visit = (n: ts.Node): void => {
    if (ts.isFunctionDeclaration(n) && n.name && ts.isIdentifier(n.name)) {
      out.push({ name: n.name.text, line: at(n) });
    }
    // `const f = () => {}` / `let f = function () {}` / `var f = async () => {}`. The binding is the
    // variable, so a destructured or array-pattern name is not one of these by construction.
    if (
      ts.isVariableDeclaration(n) &&
      ts.isIdentifier(n.name) &&
      n.initializer &&
      (ts.isArrowFunction(n.initializer) || ts.isFunctionExpression(n.initializer))
    ) {
      out.push({ name: n.name.text, line: at(n) });
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
/**
 * Bare-identifier assignments to a name this script declares NOWHERE — `veloArtifactCache = []`
 * with no `let` behind it.
 *
 * topLevelBindings() counts these as bindings, and for the page's non-strict inline script that is
 * the right answer: the assignment really does create a global. But it creates it only WHEN IT
 * RUNS. Inside an extracted module IIFE that makes the name an ordering hazard — one function
 * creates it, another reads it, and if the read happens first it is a ReferenceError, not
 * undefined. A module has no reason to want one: to share, it publishes on `window`; to keep
 * state, it declares it. So for modules the honest answer is "there should be none", which is
 * what this exists to check.
 */
export function implicitGlobals(script: DashboardScript): Array<{ name: string; line: number }> {
  const declaredAnywhere = new Set<string>();
  const at = (n: ts.Node): number =>
    script.ast.getLineAndCharacterOfPosition(n.getStart(script.ast)).line + 1;
  const declWalk = (n: ts.Node): void => {
    if (ts.isVariableDeclaration(n)) collectInto(n.name, declaredAnywhere);
    if (isFunctionLike(n)) {
      const fn = n as ts.FunctionLikeDeclaration;
      if (fn.name && ts.isIdentifier(fn.name)) declaredAnywhere.add(fn.name.text);
      for (const p of fn.parameters) collectInto(p.name, declaredAnywhere);
    }
    if (ts.isCatchClause(n) && n.variableDeclaration)
      collectInto(n.variableDeclaration.name, declaredAnywhere);
    if (ts.isClassDeclaration(n) && n.name) declaredAnywhere.add(n.name.text);
    ts.forEachChild(n, declWalk);
  };
  ts.forEachChild(script.ast, declWalk);

  const OPS = new Set([
    ts.SyntaxKind.EqualsToken,
    ts.SyntaxKind.QuestionQuestionEqualsToken,
    ts.SyntaxKind.BarBarEqualsToken,
    ts.SyntaxKind.AmpersandAmpersandEqualsToken,
  ]);
  const seen = new Set<string>();
  const out: Array<{ name: string; line: number }> = [];
  const walk = (n: ts.Node): void => {
    if (
      ts.isBinaryExpression(n) &&
      OPS.has(n.operatorToken.kind) &&
      ts.isIdentifier(n.left) &&
      !declaredAnywhere.has(n.left.text) &&
      !seen.has(n.left.text)
    ) {
      seen.add(n.left.text);
      out.push({ name: n.left.text, line: at(n.left) });
    }
    ts.forEachChild(n, walk);
  };
  ts.forEachChild(script.ast, walk);
  return out;
}

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

  // let/const at the very top of the script, AND the declaration forms that also bind a name there:
  // `function hiddenSources() {}` and `class hiddenSources {}` are page globals every bit as much
  // as `let` is, and the first version of this helper looked only at variable statements.
  for (const st of script.ast.statements) {
    if (ts.isVariableStatement(st)) {
      for (const d of st.declarationList.declarations) collect(d.name);
    } else if (
      (ts.isFunctionDeclaration(st) || ts.isClassDeclaration(st)) &&
      st.name &&
      ts.isIdentifier(st.name)
    ) {
      out.push({ name: st.name.text, line: at(st.name) });
    }
  }

  // `var` ANYWHERE outside a function, because it hoists to the script scope regardless of the
  // block it is written in. `if (ready) { var selectedEvents = new Set(); }` is a script-level
  // binding, and the first version of this helper — which looked only at direct children of the
  // SourceFile — reported nothing for it.
  const declared = new Set(out.map((b) => b.name));
  const varWalk = (n: ts.Node): void => {
    if (isFunctionLike(n)) return; // `var` inside a function is that function's, not the script's
    // `for (var selectedEvents of sets)` and its for/for-in siblings: the declaration lives in the
    // loop head, not in a VariableStatement, so the branch below never saw it.
    if (
      (ts.isForStatement(n) || ts.isForOfStatement(n) || ts.isForInStatement(n)) &&
      n.initializer &&
      ts.isVariableDeclarationList(n.initializer)
    ) {
      const list = n.initializer;
      if (!(list.flags & ts.NodeFlags.BlockScoped)) {
        for (const d of list.declarations) {
          const before = out.length;
          collect(d.name);
          for (const b of out.slice(before)) declared.add(b.name);
        }
      }
    }
    if (ts.isVariableStatement(n) && n.declarationList.flags & ts.NodeFlags.Let) {
      // let/const in a nested block is genuinely block-scoped; not ours.
    } else if (ts.isVariableStatement(n) && !(n.declarationList.flags & ts.NodeFlags.BlockScoped)) {
      for (const d of n.declarationList.declarations) {
        const before = out.length;
        collect(d.name);
        for (const b of out.slice(before)) declared.add(b.name);
      }
    }
    ts.forEachChild(n, varWalk);
  };
  ts.forEachChild(script.ast, varWalk);

  // IMPLICIT GLOBALS. These scripts are not strict, so a bare `selectedEvents = new Set()` with no
  // declaration anywhere creates a property on the global object — a binding by any useful
  // definition, and invisible to every declaration-shaped check. Collected by finding assignments
  // whose target is declared NOWHERE in this script (parameters and nested `let`s included).
  const declaredAnywhere = new Set<string>();
  const declWalk = (n: ts.Node): void => {
    if (ts.isVariableDeclaration(n)) collectInto(n.name, declaredAnywhere);
    if (isFunctionLike(n)) {
      const fn = n as ts.FunctionLikeDeclaration;
      if (fn.name && ts.isIdentifier(fn.name)) declaredAnywhere.add(fn.name.text);
      for (const p of fn.parameters) collectInto(p.name, declaredAnywhere);
    }
    if (ts.isCatchClause(n) && n.variableDeclaration)
      collectInto(n.variableDeclaration.name, declaredAnywhere);
    ts.forEachChild(n, declWalk);
  };
  ts.forEachChild(script.ast, declWalk);

  const ASSIGN_OPS = new Set([
    ts.SyntaxKind.EqualsToken,
    // `window.hiddenSources ??= new Set()` creates the global just as surely as `=` does.
    ts.SyntaxKind.QuestionQuestionEqualsToken,
    ts.SyntaxKind.BarBarEqualsToken,
    ts.SyntaxKind.AmpersandAmpersandEqualsToken,
  ]);
  const assignWalk = (n: ts.Node): void => {
    if (ts.isBinaryExpression(n) && ASSIGN_OPS.has(n.operatorToken.kind)) {
      // `selectedEvents = new Set()` with no declaration anywhere — an implicit global.
      if (ts.isIdentifier(n.left) && !declaredAnywhere.has(n.left.text) && !declared.has(n.left.text)) {
        out.push({ name: n.left.text, line: at(n.left) });
        declared.add(n.left.text);
      }
      // `window.selectedEvents = new Set()` — the explicit form of the same thing, and the one a
      // declaration-shaped check will never see however carefully it is written.
      if (
        ts.isPropertyAccessExpression(n.left) &&
        ts.isIdentifier(n.left.expression) &&
        GLOBAL_ROOTS.has(n.left.expression.text) &&
        !declared.has(n.left.name.text)
      ) {
        out.push({ name: n.left.name.text, line: at(n.left.name) });
        declared.add(n.left.name.text);
      }
      // ...and `globalThis["hiddenSources"] = new Set()`, which is the same global by the one
      // spelling the property-access branch above cannot see.
      if (
        ts.isElementAccessExpression(n.left) &&
        ts.isIdentifier(n.left.expression) &&
        GLOBAL_ROOTS.has(n.left.expression.text) &&
        n.left.argumentExpression &&
        (ts.isStringLiteral(n.left.argumentExpression) ||
          ts.isNoSubstitutionTemplateLiteral(n.left.argumentExpression)) &&
        !declared.has(n.left.argumentExpression.text)
      ) {
        out.push({ name: n.left.argumentExpression.text, line: at(n.left) });
        declared.add(n.left.argumentExpression.text);
      }
    }
    ts.forEachChild(n, assignWalk);
  };
  ts.forEachChild(script.ast, assignWalk);

  return out;
}

/** Names bound by a binding pattern, into an existing set. */
function collectInto(name: ts.BindingName, into: Set<string>): void {
  if (ts.isIdentifier(name)) {
    into.add(name.text);
    return;
  }
  for (const el of name.elements) {
    if (ts.isBindingElement(el)) collectInto(el.name, into);
  }
}

/** One call of an owner's method, and whether a loop encloses it. */
export interface OwnerCall {
  script: string;
  line: number;
  /** The dotted path as written, e.g. `DfirSelection.events.addAll`. */
  path: string;
  method: string;
  inLoop: boolean;
  /** The innermost NAMED enclosing function, for allowlisting a documented exception. */
  fn: string;
}

/**
 * Every call to `<namespace>.….<method>` for the named methods, flagged if a loop encloses it.
 *
 * THE LOOP FLAG IS THE POINT, and it is specific to replace-on-write owners. A set behind
 * replace-on-write costs O(n) per commit, so a commit inside a loop is O(n^2) for the gesture —
 * and js/dashboard-selection.js exists partly because four of the sites it replaced were exactly
 * that, over data no page size bounds. The bulk operations (addAll/removeAll/replace) are the
 * supported way to write many ids, so "no commit in a loop" is a rule a test can hold, unlike
 * "remember that this is O(n)".
 *
 * Matches at any depth under the namespace, so `DfirSelection.events.toggle` and a hypothetical
 * `DfirSelection.toggle` both count; `denotesNamespace` handles the window-rooted spelling.
 */
export function ownerCalls(
  scripts: DashboardScript[],
  namespace: string,
  methods: readonly string[],
): OwnerCall[] {
  const want = new Set(methods);
  const out: OwnerCall[] = [];
  // Walk down a property-access chain to its root, collecting the names on the way.
  const chain = (n: ts.Node): string[] | null => {
    if (denotesNamespace(n, namespace)) return [namespace];
    if (ts.isPropertyAccessExpression(n)) {
      const head = chain(n.expression);
      return head ? [...head, n.name.text] : null;
    }
    return null;
  };
  // `DfirSelection.events.toggle.call(null, x)` still invokes toggle. Dropping the reflective tail
  // is what makes the path end at the member the rule is about, instead of at "call".
  const withoutReflection = (path: string[]): string[] =>
    path.length > 1 && FUNCTION_INVOKERS.has(path[path.length - 1]) ? path.slice(0, -1) : path;

  for (const s of scripts) {
    const at = (n: ts.Node): number => s.ast.getLineAndCharacterOfPosition(n.getStart(s.ast)).line + 1;
    // Innermost NAMED function enclosing a position, for allowlisting a documented exception.
    const named = functionsOf(s).filter((f) => !f.name.startsWith("<"));
    const enclosing = (n: ts.Node): string => {
      let best: FunctionInfo | null = null;
      const p = n.getStart(s.ast);
      for (const f of named) {
        if (f.node.getStart(s.ast) <= p && f.node.getEnd() >= p) {
          if (!best || f.node.getStart(s.ast) > best.node.getStart(s.ast)) best = f;
        }
      }
      return best ? best.name : "<top-level>";
    };

    // ONE walk from the SourceFile, carrying loop depth. Walking per-function (the first version)
    // skipped every commit at top level, where a classic script does most of its wiring.
    const visit = (n: ts.Node, loops: number): void => {
      let inner = loops;
      if (
        ts.isForStatement(n) ||
        ts.isForOfStatement(n) ||
        ts.isForInStatement(n) ||
        ts.isWhileStatement(n) ||
        ts.isDoStatement(n)
      ) {
        inner = loops + 1;
      }
      if (ts.isCallExpression(n) && ts.isPropertyAccessExpression(n.expression)) {
        const path = chain(n.expression) && withoutReflection(chain(n.expression) as string[]);
        if (path && want.has(path[path.length - 1])) {
          out.push({
            script: s.name,
            line: at(n),
            path: path.join("."),
            method: path[path.length - 1],
            inLoop: loops > 0,
            fn: enclosing(n),
          });
        }
      }
      // An iteration callback is a loop body, so its ARGUMENTS are walked at depth+1 while the
      // receiver is not: in `xs.forEach(cb)` the `xs` expression runs once.
      // ONLY AN EVENT-DRIVEN CALLBACK IS DECOUPLED FROM THE LOOP.
      //
      // `["a","b"].forEach(id => el(id).addEventListener("keydown", () => createNewCase()))` puts a
      // commit three frames inside a forEach, but it runs on a KEYSTROKE — once, later, not once
      // per element. That one is genuinely not per-element.
      //
      // An earlier version reset depth at EVERY nested function that was not an iteration callback,
      // which was far too broad: a synchronous IIFE, an unknown helper's callback, and
      // `for (…) queueMicrotask(() => commit())` all became invisible, and the last of those really
      // does run N times. Deferral is not the property that matters — being driven by something
      // other than the loop is — so only listener registration qualifies.
      if (isFunctionLike(n) && isEventHandlerArg(n)) {
        ts.forEachChild(n, (c) => visit(c, 0));
        return;
      }
      if (isIterationCall(n)) {
        visit(n.expression, inner);
        for (const a of n.arguments) visit(a, inner + 1);
        return;
      }
      ts.forEachChild(n, (c) => visit(c, inner));
    };
    ts.forEachChild(s.ast, (c) => visit(c, 0));
  }
  return out;
}

/**
 * Positions of every call to a bare `name(...)` within `node`.
 *
 * For asking questions about a module's INTERNALS — specifically whether an owner's own bulk
 * operation loops around its private commit, which no call-site analysis can see.
 */
export function ownerCallPositions(node: ts.Node, name: string): number[] {
  const out: number[] = [];
  const visit = (n: ts.Node): void => {
    if (ts.isCallExpression(n) && ts.isIdentifier(n.expression) && n.expression.text === name) {
      out.push(n.getStart());
    }
    ts.forEachChild(n, visit);
  };
  ts.forEachChild(node, visit);
  return out;
}

/**
 * Names called from inside a loop body, anywhere in these scripts.
 *
 * The indirect half of the loop rule: a commit does not stop being per-iteration because a function
 * call sits between it and the loop. Feed these to reachableFrom() against the set of functions
 * that commit, and `for (const id of ids) selectOne(id)` is caught even though the commit is a hop
 * away — the same direct-vs-transitive distinction that cleared jumpToEvent earlier in #415.
 */
export function calleesInsideLoops(scripts: DashboardScript[]): Set<string> {
  const out = new Set<string>();
  for (const s of scripts) {
    const visit = (n: ts.Node, loops: number): void => {
      let inner = loops;
      if (
        ts.isForStatement(n) ||
        ts.isForOfStatement(n) ||
        ts.isForInStatement(n) ||
        ts.isWhileStatement(n) ||
        ts.isDoStatement(n)
      ) {
        inner = loops + 1;
      }
      if (loops > 0 && ts.isCallExpression(n)) {
        if (ts.isIdentifier(n.expression)) out.add(n.expression.text);
        else if (ts.isPropertyAccessExpression(n.expression)) out.add(n.expression.name.text);
      }
      // ONLY AN EVENT-DRIVEN CALLBACK IS DECOUPLED FROM THE LOOP.
      //
      // `["a","b"].forEach(id => el(id).addEventListener("keydown", () => createNewCase()))` puts a
      // commit three frames inside a forEach, but it runs on a KEYSTROKE — once, later, not once
      // per element. That one is genuinely not per-element.
      //
      // An earlier version reset depth at EVERY nested function that was not an iteration callback,
      // which was far too broad: a synchronous IIFE, an unknown helper's callback, and
      // `for (…) queueMicrotask(() => commit())` all became invisible, and the last of those really
      // does run N times. Deferral is not the property that matters — being driven by something
      // other than the loop is — so only listener registration qualifies.
      if (isFunctionLike(n) && isEventHandlerArg(n)) {
        ts.forEachChild(n, (c) => visit(c, 0));
        return;
      }
      if (isIterationCall(n)) {
        // A CALLBACK PASSED BY NAME IS STILL CALLED PER ELEMENT. `xs.forEach(hideOne)` has no call
        // expression anywhere inside it, so walking the arguments finds nothing — the identifier
        // IS the per-element call, and review found this failing open exactly that way.
        for (const a of n.arguments) {
          if (ts.isIdentifier(a)) out.add(a.text);
          else if (ts.isPropertyAccessExpression(a)) out.add(a.name.text);
        }
        visit(n.expression, inner);
        for (const a of n.arguments) visit(a, inner + 1);
        return;
      }
      // The same by-name hand-off inside a real loop: `for (…) xs.map(hideOne)` is covered above,
      // but `for (…) run(hideOne)` passes it to something that will call it. NOT for a listener
      // registration — `for (…) el.addEventListener("click", handler)` registers N handlers that
      // each run on a click, not N calls, and treating it as a call reported handlers falsely.
      if (loops > 0 && ts.isCallExpression(n) && !isEventRegistration(n)) {
        for (const a of n.arguments) if (ts.isIdentifier(a)) out.add(a.text);
      }
      ts.forEachChild(n, (c) => visit(c, inner));
    };
    ts.forEachChild(s.ast, (c) => visit(c, 0));
  }
  return out;
}

/** A construct that puts an owner's methods beyond what ownerCalls() can follow. */
export interface OwnerEscape {
  script: string;
  line: number;
  form: "alias" | "passed" | "computed-member" | "dynamic-member";
  text: string;
}

/**
 * Ways of reaching an owner that defeat ownerCalls(), reported so they can be REJECTED.
 *
 * Same argument as setterRefs' rejection list, for the same reason. `const events =
 * DfirSelection.events; ids.forEach(id => events.toggle(id))` is a commit in a loop that no
 * path-matching analysis sees, and `DfirSelection.events["toggle"](id)` is another. Following
 * either needs binding-aware analysis; neither has a use in this page, and both are one line to
 * avoid — so they are reported wherever they appear rather than resolved.
 */
/**
 * Is this the PROPERTY NAME half of `a.b`, rather than a reference to something called `b`?
 *
 * The bare identifier `DfirFacets` inside `window.DfirFacets` matches "denotes the namespace" on
 * its own, and it sits at `parent.name` — not `parent.expression` — so the longer-path check does
 * not cover it. Without this, every module was reported as smuggling out its own namespace.
 */
/**
 * Is this the operand of a `typeof`? Then it is a GUARD, not an escape.
 *
 * `typeof DfirTimelineView !== "undefined"` neither aliases the namespace nor reaches it
 * dynamically — it is the one operation that does not even evaluate the binding, which is exactly
 * why it is the guard a 404-able module gets wrapped in. Before the tier-3 guards there was no
 * `typeof` on any owner in the page, so this read as a bare reference being passed somewhere and
 * the escape gate fired on the very construct added to make the page survive a missing module.
 */
function isTypeofOperand(n: ts.Node): boolean {
  let cur: ts.Node = n;
  while (cur.parent && ts.isParenthesizedExpression(cur.parent)) cur = cur.parent;
  return !!cur.parent && ts.isTypeOfExpression(cur.parent) && cur.parent.expression === cur;
}

function isPropertyName(n: ts.Node): boolean {
  const p = n.parent;
  return !!p && (ts.isPropertyAccessExpression(p) || ts.isPropertyAssignment(p)) && p.name === n;
}

/** Names whose callback is invoked by something OTHER than the surrounding code's control flow. */
/** Reflective invokers: `f.call(…)`, `f.apply(…)`, `f.bind(…)` still reach `f`. */
const FUNCTION_INVOKERS = new Set(["call", "apply", "bind"]);

/** `el.addEventListener("click", fn)` — the call itself, not its callback. */
function isEventRegistration(n: ts.CallExpression): boolean {
  return ts.isPropertyAccessExpression(n.expression) && EVENT_REGISTRARS.has(n.expression.name.text);
}

const EVENT_REGISTRARS = new Set(["addEventListener", "removeEventListener", "on", "once"]);

/**
 * Is this function registered as an event handler, rather than called by the code around it?
 *
 * Deliberately narrow. setTimeout/queueMicrotask/Promise.then all invoke their callback ONCE PER
 * CALL, so N registrations in a loop are still N commits — they are not on this list. Only handlers
 * driven by an external event are, plus `el.onclick = fn`.
 */
function isEventHandlerArg(n: ts.Node): boolean {
  const p = n.parent;
  if (!p) return false;
  if (
    ts.isCallExpression(p) &&
    ts.isPropertyAccessExpression(p.expression) &&
    EVENT_REGISTRARS.has(p.expression.name.text) &&
    p.arguments.some((a) => a === n)
  ) {
    return true;
  }
  // el.onclick = () => …
  return (
    ts.isBinaryExpression(p) &&
    p.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
    p.right === n &&
    ts.isPropertyAccessExpression(p.left) &&
    /^on[a-z]/.test(p.left.name.text)
  );
}

/** Is this function the callback argument of `xs.forEach(...)` and friends? Parentheses unwrapped. */
function isIterationCallback(n: ts.Node): boolean {
  let node: ts.Node = n;
  while (node.parent && ts.isParenthesizedExpression(node.parent)) node = node.parent;
  const p = node.parent;
  return !!p && isIterationCall(p) && p.arguments.some((a) => a === node);
}

/** Is this node the `X` in `X(...)` — i.e. the thing actually being invoked? */
function isCalleePosition(n: ts.Node): boolean {
  const p = n.parent;
  return !!p && (ts.isCallExpression(p) || ts.isNewExpression(p)) && p.expression === n;
}

/** A sub-path like `DfirSelection.events` inside `DfirSelection.events.toggle(x)` is not itself an escape. */
function isPartOfLongerPath(n: ts.Node): boolean {
  const p = n.parent;
  if (!p || !(ts.isPropertyAccessExpression(p) || ts.isElementAccessExpression(p))) return false;
  if (p.expression !== n) return false;
  // `DfirSelection.events.toggle.call` is NOT a longer path in the sense that matters: the tail is
  // reflection, so the owner's method is still what gets invoked and must stay reportable.
  return !(ts.isPropertyAccessExpression(p) && FUNCTION_INVOKERS.has(p.name.text));
}

function nearbyText(n: ts.Node, sf: ts.SourceFile): string {
  const target = n.parent && ts.isPropertyAccessExpression(n.parent) ? n.parent : n;
  return target.getText(sf).slice(0, 90);
}

export function ownerEscapes(scripts: DashboardScript[], namespace: string): OwnerEscape[] {
  const hits: OwnerEscape[] = [];
  const denotesOwnerOrChild = (n: ts.Node): boolean => {
    if (denotesNamespace(n, namespace)) return true;
    return ts.isPropertyAccessExpression(n) && denotesOwnerOrChild(n.expression);
  };
  for (const s of scripts) {
    const at = (n: ts.Node): number => s.ast.getLineAndCharacterOfPosition(n.getStart(s.ast)).line + 1;
    // Positions that DEFINE the namespace rather than reference it: the `window.DfirFacets` in
    // `window.DfirFacets = { … }`. Collected in a pre-pass rather than read off node.parent, which
    // did not match reliably here.
    const definitionTargets = new Set<number>();
    const findDefs = (n: ts.Node): void => {
      if (ts.isBinaryExpression(n) && n.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
        // The namespace's OWN definition (`window.DfirFacets = {…}`) only. Assigning to a MEMBER —
        // `DfirSelection.events.toggle = fn` — is a method being replaced, which is the opposite of
        // a definition and must stay reportable; treating every assignment target as a definition
        // let that through.
        if (denotesNamespace(n.left, namespace) || !denotesOwnerOrChild(n.left)) {
          definitionTargets.add(n.left.getStart(s.ast));
        }
      }
      ts.forEachChild(n, findDefs);
    };
    ts.forEachChild(s.ast, findDefs);

    const visit = (n: ts.Node): void => {
      // const events = DfirSelection.events
      if (
        ts.isVariableDeclaration(n) &&
        n.initializer &&
        denotesOwnerOrChild(n.initializer) &&
        !denotesNamespace(n.initializer, namespace)
      ) {
        hits.push({ script: s.name, line: at(n), form: "alias", text: n.getText(s.ast).slice(0, 90) });
      }
      // evs = DfirSelection.events  (assignment, not declaration)
      if (
        ts.isBinaryExpression(n) &&
        n.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
        denotesOwnerOrChild(n.right) &&
        !denotesNamespace(n.right, namespace)
      ) {
        hits.push({ script: s.name, line: at(n), form: "alias", text: n.getText(s.ast).slice(0, 90) });
      }
      // ANY reference to the owner that is NOT the callee of a call.
      //
      // Enumerating contexts (argument here, assignment there) is how this kept failing open —
      // review found detached method references stashed in arrays, in object literals and returned
      // from functions, none of which was in the list. So the rule is inverted: an owner or one of
      // its members may appear as the thing being CALLED, and nowhere else. Everything else is a
      // reference this analysis stops following, and there is a supported alternative for the one
      // legitimate case (matcher(), a read-only view).
      if (
        denotesOwnerOrChild(n) &&
        !isCalleePosition(n) &&
        !isPartOfLongerPath(n) &&
        !isPropertyName(n) &&
        !isTypeofOperand(n) &&
        !definitionTargets.has(n.getStart(s.ast))
      ) {
        hits.push({ script: s.name, line: at(n), form: "passed", text: nearbyText(n, s.ast) });
      }
      // DfirSelection.events["toggle"](…) / DfirSelection.events[m](…)
      if (ts.isElementAccessExpression(n) && denotesOwnerOrChild(n.expression)) {
        const arg = n.argumentExpression;
        hits.push({
          script: s.name,
          line: at(n),
          form: arg && ts.isStringLiteral(arg) ? "computed-member" : "dynamic-member",
          text: n.getText(s.ast).slice(0, 90),
        });
      }
      ts.forEachChild(n, visit);
    };
    ts.forEachChild(s.ast, visit);
  }
  return hits;
}

/** A commit made once per element, inside an owner module itself. */
export interface LoopedCommit {
  fn: string;
  line: number;
  /** `direct` is the commit call itself in the loop; `via` names the helper that reaches one. */
  via: string | null;
}

/**
 * Commits an owner module makes once per element, in ANY spelling.
 *
 * The narrow version of this check looked for a bare `commit(` inside a named bulk operation, and
 * review showed two ways past it that both produce the quadratic cost the bulk operations exist to
 * avoid:
 *
 *     addAll(ids)  { for (const id of ids) cell.set(new Set([id])); }   // member call, not `commit(`
 *     hideAll(ids) { for (const id of ids) put(id); }                    // helper that commits
 *
 * So: a function "commits" if it calls any of `commitNames` by bare name OR as a member (`cell.set`),
 * closed transitively over the module's own functions; and a loop enclosing a call to any committer
 * is an offender. Every function in the module is examined, not a hand-listed few — the list was
 * itself a way to be wrong.
 */
export function commitsInsideLoops(script: DashboardScript, commitNames: readonly string[]): LoopedCommit[] {
  const want = new Set(commitNames);
  const fns = functionsOf(script);
  const at = (n: ts.Node): number =>
    script.ast.getLineAndCharacterOfPosition(n.getStart(script.ast)).line + 1;

  /** Names called from inside `node`, bare or as a member, WITHOUT descending into nested functions. */
  const ownCalls = (node: ts.Node): string[] => {
    const out: string[] = [];
    const visit = (n: ts.Node): void => {
      if (n !== node && isFunctionLike(n) && !isIterationCallback(n)) return;
      if (ts.isCallExpression(n)) {
        if (ts.isIdentifier(n.expression)) out.push(n.expression.text);
        else if (ts.isPropertyAccessExpression(n.expression)) out.push(n.expression.name.text);
      }
      ts.forEachChild(n, visit);
    };
    ts.forEachChild(node, visit);
    return out;
  };

  // Which of the module's own functions reach a commit — closed to a fixpoint, so a helper behind a
  // helper counts.
  const commits = new Set<string>();
  for (const f of fns) if (ownCalls(f.node).some((c) => want.has(c))) commits.add(f.name);
  for (let changed = true; changed;) {
    changed = false;
    for (const f of fns) {
      if (commits.has(f.name)) continue;
      if (ownCalls(f.node).some((c) => commits.has(c))) {
        commits.add(f.name);
        changed = true;
      }
    }
  }

  const out: LoopedCommit[] = [];
  for (const f of fns) {
    const visit = (n: ts.Node): void => {
      // Descend into ITERATION callbacks — `ids.forEach(id => cell.set(…))` is the same per-element
      // commit as `for (const id of ids) cell.set(…)`, and skipping every nested function made this
      // blind to it. insideLoop() already treats an iteration callback's body as a loop body.
      // Other nested functions are judged on their own pass.
      if (n !== f.node && isFunctionLike(n) && !isIterationCallback(n)) return;
      if (ts.isCallExpression(n)) {
        const name = ts.isIdentifier(n.expression)
          ? n.expression.text
          : ts.isPropertyAccessExpression(n.expression)
            ? n.expression.name.text
            : null;
        if (name && (want.has(name) || commits.has(name)) && insideLoop(f.node, n.getStart(script.ast))) {
          out.push({ fn: f.name, line: at(n), via: want.has(name) ? null : name });
        }
      }
      ts.forEachChild(n, visit);
    };
    ts.forEachChild(f.node, visit);
  }
  return out;
}

// ── IS A MISSING MODULE'S NAME SAFE TO TOUCH HERE? ───────────────────────────────────────────────
//
// A tier-3 feature module is a separate <script src>. If that request fails the name is simply
// undeclared, and ANY evaluation of it — a call, or a bare reference handed to addEventListener —
// throws a ReferenceError. At the top level of the inline script that throw aborts EVERYTHING AFTER
// IT, which is how blocking one 26 KB file left the dashboard disconnected with unrelated controls
// unwired. `typeof` is the one operation that does not throw on an undeclared identifier, so it is
// the guard.
//
// THE FIRST VERSION OF THIS CHECK ASKED THE WRONG QUESTION. It asked whether some ancestor `if` or
// `?:` MENTIONED `typeof N` anywhere in its condition; it never asked what the condition PROVES, nor
// which BRANCH the reference sat in, and it only ever looked at `N(...)` with a bare identifier
// callee. Seven shapes that all throw were reported as guarded, and mutation-testing the real suite
// caught none of them:
//
//     if (typeof N !== "function") N();                 // inverted
//     if (typeof N === "function") {} else N();          // else branch
//     if (typeof N === "function" || ready) N();         // widened away by an ||
//     if (typeof N === "undefined") N();                 // reads as a guard, means the opposite
//     typeof N === "function" ? 0 : N();                 // wrong arm of the ternary
//     el.addEventListener("click", N);                   // no CallExpression at all
//     const h = N;                                       // nor here
//
// So the question is asked properly now: what does this condition prove about this name, in this
// branch, and every VALUE REFERENCE is asked — which is also what makes `DfirTimelineView.hydrate()`
// visible, since the fragile name there is the ROOT of the member expression, not the method.

/** What a `typeof <name>` test proves, and in which branch it proves it. */
export type TypeofVerdict = "declared-when-true" | "declared-when-false" | "none";

/**
 * Read one comparison as a statement about whether `name` is declared.
 *
 * `"undefined"` is the only string that means UNDECLARED, so it is the pivot: comparing equal to it
 * proves the name is missing when the test passes, comparing equal to anything else proves it is
 * present. Negation swaps the branch. A NON-LITERAL comparand — `typeof N === want` — proves
 * nothing at all, whatever `want` happens to hold at runtime, and saying so is the difference
 * between a guard and a coincidence.
 */
export function typeofTest(cond: ts.Node, name: string): TypeofVerdict {
  if (!ts.isBinaryExpression(cond)) return "none";
  const op = cond.operatorToken.kind;
  const negated =
    op === ts.SyntaxKind.ExclamationEqualsEqualsToken || op === ts.SyntaxKind.ExclamationEqualsToken;
  const positive = op === ts.SyntaxKind.EqualsEqualsEqualsToken || op === ts.SyntaxKind.EqualsEqualsToken;
  if (!negated && !positive) return "none";

  const bare = (e: ts.Node): ts.Node => (ts.isParenthesizedExpression(e) ? bare(e.expression) : e);
  const isTypeofName = (e: ts.Node): boolean => {
    if (!ts.isTypeOfExpression(e)) return false;
    const operand = bare(e.expression);
    return ts.isIdentifier(operand) && operand.text === name;
  };
  const left = bare(cond.left);
  const right = bare(cond.right);
  let literal: ts.Node | null = null;
  if (isTypeofName(left)) literal = right;
  else if (isTypeofName(right)) literal = left;
  else return "none";
  if (!ts.isStringLiteralLike(literal)) return "none";

  const declaredWhenTrue = literal.text === "undefined" ? negated : positive;
  return declaredWhenTrue ? "declared-when-true" : "declared-when-false";
}

/**
 * Does taking `branch` out of `cond` GUARANTEE `name` is declared?
 *
 * The two logical operators are not symmetric and the old check treated them as if they were:
 *
 *   - the TRUE branch of `A && B` was reached only because BOTH held, so either conjunct proving the
 *     name is enough. Its FALSE branch proves nothing — one of them failed and we cannot say which.
 *   - the FALSE branch of `A || B` was reached only because BOTH failed, so either disjunct proving
 *     the name (when false) is enough. Its TRUE branch proves nothing, which is exactly how
 *     `typeof N === "function" || ready` used to pass.
 */
export function guarantees(cond: ts.Node, name: string, branch: boolean): boolean {
  if (ts.isParenthesizedExpression(cond)) return guarantees(cond.expression, name, branch);
  if (ts.isPrefixUnaryExpression(cond) && cond.operator === ts.SyntaxKind.ExclamationToken) {
    return guarantees(cond.operand, name, !branch);
  }
  if (ts.isBinaryExpression(cond)) {
    const op = cond.operatorToken.kind;
    if (op === ts.SyntaxKind.AmpersandAmpersandToken) {
      return branch && (guarantees(cond.left, name, true) || guarantees(cond.right, name, true));
    }
    if (op === ts.SyntaxKind.BarBarToken) {
      return !branch && (guarantees(cond.left, name, false) || guarantees(cond.right, name, false));
    }
  }
  return typeofTest(cond, name) === (branch ? "declared-when-true" : "declared-when-false");
}

/**
 * Is this identifier a place the name's VALUE is read — the thing that throws when it is undeclared?
 *
 * `obj.kevClear` names a property and evaluates nothing; `typeof kevClear` is the guard itself, not a
 * use of it; a declaration or a label is a name being bound rather than read. Everything else is a
 * read, INCLUDING the root of a member expression: the fragile half of `DfirTimelineView.hydrate()`
 * is `DfirTimelineView`, which sits at `parent.expression` and so is not excluded by the
 * property-name rule that hides `hydrate`.
 */
/**
 * Is this node inside the TARGET of a destructuring assignment rather than a value being read?
 *
 * `({ Foo } = src)` and `[Foo] = xs` and `for ({ Foo } of xs)` all WRITE Foo. A write to a name a
 * missing module would have declared does not throw — it is the read that throws — so reporting one
 * is a false positive, and a gate that flags correct code gets switched off.
 *
 * Walks out through the pattern's own shapes only (object/array literals, the value half of a
 * property, parens, spread) so that `({ a: Foo } = x)` and `({ Foo } = x)` both resolve, while a
 * genuine read nested in an initializer — `const o = { Foo }` — stops at the variable declaration.
 */
function isAssignmentTarget(node: ts.Node): boolean {
  let cur: ts.Node = node;
  let parent = cur.parent;
  while (parent) {
    if (ts.isBinaryExpression(parent) && parent.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
      return parent.left === cur;
    }
    // `for ({ Foo } of xs)` / `for ([Foo] in o)` — the initializer is a target, the expression is not.
    if ((ts.isForOfStatement(parent) || ts.isForInStatement(parent)) && parent.initializer === cur) {
      return true;
    }
    if (
      ts.isObjectLiteralExpression(parent) ||
      ts.isArrayLiteralExpression(parent) ||
      ts.isParenthesizedExpression(parent) ||
      ts.isSpreadAssignment(parent) ||
      ts.isSpreadElement(parent) ||
      ts.isShorthandPropertyAssignment(parent) ||
      (ts.isPropertyAssignment(parent) && parent.initializer === cur)
    ) {
      cur = parent;
      parent = cur.parent;
      continue;
    }
    return false;
  }
  return false;
}

function isValueRef(n: ts.Identifier): boolean {
  const p = n.parent;
  if (!p) return true;
  // The guard's own test is not a use.
  if (ts.isTypeOfExpression(p) && p.expression === n) return false;
  // `obj.kevClear` / `{ kevClear: v }` / `class { kevClear() {} }` — a property NAME.
  if (
    (ts.isPropertyAccessExpression(p) ||
      ts.isPropertyAssignment(p) ||
      ts.isMethodDeclaration(p) ||
      ts.isMethodSignature(p) ||
      ts.isPropertyDeclaration(p) ||
      ts.isGetAccessorDeclaration(p) ||
      ts.isSetAccessorDeclaration(p) ||
      ts.isEnumMember(p)) &&
    p.name === n
  ) {
    return false;
  }
  // `const { kevClear: local } = o` — both halves bind, neither reads a global.
  if (ts.isBindingElement(p) && (p.propertyName === n || p.name === n)) return false;
  if ((ts.isImportSpecifier(p) || ts.isExportSpecifier(p)) && (p.propertyName === n || p.name === n)) {
    return false;
  }
  // Labels are their own namespace.
  if (ts.isLabeledStatement(p) && p.label === n) return false;
  if ((ts.isBreakStatement(p) || ts.isContinueStatement(p)) && p.label === n) return false;
  // SHORTHAND IS A READ IN A LITERAL AND A WRITE IN A PATTERN, and TypeScript spells both
  // `ShorthandPropertyAssignment`: `const w = { kevClear }` evaluates the binding, while
  // `({ kevClear } = src)` assigns to it. Only the first can throw when the module is missing —
  // the second is a destructuring assignment, which is how the node reaches an `=` from its left.
  if (ts.isShorthandPropertyAssignment(p) && isAssignmentTarget(p)) return false;
  // A name being DECLARED. `{ kevClear }` shorthand is deliberately absent: it reads the value.
  const declares =
    ts.isVariableDeclaration(p) ||
    ts.isFunctionDeclaration(p) ||
    ts.isFunctionExpression(p) ||
    ts.isClassDeclaration(p) ||
    ts.isClassExpression(p) ||
    ts.isParameter(p) ||
    ts.isNamespaceImport(p) ||
    ts.isImportClause(p);
  return !(declares && p.name === n);
}

/** Every place `name`'s value is read in this script, with its line. */
function refsTo(script: DashboardScript, name: string): Array<{ node: ts.Identifier; line: number }> {
  const out: Array<{ node: ts.Identifier; line: number }> = [];
  const visit = (n: ts.Node): void => {
    if (ts.isIdentifier(n) && n.text === name && isValueRef(n)) {
      out.push({
        node: n,
        line: script.ast.getLineAndCharacterOfPosition(n.getStart(script.ast)).line + 1,
      });
    }
    ts.forEachChild(n, visit);
  };
  ts.forEachChild(script.ast, visit);
  return out;
}

/** Does control always leave the enclosing block by the end of this statement? */
function alwaysExits(s: ts.Statement | undefined): boolean {
  if (!s) return false;
  if (ts.isReturnStatement(s) || ts.isThrowStatement(s)) return true;
  if (ts.isBreakStatement(s) || ts.isContinueStatement(s)) return true;
  if (ts.isBlock(s)) return s.statements.some(alwaysExits);
  return false;
}

/** The statement list of a node that HAS one, so preceding siblings can be examined. */
function statementsOf(n: ts.Node): readonly ts.Statement[] | null {
  if (ts.isBlock(n) || ts.isSourceFile(n) || ts.isCaseClause(n) || ts.isDefaultClause(n)) {
    return n.statements;
  }
  return null;
}

/**
 * `if (typeof N !== "function") return; N();`
 *
 * THE IDIOM THIS FILE MUST NOT PUNISH. It is correct code and it is house style on this page and in
 * js/graph-view.js and js/dashboard-geo.js — the guard is a preceding SIBLING, not an ancestor, so an
 * ancestor walk alone reports every line after it. Anything reached after an earlier
 * `if (C) return|throw|continue|break` was reached with C false, so a C that proves the name in its
 * false branch guards the rest of the block. The mirror image (`else` exits, so C held) is the same
 * argument and is accepted too.
 */
function precedingGuardExits(stmts: readonly ts.Statement[], child: ts.Node, name: string): boolean {
  const idx = stmts.indexOf(child as ts.Statement);
  if (idx < 0) return false;
  for (let i = 0; i < idx; i++) {
    const s = stmts[i];
    if (!ts.isIfStatement(s)) continue;
    if (alwaysExits(s.thenStatement) && guarantees(s.expression, name, false)) return true;
    if (alwaysExits(s.elseStatement) && guarantees(s.expression, name, true)) return true;
  }
  return false;
}

/**
 * Is this reference reached only when `name` is known to be declared?
 *
 * WHICH CHILD WE CAME FROM is the whole point: `thenStatement` and `elseStatement` of the same `if`
 * are opposite claims, as are `whenTrue`/`whenFalse`, and the RIGHT operand of `&&` is the
 * `typeof N === "function" && N()` idiom while its left operand is the test itself.
 *
 * The walk does NOT stop at a function boundary, on purpose: a listener registered inside a guarded
 * branch is registered only when the guard held, so its body cannot run in the missing-module world.
 */
function isGuarded(ref: ts.Node, name: string): boolean {
  let child: ts.Node = ref;
  let p: ts.Node | undefined = ref.parent;
  while (p) {
    if (ts.isIfStatement(p)) {
      if (child === p.thenStatement && guarantees(p.expression, name, true)) return true;
      if (child === p.elseStatement && guarantees(p.expression, name, false)) return true;
    } else if (ts.isConditionalExpression(p)) {
      if (child === p.whenTrue && guarantees(p.condition, name, true)) return true;
      if (child === p.whenFalse && guarantees(p.condition, name, false)) return true;
    } else if (ts.isBinaryExpression(p) && child === p.right) {
      const op = p.operatorToken.kind;
      if (op === ts.SyntaxKind.AmpersandAmpersandToken && guarantees(p.left, name, true)) return true;
      if (op === ts.SyntaxKind.BarBarToken && guarantees(p.left, name, false)) return true;
    }
    const stmts = statementsOf(p);
    if (stmts && precedingGuardExits(stmts, child, name)) return true;
    child = p;
    p = p.parent;
  }
  return false;
}

/**
 * Every reference to `name` that is NOT proven safe by a `typeof` guard.
 *
 * A try/catch is deliberately NOT accepted here even though it does contain the throw: these entry
 * points are meant to say so on screen when their module is missing, and a bare
 * `try { N(); } catch {}` swallows that. topLevelUnguardedRefs() below, which asks the narrower
 * question of what would abort the script, does honour it.
 */
export function unguardedRefs(script: DashboardScript, name: string): number[] {
  return refsTo(script, name)
    .filter((r) => !isGuarded(r.node, name))
    .map((r) => r.line);
}

/** The historic name — kept so existing callers compile. Calls were never the only hazard. */
export const unguardedCalls = unguardedRefs;

/** `(function () { … })()` / `(() => { … })()` — a function that runs where it is written. */
function isImmediatelyInvoked(fn: ts.Node): boolean {
  let cur: ts.Node = fn;
  while (cur.parent && ts.isParenthesizedExpression(cur.parent)) cur = cur.parent;
  const p = cur.parent;
  return !!p && ts.isCallExpression(p) && p.expression === cur;
}

/**
 * Does this reference evaluate while the script is still parsing, with nothing to catch a throw?
 *
 * AN IIFE THAT RUNS AT LOAD COUNTS AS TOP LEVEL. This is the same call domAccessOutsideFunctions()
 * makes and for the same reason: `(() => { … })()` executes exactly where bare top-level code would,
 * and a ReferenceError inside one propagates straight out and takes the rest of the script with it.
 * dashboard.html's DfirTimelineView.hydrate() sits inside one and IS a real hazard. A function that
 * is merely DEFINED here is not — it runs later, on an event, where a throw is contained to that one
 * interaction.
 *
 * A `try` WITH a catch clause contains the throw, so a reference inside one is not this hazard. A
 * bare `try`/`finally` does not, and is not accepted.
 */
function runsAtLoad(ref: ts.Node): boolean {
  let child: ts.Node = ref;
  let p: ts.Node | undefined = ref.parent;
  while (p) {
    if (ts.isTryStatement(p) && p.catchClause && child === p.tryBlock) return false;
    if (isFunctionLike(p) && !isImmediatelyInvoked(p)) return false;
    child = p;
    p = p.parent;
  }
  return true;
}

/**
 * The unguarded references that would abort the rest of the script — top-level, uncaught.
 *
 * This is the set that matters for a <script src> that 404s. Everything else fails one feature.
 */
export function topLevelUnguardedRefs(script: DashboardScript, name: string): number[] {
  return refsTo(script, name)
    .filter((r) => !isGuarded(r.node, name) && runsAtLoad(r.node))
    .map((r) => r.line);
}

/** A literal condition's truth value, or null if it is not decidable from the text. */
function staticTruth(e: ts.Node): boolean | null {
  if (ts.isParenthesizedExpression(e)) return staticTruth(e.expression);
  if (e.kind === ts.SyntaxKind.TrueKeyword) return true;
  if (e.kind === ts.SyntaxKind.FalseKeyword) return false;
  if (ts.isNumericLiteral(e)) return Number(e.text) !== 0;
  if (ts.isStringLiteralLike(e)) return e.text.length > 0;
  if (ts.isPrefixUnaryExpression(e) && e.operator === ts.SyntaxKind.ExclamationToken) {
    const inner = staticTruth(e.operand);
    return inner === null ? null : !inner;
  }
  return null;
}

/** Is this child of `p` a branch the text itself rules out — `if (false) { … }`? */
function isDeadBranch(p: ts.Node, child: ts.Node): boolean {
  if (ts.isIfStatement(p)) {
    const t = staticTruth(p.expression);
    if (t === false && child === p.thenStatement) return true;
    if (t === true && child === p.elseStatement) return true;
  }
  if (ts.isConditionalExpression(p)) {
    const t = staticTruth(p.condition);
    if (t === false && child === p.whenTrue) return true;
    if (t === true && child === p.whenFalse) return true;
  }
  if (ts.isWhileStatement(p) && child === p.statement && staticTruth(p.expression) === false) return true;
  if (ts.isForStatement(p) && child === p.statement && p.condition && staticTruth(p.condition) === false) {
    return true;
  }
  return false;
}

/**
 * The name by which this function can be INVOKED as a bare identifier, or null if there is none.
 *
 * Only a declaration, a named function expression and `const f = () => …` qualify. An anonymous
 * callback, an object-literal method and an IIFE are TRANSPARENT — nobody can call them by name, so
 * they are not separately-reachable units; whether their body runs is entirely a question about the
 * code that registered them, which is the enclosing unit.
 */
function invocableName(fn: ts.Node): string | null {
  if (isImmediatelyInvoked(fn)) return null;
  if (ts.isFunctionDeclaration(fn) && fn.name) return fn.name.text;
  if (ts.isFunctionExpression(fn) && fn.name) return fn.name.text;
  const p = fn.parent;
  if (p && ts.isVariableDeclaration(p) && ts.isIdentifier(p.name) && p.initializer === fn) return p.name.text;
  return null;
}

const TOP_LEVEL_UNIT = "<top-level>";

/**
 * Does this script make a REACHABLE call to `name`?
 *
 * A comment mentioning it never counted. Neither, now, do the two shapes review used to walk past
 * this: a call inside `if (false)`, and a call inside a function that nothing in the script ever
 * names. Both leave the text saying `initTicketIntegrations()` while the page never runs it, which
 * is the exact failure the gate exists to catch.
 *
 * WHY NOT buildCallGraph()/reachableFrom() WHOLESALE. reachableFrom IS reused for the closure — that
 * part fits exactly. buildCallGraph does not: it drops every `<anonymous…>` function, so a call made
 * from a top-level callback would vanish; it records CALLS only, so `el.onclick = wire` never marks
 * wire live; and it has no notion of a root, which is the half this question is actually about. So
 * the edges are collected here, from top-level code outward, over every mention rather than calls
 * alone — a function handed somewhere is a function that can run.
 */
export function callsByName(script: DashboardScript, name: string): boolean {
  const mentions = new Map<string, Set<string>>([[TOP_LEVEL_UNIT, new Set<string>()]]);
  const sites: Array<{ unit: string }> = [];

  const walk = (n: ts.Node, unit: string): void => {
    ts.forEachChild(n, (c) => {
      if (isDeadBranch(n, c)) return;
      let next = unit;
      if (isFunctionLike(c)) {
        const invocable = invocableName(c);
        if (invocable !== null) {
          next = invocable;
          if (!mentions.has(next)) mentions.set(next, new Set<string>());
        }
      }
      if (ts.isIdentifier(c) && isValueRef(c)) mentions.get(unit)?.add(c.text);
      if (ts.isCallExpression(c) && ts.isIdentifier(c.expression) && c.expression.text === name) {
        sites.push({ unit });
      }
      walk(c, next);
    });
  };
  walk(script.ast, TOP_LEVEL_UNIT);

  const live = reachableFrom(mentions, [TOP_LEVEL_UNIT]);
  return sites.some((s) => live.has(s.unit));
}

/**
 * Every DOM access that runs at module scope rather than inside a function.
 *
 * These files are <head> scripts, so anything here executes before the body is parsed: a capture is
 * null, a listener attaches to nothing, and the feature is silently absent. The indentation-based
 * check this replaced missed `window.document?.getElementById(...)`, which is the same access by a
 * spelling a pattern does not recognise — so the question is asked structurally: is this a member
 * access rooted at `document`, and is it outside every function?
 *
 * "OUTSIDE EVERY FUNCTION" IS THE WRONG QUESTION, and asking it was the third hole in this check.
 * What runs before the markup exists is what runs DURING LOAD, and a function the module calls on
 * the way down runs during load exactly as bare top-level code does. Review moved the Notion
 * listener into such a helper, deleted the initializer that used to wire it, and every one of the
 * 180 tests stayed green while a runtime fixture found zero click handlers. So the walk carries a
 * LOAD SCOPE instead of a boolean: the file's top level, the body of any IIFE it evaluates, and the
 * body of any local function something in that scope CALLS.
 *
 * The same walk carries the locals bound to the document, because `const doc = document` renames
 * the root and the chain no longer bottoms out at the identifier this was looking for.
 *
 * WHAT IT DELIBERATELY DOES NOT CLAIM. "Called during load" is decided structurally, from a call
 * whose callee is a bare name declared in a scope already known to run at load — plus a function
 * handed to one of the Array methods that invoke synchronously. Everything indirect is out of
 * reach without a type system and is NOT reported: `table[key]()`, `(cond ? a : b)()`,
 * `fn.call(...)` through a variable, `eval`/`new Function`, a helper reached only as a property of
 * an object, and a document obtained from a function's return value. Deferred registration —
 * `addEventListener`, `setTimeout`, `queueMicrotask`, a promise callback — is not load-time work
 * and is correctly silent. A check that claimed those too would be guessing, and a gate that
 * guesses is how this issue got here.
 */
export function domAccessOutsideFunctions(script: DashboardScript): string[] {
  const sf = script.ast;
  const out: string[] = [];
  const at = (n: ts.Node): number => sf.getLineAndCharacterOfPosition(n.getStart(sf)).line + 1;
  const report = (n: ts.Node): void => {
    out.push(`${script.name}:${at(n)} ${n.getText(sf).slice(0, 70)}`);
  };

  // `window.document` and its computed twin `window["document"]`. The dotted spelling was already
  // covered; the bracketed one is the same access and was silent.
  const isGlobalDocument = (n: ts.Node): boolean => {
    if (ts.isPropertyAccessExpression(n)) {
      return (
        n.name.text === "document" && ts.isIdentifier(n.expression) && GLOBAL_ROOTS.has(n.expression.text)
      );
    }
    if (ts.isElementAccessExpression(n)) {
      return (
        ts.isIdentifier(n.expression) &&
        GLOBAL_ROOTS.has(n.expression.text) &&
        ts.isStringLiteralLike(n.argumentExpression) &&
        n.argumentExpression.text === "document"
      );
    }
    return false;
  };

  /** Does this member chain bottom out at the document — directly, via a global, or via an alias? */
  const rootsAtDocument = (n: ts.Node, aliases: ReadonlySet<string>): boolean => {
    let cur: ts.Node = n;
    for (;;) {
      if (ts.isIdentifier(cur)) return cur.text === "document" || aliases.has(cur.text);
      if (isGlobalDocument(cur)) return true;
      if (ts.isPropertyAccessExpression(cur) || ts.isElementAccessExpression(cur)) cur = cur.expression;
      else if (ts.isNonNullExpression(cur) || ts.isParenthesizedExpression(cur)) cur = cur.expression;
      else return false;
    }
  };

  // AN IIFE WRAPPER IS STILL MODULE SCOPE. Every one of these modules is `(function () { … })()`,
  // so treating any enclosing function as "inside a function" made this check vacuous — it could
  // never fire, on any module. The wrapper runs at load exactly as bare top-level code would.
  /** The function an IIFE invokes, unwrapping the parentheses, or null if this is not one. */
  const iifeBody = (n: ts.Node): ts.Node | null => {
    if (!ts.isCallExpression(n)) return null;
    let callee: ts.Node = n.expression;
    while (ts.isParenthesizedExpression(callee)) callee = callee.expression;
    // `(function () { … }).call(this)` runs just as immediately as `(function () { … })()`.
    if (
      ts.isPropertyAccessExpression(callee) &&
      (callee.name.text === "call" || callee.name.text === "apply")
    ) {
      callee = callee.expression;
      while (ts.isParenthesizedExpression(callee)) callee = callee.expression;
    }
    return ts.isFunctionExpression(callee) || ts.isArrowFunction(callee) ? callee.body : null;
  };

  // Array methods that invoke their callback SYNCHRONOUSLY, so `ids.forEach(wire)` at load scope
  // runs wire at load. setTimeout/queueMicrotask/then are deliberately absent: those run after the
  // parser is done, which is the whole point of deferring to them.
  const SYNC_INVOKERS = new Set([
    "forEach",
    "map",
    "filter",
    "some",
    "every",
    "find",
    "findIndex",
    "flatMap",
    "reduce",
    "sort",
  ]);

  /** What a scope knows: its callable local functions, and its locals bound to the document. */
  interface LoadScope {
    fns: Map<string, ts.Node>;
    docs: Set<string>;
  }

  const collect = (body: ts.Node, outer: LoadScope): LoadScope => {
    const fns = new Map(outer.fns);
    const docs = new Set(outer.docs);
    const walk = (n: ts.Node): void => {
      if (ts.isFunctionDeclaration(n)) {
        if (n.name) fns.set(n.name.text, n);
        return; // its body is a scope of its own, visited only if something calls it
      }
      if (isFunctionLike(n)) return;
      if (ts.isVariableDeclaration(n) && ts.isIdentifier(n.name) && n.initializer) {
        let init: ts.Node = n.initializer;
        while (ts.isParenthesizedExpression(init)) init = init.expression;
        if (ts.isFunctionExpression(init) || ts.isArrowFunction(init)) fns.set(n.name.text, init);
        // ONLY the document itself, never something derived from it: `const box =
        // document.getElementById(...)` binds an element, and treating that as an alias would
        // report every later use of a capture the module made perfectly legitimately.
        else if ((ts.isIdentifier(init) || isGlobalDocument(init)) && rootsAtDocument(init, docs)) {
          docs.add(n.name.text);
        }
      }
      ts.forEachChild(n, walk);
    };
    // To a fixpoint, so `const d2 = doc` is an alias whichever order the two lines appear in.
    for (let seen = -1; seen !== docs.size;) {
      seen = docs.size;
      ts.forEachChild(body, walk);
    }
    return { fns, docs };
  };

  const visited = new Set<ts.Node>();

  const scan = (body: ts.Node, outer: LoadScope): void => {
    const scope = collect(body, outer);
    const enter = (fn: ts.Node): void => {
      if (visited.has(fn)) return; // and it stops mutual recursion walking forever
      visited.add(fn);
      const inner = (fn as ts.FunctionLikeDeclaration).body;
      if (inner) scan(inner, scope);
    };
    const visit = (n: ts.Node): void => {
      const immediate = iifeBody(n);
      if (immediate) {
        scan(immediate, scope);
        return;
      }
      if (ts.isCallExpression(n)) {
        const callee = n.expression;
        if (ts.isIdentifier(callee) && scope.fns.has(callee.text))
          enter(scope.fns.get(callee.text) as ts.Node);
        if (ts.isPropertyAccessExpression(callee) && SYNC_INVOKERS.has(callee.name.text)) {
          for (const arg of n.arguments) {
            if (ts.isIdentifier(arg) && scope.fns.has(arg.text)) enter(scope.fns.get(arg.text) as ts.Node);
          }
        }
        ts.forEachChild(n, visit);
        return;
      }
      if (isFunctionLike(n)) return; // judged on its own pass, only if something calls it at load
      if (ts.isPropertyAccessExpression(n) || ts.isElementAccessExpression(n)) {
        if (rootsAtDocument(n, scope.docs)) report(n);
      }
      // `const { body } = document` reads a property of the document at load just as surely as
      // `document.body` does, and the initializer alone is a bare identifier this would not flag.
      if (
        ts.isVariableDeclaration(n) &&
        n.initializer &&
        !ts.isIdentifier(n.name) &&
        rootsAtDocument(n.initializer, scope.docs)
      ) {
        report(n);
      }
      ts.forEachChild(n, visit);
    };
    ts.forEachChild(body, visit);
  };

  scan(sf, { fns: new Map(), docs: new Set() });
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
/**
 * Array methods whose callback runs once per element — a loop written as a call.
 *
 * These are here because leaving them out made the loop check miss the very shape it was written
 * for. Three of the four sites js/dashboard-selection.js replaced were `.forEach(cb => …)`, so a
 * gate that recognised only `for`/`while` reported `inLoop: false` for a re-introduction of the
 * exact quadratic regression it exists to prevent. Syntax is not the property being tested;
 * "does this run once per element" is.
 */
const ITERATION_METHODS = new Set([
  "forEach",
  "map",
  "filter",
  "reduce",
  "reduceRight",
  "some",
  "every",
  "flatMap",
  "find",
  "findLast",
  "findIndex",
  "findLastIndex",
  "sort",
]);

/** Is this node a call whose callback argument runs per element? */
function isIterationCall(n: ts.Node): n is ts.CallExpression {
  return (
    ts.isCallExpression(n) &&
    ts.isPropertyAccessExpression(n.expression) &&
    ITERATION_METHODS.has(n.expression.name.text)
  );
}

export function insideLoop(node: ts.Node, pos: number): boolean {
  let found = false;
  const visit = (n: ts.Node): void => {
    if (found) return;
    const isLoop =
      ts.isForStatement(n) ||
      ts.isForOfStatement(n) ||
      ts.isForInStatement(n) ||
      ts.isWhileStatement(n) ||
      ts.isDoStatement(n) ||
      // `xs.forEach(x => …)` — the callback body is a loop body. Only the ARGUMENTS count, not the
      // receiver: `getIds().forEach(…)` does not put getIds() itself in a loop.
      (isIterationCall(n) && n.arguments.some((a) => a.pos <= pos && a.end >= pos));
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

// ── A TOP-LEVEL REFERENCE TO A MODULE'S GLOBAL, IN ANY SHAPE ─────────────────────────────────────
//
// unguardedCalls() above answers a narrower question than its name suggests: it finds
// CallExpressions whose callee is a bare Identifier, anywhere in the script. That is ONE of the
// shapes a missing module throws in, and the page contains the others.
// `addEventListener("click", kevImportUrl)` throws while the ARGUMENT is evaluated, with no call
// anywhere in the expression; `DfirTimelineView.hydrate({…})` throws on the property access, whose
// callee is not an Identifier. Both abort the rest of the inline script exactly as a bare call
// does, and neither was visible to a CallExpression-with-Identifier-callee visitor.
//
// So this asks the question the failure actually poses: does a reference to a name that only a
// /js/ module declares get EVALUATED at load, on a path that has not first established the name
// exists? Shape-independent, and scoped to load time — the ~600 references from inside functions
// are contained to one interaction and are not this gate's business.

/**
 * Every function this script declares under a name, so a load-time call can be followed into one.
 *
 * First declaration wins: a redeclared name is a different bug, and either body answers "does
 * load-time code reach a reference to a missing module" the same way.
 */
function declaredFunctionsOf(script: DashboardScript): Map<string, ts.Node> {
  const out = new Map<string, ts.Node>();
  for (const f of functionsOf(script)) {
    if (f.name.startsWith("<anonymous")) continue;
    if (!out.has(f.name)) out.set(f.name, f.node);
  }
  return out;
}

/**
 * The names a call expression could invoke, in every spelling the page actually uses.
 *
 * `f()` · `(f)()` · `f.call(…)` · `f.apply(…)` · `window.f()` · `window["f"]()`, plus any helper
 * handed off BY NAME as an argument — `ready(initTicketIntegrations)` invokes it as surely as
 * writing the call. Over-collecting is safe: a name that is not a declared function is dropped by
 * the caller, so an extra spelling costs one map lookup that misses.
 */
/** `window` · `globalThis` · `self` — the roots through which a page-level function is itself. */
function isGlobalRoot(n: ts.Node): boolean {
  let cur: ts.Node = n;
  while (ts.isParenthesizedExpression(cur)) cur = cur.expression;
  return ts.isIdentifier(cur) && GLOBAL_ROOTS.has(cur.text);
}

function invokedNames(n: ts.CallExpression): string[] {
  const names: string[] = [];
  let callee: ts.Node = n.expression;
  while (ts.isParenthesizedExpression(callee)) callee = callee.expression;
  if (ts.isIdentifier(callee)) names.push(callee.text);
  else if (ts.isPropertyAccessExpression(callee)) {
    // `f.call(…)` / `f.apply(…)` — the invoked function is the OBJECT, not the property.
    if (callee.name.text === "call" || callee.name.text === "apply") {
      let target: ts.Node = callee.expression;
      while (ts.isParenthesizedExpression(target)) target = target.expression;
      if (ts.isIdentifier(target)) names.push(target.text);
    } else if (isGlobalRoot(callee.expression)) {
      // ONLY THROUGH A GLOBAL ROOT. `window.boot()` IS the page-level `boot`; `api.boot()` is
      // somebody else's method that merely shares the spelling, and following it would walk a body
      // that never runs at load — reporting hazards that cannot happen. (Found by Codex review of
      // the sibling #477 change, which had the same unrestricted branch.)
      names.push(callee.name.text);
    }
  } else if (
    ts.isElementAccessExpression(callee) &&
    ts.isStringLiteralLike(callee.argumentExpression) &&
    isGlobalRoot(callee.expression)
  ) {
    names.push(callee.argumentExpression.text);
  }
  for (const a of n.arguments) if (ts.isIdentifier(a)) names.push(a.text);
  return names;
}

/**
 * Visit every node that RUNS when the script loads — everything outside a function, IIFE bodies,
 * and TRANSITIVELY the body of any declared function those reach by calling it.
 *
 * AN IIFE RUNS AT LOAD. Six of the page's load-time blocks are `(() => { … })()`, and treating any
 * enclosing function as "contained" would have hidden every one of them — the same mistake
 * domAccessOutsideFunctions() above had to correct.
 *
 * SO DOES AN ORDINARY HELPER THAT LOAD-TIME CODE CALLS (#476). Stopping at the syntactic region left
 * exactly one hop invisible, and one hop was enough to ship a page that dies: `renderExcludeChips()`
 * held a bare `DfirTimelineView` reference and a top-level statement called it, so blocking that
 * module threw a ReferenceError that aborted the rest of the inline script while every gate stayed
 * green. Rewriting a guarded call as `function boot() { … } boot();` reproduced it exactly.
 *
 * The fixpoint is the shape calleesInsideLoops() already uses for the loop checker, whose own
 * contract test is "no function reachable from a loop through ANY number of hops commits". A
 * function merely DEFINED at load is still not this hazard — it runs later, on an event, where a
 * throw is contained to one interaction. Being CALLED is the property that matters.
 */
function walkLoadTime(script: DashboardScript, fn: (n: ts.Node) => void): void {
  const iifeBodyOf = (n: ts.CallExpression): ts.Node | null => {
    let callee: ts.Node = n.expression;
    while (ts.isParenthesizedExpression(callee)) callee = callee.expression;
    if (ts.isFunctionExpression(callee) || ts.isArrowFunction(callee)) return callee.body;
    // `(function(){ … }).call(this)` invokes it just as directly as `(function(){ … })()`.
    if (
      ts.isPropertyAccessExpression(callee) &&
      (callee.name.text === "call" || callee.name.text === "apply")
    ) {
      let target: ts.Node = callee.expression;
      while (ts.isParenthesizedExpression(target)) target = target.expression;
      if (ts.isFunctionExpression(target) || ts.isArrowFunction(target)) return target.body;
    }
    return null;
  };

  const declared = declaredFunctionsOf(script);
  const pending: string[] = [];
  const entered = new Set<string>();

  const go = (n: ts.Node): void => {
    if (ts.isCallExpression(n)) {
      for (const name of invokedNames(n)) if (declared.has(name)) pending.push(name);
      const body = iifeBodyOf(n);
      if (body) {
        fn(n);
        ts.forEachChild(body, go);
        // The ARGUMENTS of an IIFE are evaluated at load too — `(fn => …)(DfirTimelineView)`.
        for (const arg of n.arguments) go(arg);
        return;
      }
    }
    if (isFunctionLike(n)) return;
    fn(n);
    ts.forEachChild(n, go);
  };

  ts.forEachChild(script.ast, go);

  // Fixpoint over what load-time code calls. `entered` also breaks recursion, direct or mutual.
  while (pending.length > 0) {
    const name = pending.shift() as string;
    if (entered.has(name)) continue;
    entered.add(name);
    // Walking the DECLARATION's children rather than the body alone keeps default parameter values
    // in scope — `function f(x = DfirTimelineView.id) {}` evaluates that default on every call.
    ts.forEachChild(declared.get(name) as ts.Node, go);
  }
}

/**
 * Every identifier this script READS without binding it anywhere in scope.
 *
 * The question behind it: does every name the page calls actually exist? A missing module, a typo,
 * a renamed function and a deleted one all look the same at runtime — a ReferenceError that aborts
 * whatever was running — and all four are decidable BEFORE merge, because this is a closed world.
 * Every name the page may legitimately use is declared in the page, published by a module it loads,
 * or a browser/JS built-in.
 *
 * SCOPE-AWARE, because the naive version is useless. The inline script references ~2,570 distinct
 * identifiers and ~1,350 of them are locals (`e`, `msg`, `btn`, `i`) or built-ins; reporting those
 * buries the handful that matter. Tracking a real scope chain — parameters, var/let/const, function
 * and class declarations, catch bindings, destructuring patterns, labels — takes it to 50, of which
 * 48 are built-ins.
 *
 * `var` and function declarations HOIST to the enclosing FUNCTION, not the block, which is why the
 * chain carries a separate function-scope flag. Getting that wrong makes every `var` inside an `if`
 * read as free. Declarations are collected before the bodies are walked, too: a function called
 * above its own declaration is legal and this page does it constantly.
 */
export function freeIdentifiers(script: DashboardScript): Map<string, number> {
  const out = new Map<string, number>();
  const bump = (n: string): void => {
    out.set(n, (out.get(n) ?? 0) + 1);
  };

  interface Scope {
    names: Set<string>;
    fn: boolean;
    parent: Scope | null;
  }
  const declare = (sc: Scope, name: string, hoists: boolean): void => {
    let target = sc;
    if (hoists) while (!target.fn && target.parent) target = target.parent;
    target.names.add(name);
  };
  const bound = (sc: Scope | null, name: string): boolean => {
    for (let s = sc; s; s = s.parent) if (s.names.has(name)) return true;
    return false;
  };
  const bindPattern = (name: ts.BindingName, sc: Scope, hoists: boolean): void => {
    if (ts.isIdentifier(name)) {
      declare(sc, name.text, hoists);
      return;
    }
    for (const el of name.elements) {
      if (ts.isBindingElement(el)) bindPattern(el.name, sc, hoists);
    }
  };

  const hoistInto = (nodes: readonly ts.Node[], sc: Scope): void => {
    const seen = (n: ts.Node): void => {
      if (ts.isFunctionDeclaration(n) && n.name) declare(sc, n.name.text, true);
      else if (ts.isClassDeclaration(n) && n.name) declare(sc, n.name.text, false);
      else if (ts.isVariableStatement(n)) {
        const hoists = !(n.declarationList.flags & (ts.NodeFlags.Let | ts.NodeFlags.Const));
        for (const d of n.declarationList.declarations) bindPattern(d.name, sc, hoists);
      }
      // `var` escapes blocks, loops and try, so keep descending through statement containers only.
      if (
        ts.isBlock(n) ||
        ts.isIfStatement(n) ||
        ts.isForStatement(n) ||
        ts.isForOfStatement(n) ||
        ts.isForInStatement(n) ||
        ts.isWhileStatement(n) ||
        ts.isDoStatement(n) ||
        ts.isTryStatement(n) ||
        ts.isCatchClause(n) ||
        ts.isSwitchStatement(n) ||
        ts.isCaseBlock(n) ||
        ts.isCaseClause(n) ||
        ts.isDefaultClause(n) ||
        ts.isLabeledStatement(n)
      ) {
        ts.forEachChild(n, seen);
      }
    };
    for (const n of nodes) seen(n);
  };

  const walk = (n: ts.Node, sc: Scope): void => {
    if (isFunctionLike(n)) {
      const inner: Scope = { names: new Set(), fn: true, parent: sc };
      const fn = n as ts.FunctionLikeDeclaration;
      // A named function expression can call itself by name from inside its own body.
      if ((ts.isFunctionDeclaration(fn) || ts.isFunctionExpression(fn)) && fn.name) {
        inner.names.add(fn.name.text);
      }
      for (const p of fn.parameters) bindPattern(p.name, inner, false);
      inner.names.add("arguments");
      for (const p of fn.parameters) if (p.initializer) walk(p.initializer, inner);
      if (fn.body) {
        if (ts.isBlock(fn.body)) hoistInto(fn.body.statements, inner);
        walk(fn.body, inner);
      }
      return;
    }
    if (ts.isBlock(n) || ts.isCaseBlock(n)) {
      const inner: Scope = { names: new Set(), fn: false, parent: sc };
      hoistInto(ts.isBlock(n) ? n.statements : n.clauses, inner);
      ts.forEachChild(n, (c) => walk(c, inner));
      return;
    }
    if (ts.isCatchClause(n)) {
      const inner: Scope = { names: new Set(), fn: false, parent: sc };
      if (n.variableDeclaration) bindPattern(n.variableDeclaration.name, inner, false);
      hoistInto(n.block.statements, inner);
      ts.forEachChild(n.block, (c) => walk(c, inner));
      return;
    }
    if (ts.isForStatement(n) || ts.isForOfStatement(n) || ts.isForInStatement(n)) {
      const inner: Scope = { names: new Set(), fn: false, parent: sc };
      const init = n.initializer;
      if (init && ts.isVariableDeclarationList(init)) {
        for (const d of init.declarations) bindPattern(d.name, inner, false);
      }
      ts.forEachChild(n, (c) => walk(c, inner));
      return;
    }
    if (ts.isIdentifier(n)) {
      const p = n.parent;
      if (!p) return;
      // Not a READ: a property name, a name being declared, or a label.
      if (ts.isPropertyAccessExpression(p) && p.name === n) return;
      if (ts.isPropertyAssignment(p) && p.name === n) return;
      if (ts.isMethodDeclaration(p) && p.name === n) return;
      if (ts.isBindingElement(p) && (p.propertyName === n || p.name === n)) return;
      if (ts.isLabeledStatement(p) && p.label === n) return;
      if ((ts.isBreakStatement(p) || ts.isContinueStatement(p)) && p.label === n) return;
      if (ts.isVariableDeclaration(p) && p.name === n) return;
      if (ts.isFunctionDeclaration(p) && p.name === n) return;
      if (ts.isClassDeclaration(p) && p.name === n) return;
      if (ts.isParameter(p) && p.name === n) return;
      if (!bound(sc, n.text)) bump(n.text);
      return;
    }
    ts.forEachChild(n, (c) => walk(c, sc));
  };

  const top: Scope = { names: new Set(), fn: true, parent: null };
  hoistInto(script.ast.statements, top);
  ts.forEachChild(script.ast, (c) => walk(c, top));
  return out;
}

/**
 * Every place `name` is CALLED on a path that runs at load, with its line.
 *
 * DELIBERATELY NARROWER THAN callsByName(), which answers "is this name called anywhere the page
 * can reach" — a different question, and the wrong one for an initializer. Review found three
 * shapes that satisfied reachability while the feature never initialised:
 *
 *   document.addEventListener("dfir-never", () => initSwimlane());   // never fires
 *   function dead() { initSwimlane(); } void dead;                   // never called
 *   el.onclick = () => initSwimlane();                               // needs a click
 *
 * walkLoadTime refuses to enter a function body that is not immediately invoked, so all three are
 * invisible here and only a real load-time call counts. Returning every site rather than a boolean
 * is what lets a caller demand EXACTLY ONE: these initializers are not idempotent, and a second
 * call stacks listeners and a ResizeObserver.
 *
 * Callee spellings collapsed on purpose — `(f)()`, `f.call(this)` and `f.apply(null, [])` all
 * invoke f, and an auto-run check that recognised only the bare shape was bypassed by the parens.
 */
export function loadTimeCallsTo(script: DashboardScript, name: string): number[] {
  const out: number[] = [];
  const at = (n: ts.Node): number =>
    script.ast.getLineAndCharacterOfPosition(n.getStart(script.ast)).line + 1;
  walkLoadTime(script, (n) => {
    if (!ts.isCallExpression(n)) return;
    let callee: ts.Node = n.expression;
    while (ts.isParenthesizedExpression(callee)) callee = callee.expression;
    // `f.call(…)` / `f.apply(…)` — the invoked function is the object, not the property.
    if (
      ts.isPropertyAccessExpression(callee) &&
      (callee.name.text === "call" || callee.name.text === "apply")
    ) {
      let target: ts.Node = callee.expression;
      while (ts.isParenthesizedExpression(target)) target = target.expression;
      if (ts.isIdentifier(target) && target.text === name) out.push(at(n));
      return;
    }
    if (ts.isIdentifier(callee) && callee.text === name) out.push(at(n));
  });
  return out;
}

/** Every name a classic script binds at its top level — all of which are page globals. */
function topLevelNamesOf(script: DashboardScript): string[] {
  const out: string[] = [];
  const collect = (b: ts.BindingName): void => {
    if (ts.isIdentifier(b)) {
      out.push(b.text);
      return;
    }
    for (const el of b.elements) if (ts.isBindingElement(el)) collect(el.name);
  };
  for (const st of script.ast.statements) {
    if (ts.isVariableStatement(st)) {
      for (const d of st.declarationList.declarations) collect(d.name);
    } else if ((ts.isFunctionDeclaration(st) || ts.isClassDeclaration(st)) && st.name) {
      out.push(st.name.text);
    }
  }
  return out;
}

/**
 * The assignment forms that CREATE a global. `window.Dfir ??= …` publishes as surely as `=` does,
 * and topLevelBindings() above already had to learn that; the same list is the right one here.
 */
const PUBLISH_OPS = new Set<ts.SyntaxKind>([
  ts.SyntaxKind.EqualsToken,
  ts.SyntaxKind.QuestionQuestionEqualsToken,
  ts.SyntaxKind.BarBarEqualsToken,
  ts.SyntaxKind.AmpersandAmpersandEqualsToken,
]);

/**
 * Every global name the page's `js/dashboard-*.js` modules put into scope, mapped to its owners.
 *
 * Both halves of "global" are here, because a classic script has two. A top-level `function` or
 * `var` becomes a property of `window`; a top-level `let`/`const`/`class` does not, but it joins
 * the shared global LEXICAL environment and is reachable by bare name from every other script on
 * the page just the same. A harvest that read only one half would miss whichever names the next
 * module happens to declare the other way.
 *
 * `window.X = …` counts only where it runs AT LOAD — at the file's top level or inside its wrapper
 * IIFE. That is not a nicety: js/dashboard-geo.js contains `window.location = …` inside
 * geoDownloadCsv(), which is a NAVIGATION, not a publication, and counting it made the page's
 * ordinary `location.search` read at load look like an unguarded reference to a module global.
 *
 * A list of names would be simpler and would be a claim about the page that nothing checks. The
 * page and the modules are both on disk; ask them.
 */
export function moduleGlobals(scripts: DashboardScript[] = dashboardScripts()): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (const s of scripts) {
    if (!/^js\/dashboard-[^/]+\.js$/.test(s.name)) continue;
    const names = new Set<string>(topLevelNamesOf(s));
    walkLoadTime(s, (n) => {
      if (!ts.isBinaryExpression(n) || !PUBLISH_OPS.has(n.operatorToken.kind)) return;
      const target = n.left;
      if (!ts.isPropertyAccessExpression(target) && !ts.isElementAccessExpression(target)) return;
      if (!ts.isIdentifier(target.expression) || !GLOBAL_ROOTS.has(target.expression.text)) return;
      if (ts.isPropertyAccessExpression(target)) names.add(target.name.text);
      else if (ts.isStringLiteralLike(target.argumentExpression)) {
        names.add(target.argumentExpression.text);
      }
    });
    for (const name of names) out.set(name, [...(out.get(name) ?? []), s.name]);
  }
  return out;
}

/**
 * Every reference to one of `names` that is evaluated at LOAD without a `typeof` guard on that name.
 *
 * Any shape: a call, a bare reference passed as an argument, a namespace member access, an
 * initialiser. All four are in the page, all four throw a ReferenceError when the module that
 * declares the name failed to load.
 *
 * DELIBERATELY STRICTER THAN topLevelUnguardedRefs, and the difference is one case: a reference
 * inside `try { … } catch {}`. That one excuses it, because a caught throw cannot abort the script.
 * This one does not, because review found the other half of the failure: render() called into
 * js/dashboard-collection-plan.js on its first line, both of render()'s callers swallowed the
 * throw, and the write to DfirState.lastState() that every refresh path depends on was simply
 * skipped. The page stayed up, said "connected (live)", and was inert. A catch converts "the script
 * dies" into "the rest of THIS function is skipped, in silence", which is not obviously the better
 * outcome — so at load, wrap the site in a `typeof` test rather than a `catch`.
 */
export function unguardedTopLevelRefs(
  script: DashboardScript,
  names: ReadonlySet<string>,
): Array<{ name: string; line: number }> {
  const out: Array<{ name: string; line: number }> = [];
  const at = (n: ts.Node): number =>
    script.ast.getLineAndCharacterOfPosition(n.getStart(script.ast)).line + 1;
  walkLoadTime(script, (n) => {
    if (!ts.isIdentifier(n) || !names.has(n.text)) return;
    if (!n.parent) return;
    // ONE REFERENCE PREDICATE, NOT TWO — the same argument the guard comment below makes, and it
    // took a second rot to apply it here. A bespoke exclusion list lived at this line and drifted
    // from isValueRef() in three places: it grouped ShorthandPropertyAssignment with
    // PropertyAssignment, so `{ initTicketIntegrations }` — which desugars to `{ N: N }` and
    // EVALUATES the binding — was excluded as if it were a property name, and a missing module
    // threw there with the gate reporting zero; and it missed a renamed destructuring key
    // (`const { N: local } = q`) and a loop label, reporting both as hazards. isValueRef() answered
    // all three correctly and says so in its own comment: "`{ kevClear }` shorthand is deliberately
    // absent: it reads the value." The wrong copy was the one wired in.
    if (!isValueRef(n)) return;
    // ONE GUARD PREDICATE, NOT TWO. This function and topLevelUnguardedRefs were written
    // independently against the same question and kept two answers to it, which differed on
    // `try { N(); } catch {}` — this one demanded a typeof guard the other correctly did not,
    // because a catch already stops the ReferenceError aborting the script. Two implementations of
    // one rule is one that will rot, so this defers to isGuarded and the duplicate is gone.
    if (isGuarded(n, n.text)) return;
    out.push({ name: n.text, line: at(n) });
  });
  return out;
}
