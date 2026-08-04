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

/**
 * Calls to `name` that are NOT wrapped in a `typeof name === "function"` guard.
 *
 * A tier-3 feature module is a separate <script src>. If that request fails the name is undeclared,
 * and an unguarded call throws a ReferenceError that aborts the rest of the inline script — which
 * is how blocking one file left the dashboard disconnected with unrelated controls unwired. `typeof`
 * is the one operation that does not throw on an undeclared identifier, so it is the guard, and
 * this finds any call that skipped it.
 */
export function unguardedCalls(script: DashboardScript, name: string): number[] {
  const out: number[] = [];
  const at = (n: ts.Node): number =>
    script.ast.getLineAndCharacterOfPosition(n.getStart(script.ast)).line + 1;
  const guardsName = (cond: ts.Node): boolean => {
    let found = false;
    const walk = (n: ts.Node): void => {
      if (ts.isTypeOfExpression(n) && ts.isIdentifier(n.expression) && n.expression.text === name) {
        found = true;
      }
      ts.forEachChild(n, walk);
    };
    walk(cond);
    return found;
  };
  const visit = (n: ts.Node): void => {
    if (ts.isCallExpression(n) && ts.isIdentifier(n.expression) && n.expression.text === name) {
      let p: ts.Node | undefined = n.parent;
      let guarded = false;
      while (p) {
        if (ts.isIfStatement(p) && guardsName(p.expression)) {
          guarded = true;
          break;
        }
        if (ts.isConditionalExpression(p) && guardsName(p.condition)) {
          guarded = true;
          break;
        }
        p = p.parent;
      }
      if (!guarded) out.push(at(n));
    }
    ts.forEachChild(n, visit);
  };
  ts.forEachChild(script.ast, visit);
  return out;
}

/** Does this script contain a real CALL to `name`? A comment mentioning it does not count. */
export function callsByName(script: DashboardScript, name: string): boolean {
  let found = false;
  const visit = (n: ts.Node): void => {
    if (found) return;
    if (ts.isCallExpression(n) && ts.isIdentifier(n.expression) && n.expression.text === name) {
      found = true;
      return;
    }
    ts.forEachChild(n, visit);
  };
  ts.forEachChild(script.ast, visit);
  return found;
}

/**
 * Every DOM access that runs at module scope rather than inside a function.
 *
 * These files are <head> scripts, so anything here executes before the body is parsed: a capture is
 * null, a listener attaches to nothing, and the feature is silently absent. The indentation-based
 * check this replaced missed `window.document?.getElementById(...)`, which is the same access by a
 * spelling a pattern does not recognise — so the question is asked structurally: is this a member
 * access rooted at `document`, and is it outside every function?
 */
export function domAccessOutsideFunctions(script: DashboardScript): string[] {
  const out: string[] = [];
  const rootsAtDocument = (n: ts.Node): boolean => {
    let cur: ts.Node = n;
    for (;;) {
      if (ts.isIdentifier(cur)) return cur.text === "document";
      // `window.document?.getElementById(...)` roots at `window`, not `document` — the spelling
      // review used to slip past this. A global root followed by `.document` IS the document.
      if (
        ts.isPropertyAccessExpression(cur) &&
        cur.name.text === "document" &&
        ts.isIdentifier(cur.expression) &&
        GLOBAL_ROOTS.has(cur.expression.text)
      ) {
        return true;
      }
      if (ts.isPropertyAccessExpression(cur) || ts.isElementAccessExpression(cur)) cur = cur.expression;
      else if (ts.isNonNullExpression(cur) || ts.isParenthesizedExpression(cur)) cur = cur.expression;
      else return false;
    }
  };
  const at = (n: ts.Node): number =>
    script.ast.getLineAndCharacterOfPosition(n.getStart(script.ast)).line + 1;
  // AN IIFE WRAPPER IS STILL MODULE SCOPE. Every one of these modules is `(function () { … })()`,
  // so treating any enclosing function as "inside a function" made this check vacuous — it could
  // never fire, on any module. The wrapper runs at load exactly as bare top-level code would.
  /** The function an IIFE invokes, unwrapping the parentheses, or null if this is not one. */
  const iifeBody = (n: ts.Node): ts.Node | null => {
    if (!ts.isCallExpression(n)) return null;
    let callee: ts.Node = n.expression;
    while (ts.isParenthesizedExpression(callee)) callee = callee.expression;
    return ts.isFunctionExpression(callee) || ts.isArrowFunction(callee) ? callee.body : null;
  };

  const visit = (n: ts.Node, inFunction: boolean): void => {
    // Descend into the wrapper's BODY at the CURRENT scope. Walking its children generically hits
    // the FunctionExpression itself, which then sets inFunction — which is why the first attempt at
    // this still reported nothing for a DOM read sitting directly inside the wrapper.
    const body = iifeBody(n);
    if (body) {
      ts.forEachChild(body, (c) => visit(c, inFunction));
      return;
    }
    if (isFunctionLike(n)) {
      ts.forEachChild(n, (c) => visit(c, true));
      return;
    }
    if (!inFunction && (ts.isPropertyAccessExpression(n) || ts.isElementAccessExpression(n))) {
      if (rootsAtDocument(n)) out.push(`${script.name}:${at(n)} ${n.getText(script.ast).slice(0, 70)}`);
    }
    ts.forEachChild(n, (c) => visit(c, inFunction));
  };
  ts.forEachChild(script.ast, (c) => visit(c, false));
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
