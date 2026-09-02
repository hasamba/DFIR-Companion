// A finding id that claims deterministic provenance must be REGISTERED (#758).
//
// `responseSchema.ts` holds the register — `AUTO_FINDING_ID_PREFIX`, `GAP_FINDING_ID_PREFIX`,
// `WAVES_FINDING_ID` — and `isDeterministicFindingId` is the reader that decides a case's fate:
// `carryOutOfWindowFindings` re-attaches a prior finding across a narrowed window ONLY when that
// predicate accepts its id. An id the register does not know is not carried, so the first time an
// analyst narrows the scope, that pass's findings are overwritten in SQLite and widening the window
// again does not bring them back. That is #751, and the whole suite stays green while it happens.
//
// #787 gave the three existing mint sites one shared list, which removed the drift BETWEEN them.
// What it could not do is speak for a pass nobody has written yet. A fourth backfill minting
// `f-newthing-${id}` inline compiles, ships, and loses findings in silence.
//
// tests/analysis/deterministicFindingIds.test.ts covers that from the behaviour side: it RUNS each
// backfill and puts the id it really mints through the predicate and the carry. This file is the
// half that needs no remembering, and it has two jobs, because registration is not the only way a
// pass loses its findings:
//
//   1. Every finding-id literal in the source is found and checked, wherever it is written and
//      whether or not its author knew this rule existed.
//   2. Every `export function backfill*` in src/analysis appears in that behaviour table.
//
// The second exists because the first cannot see LINKAGE. A pass that registers its prefix
// correctly but never back-links its finding to an event is dropped by `supportingEventIds` as
// "nothing proves it is outside the window" — not carried, same lost findings, and a literal scan
// reads its id as perfectly well-formed. Only running the pass through the carry catches that, and
// running it requires the pass to be in the table. So the table's completeness is itself pinned
// here rather than left to a comment saying "add a new backfill here".
//
// PARSED, NOT SCANNED, for the reason childStderr.test.ts gives at length: the register's own
// docblock names `f-auto-` and `f-gap-` in prose, dashboard-filters.js explains both prefixes over
// twenty lines of comment, and a text scan reports all of it. The parser sees string literals.
import { readFile, readdir } from "node:fs/promises";
import ts from "typescript";
import { describe, expect, it } from "vitest";
import {
  AUTO_FINDING_ID_PREFIX,
  GAP_FINDING_ID_PREFIX,
  MODEL_FINDING_ID_PREFIX,
  isDeterministicFindingId,
} from "../../src/analysis/responseSchema.js";
import { BACKFILLS } from "../helpers/deterministicBackfills.js";

const SRC = new URL("../../src/", import.meta.url);
const DASHBOARD_FILTERS = new URL("../../../public/js/dashboard-filters.js", import.meta.url);

// The finding-id namespace. Every id the product mints for a finding starts `f-`, which is what
// makes a literal recognisable as a provenance claim rather than an ordinary string.
const FINDING_ID_SHAPE = /^f-[a-z0-9]/i;

/**
 * Lines in `source` carrying a finding-id literal the register does not know.
 *
 * A template head counts: `` `f-newthing-${id}` `` has the head text "f-newthing-", which is
 * exactly how the three registered sites were written before #787 gave them constants. A literal
 * built from a constant has an EMPTY head (`${GAP_FINDING_ID_PREFIX}${a}-${b}`) and so is invisible
 * here — correct, because a constant is by definition already in the register.
 *
 * `f-model-` is the one finding-id namespace that is deliberately NOT deterministic: it is what a
 * model's invented claim is renamed to, so a literal in it asserts the opposite of the claim this
 * guard polices. The whole namespace is exempt, named by the register's own constant rather than
 * spelled out here, so nothing else can slip through by resembling it.
 */
export function unregisteredFindingIdLiterals(source: string): number[] {
  const sf = ts.createSourceFile("scan.ts", source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  const found: number[] = [];
  const visit = (node: ts.Node): void => {
    const text =
      ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)
        ? node.text
        : node.kind === ts.SyntaxKind.TemplateHead
          ? (node as ts.TemplateHead).text
          : null;
    if (
      text !== null &&
      FINDING_ID_SHAPE.test(text) &&
      !text.startsWith(MODEL_FINDING_ID_PREFIX) &&
      !isDeterministicFindingId(text)
    ) {
      found.push(sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1);
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return found.sort((a, b) => a - b);
}

/** Every .ts file under src/, as a path relative to src/. */
async function sources(dir: URL, prefix = ""): Promise<string[]> {
  const out: string[] = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      out.push(...(await sources(new URL(`${entry.name}/`, dir), `${prefix}${entry.name}/`)));
    } else if (entry.name.endsWith(".ts")) {
      out.push(`${prefix}${entry.name}`);
    }
  }
  return out;
}

describe("every finding-id literal in the source is registered", () => {
  // 30s rather than the suite's 15s default, matching childStderr.test.ts: this parses all ~657
  // source files with the TypeScript compiler, so it is genuinely heavy rather than accidentally
  // slow, and a tight budget would make it the first thing to fail under contention.
  it("finds no finding-id prefix the register does not know", { timeout: 30_000 }, async () => {
    const files = await sources(SRC);
    expect(files.length, "found no sources — the walk is looking in the wrong place").toBeGreaterThan(10);

    const offenders: string[] = [];
    for (const file of files) {
      const source = await readFile(new URL(file, SRC), "utf8");
      offenders.push(...unregisteredFindingIdLiterals(source).map((line) => `${file}:${line}`));
    }

    expect(
      offenders,
      "a finding id in the `f-` namespace that isDeterministicFindingId does not accept. If a " +
        "backfill pass mints it, register its prefix in responseSchema.ts beside " +
        "AUTO_FINDING_ID_PREFIX and add the pass to the table in " +
        "tests/analysis/deterministicFindingIds.test.ts — an unregistered id is not carried across " +
        "a narrowed window, so the pass loses its findings the first time an analyst narrows the " +
        "scope (#751/#758)",
    ).toEqual([]);
  });

  it("flags an unregistered literal, and leaves every registered one alone", () => {
    // The detector watched working. A file walk that reports "[]" looks identical whether every
    // literal is registered or the scan has quietly stopped recognising literals at all.
    const source = [
      'const a = "f-auto-e5";', // registered
      "const b = `f-gap-${before}-${after}`;", // 2: registered, read from the template HEAD
      'const c = "f-waves";', // registered — an exact id, not a prefix
      'const d = "f-model-x";', // in the declared non-deterministic namespace: the opposite claim
      "const e = `f-newthing-${id}`;", // 5: the case this guard exists for
      'const f = "f-hunch-";', // 6: and the same as a plain string
      "const g = `${GAP_FINDING_ID_PREFIX}${a}-${b}`;", // built from the register: head is empty
      'const h = "finding-1";', // not the `f-` namespace at all
      'const i = "f1";', // an ordinary model id, no hyphen
      "// f-newthing- in prose is not a literal", // 10: must NOT be flagged
      'const j = describe("f-newthing-x", () => {});', // 11: a name quoted as data IS a literal
    ].join("\n");

    expect(unregisteredFindingIdLiterals(source)).toEqual([5, 6, 11]);
  });
});

describe("the dashboard's copy of the prefixes matches the register", () => {
  // public/js/dashboard-filters.js classifies a finding's ORIGIN for the two panel lenses ("Hide
  // auto-flagged" / "Hide coverage-gap"), and it does it by prefix — a fourth copy of the register,
  // in a browser module that cannot import a TypeScript constant. Nothing kept the two in step, so
  // renaming a prefix server-side would leave the lens matching an id the product no longer mints:
  // the checkbox stops hiding anything, in silence, with every server-side test green.
  //
  // Only the two prefixes the lenses actually use are pinned. `f-waves` has no lens of its own —
  // it is a single finding about the intrusion's cadence, not a class of rows worth hiding — so
  // requiring it here would demand a control the panel deliberately does not have.
  it("uses exactly the prefixes responseSchema.ts exports", async () => {
    const source = await readFile(DASHBOARD_FILTERS, "utf8");
    const sf = ts.createSourceFile("f.js", source, ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);

    // The argument of every `.startsWith(...)` in the file, which is how both classifiers test an
    // id. Read from the call rather than from the file's text so the twenty lines of comment above
    // them — which name both prefixes in prose — cannot be mistaken for the code.
    const prefixes: string[] = [];
    const visit = (node: ts.Node): void => {
      if (
        ts.isCallExpression(node) &&
        ts.isPropertyAccessExpression(node.expression) &&
        node.expression.name.text === "startsWith"
      ) {
        const arg = node.arguments[0];
        if (arg && (ts.isStringLiteral(arg) || ts.isNoSubstitutionTemplateLiteral(arg))) {
          if (FINDING_ID_SHAPE.test(arg.text)) prefixes.push(arg.text);
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(sf);

    expect(
      prefixes.sort(),
      "the finding-origin lenses in public/js/dashboard-filters.js no longer match the prefixes " +
        "responseSchema.ts mints. A lens matching an id the product does not mint hides nothing, " +
        "and says so nowhere",
    ).toEqual([AUTO_FINDING_ID_PREFIX, GAP_FINDING_ID_PREFIX].sort());
  });
});

/**
 * Every exported name in `source` that starts with "backfill", however it is written.
 *
 * Every form counts, because TypeScript has several ordinary ways to export a function and a guard
 * that knows only the shape already in the tree waves through the first person to write another.
 * Each line below was missed by some earlier version of this scanner:
 *
 *   export function backfill…() {}          the form all three passes use today
 *   export const backfill… = …              a binding rather than a declaration
 *   export { backfill… }                    declared plainly, exported in a list at the end
 *   export { x as backfill… }               exported under a different name
 *   export default function backfill…() {}  a named default
 *   export default backfill…                an assignment, not a declaration or a list
 *   export = backfill…                      the same, in TypeScript's own spelling
 *   export { backfill… as default }         the name is in the specifier's LEFT half
 *
 * The pattern in the misses: a scanner that looks for the `export` keyword ON a declaration sees
 * only the first two. The rest put the export in a statement of its own, and two of them put the
 * pass's name somewhere other than where the previous version looked for it.
 *
 * The reported name is always the one the rest of the tree can CALL the pass by — the alias for
 * `x as backfill…`, and the local name for `backfill… as default`, whose exported name is the
 * useless string "default". The converse follows and is deliberate: `export { backfill… as helper
 * }` is NOT reported, because `helper` is what the tree sees. A pass exported under a name outside
 * the convention is outside this gate, the same as one named `applyGapFindings`, and saying so is
 * honest where reporting it under a name nothing can call would not be.
 *
 * Type-only exports are skipped: a type is not a pass. `export * from` needs nothing — whatever it
 * re-exports is declared in a file this walk already reads. An ANONYMOUS default
 * (`export default function () {}`) has no name to match and is not reachable by one either.
 */
export function exportedBackfillNames(source: string): string[] {
  const sf = ts.createSourceFile("scan.ts", source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  const exported = (node: ts.Node): boolean =>
    ts.canHaveModifiers(node) &&
    (ts.getModifiers(node) ?? []).some((m) => m.kind === ts.SyntaxKind.ExportKeyword);
  const names = new Set<string>();
  for (const node of sf.statements) {
    // `export { … }` carries no export MODIFIER — the statement is the export — so it has to be
    // read before the modifier check below, not through it.
    if (ts.isExportDeclaration(node)) {
      if (node.isTypeOnly || !node.exportClause || !ts.isNamedExports(node.exportClause)) continue;
      for (const spec of node.exportClause.elements) {
        if (spec.isTypeOnly) continue;
        // The EXPORTED name, which is what the rest of the tree can call it by. `as default` is
        // the one exception: "default" names nothing usable, so the local name stands in.
        //
        // Deliberately not "either half starts with backfill". That reading reported `export {
        // backfillX as helper }` as a pass called `backfillX`, which nothing can call it — the
        // tree sees `helper`. A pass exported under a non-backfill name has left the convention
        // this gate reads, exactly as one named `applyGapFindings` would have, and the docblock
        // above says so rather than half-catching it under a name that does not exist.
        const called = spec.name.text === "default" ? spec.propertyName?.text : spec.name.text;
        if (called?.startsWith("backfill")) names.add(called);
      }
      continue;
    }
    // `export default backfill…` and `export = backfill…`: an assignment, so neither a modified
    // declaration nor a named-export list. The identifier is the only name it has.
    if (ts.isExportAssignment(node)) {
      if (ts.isIdentifier(node.expression) && node.expression.text.startsWith("backfill")) {
        names.add(node.expression.text);
      }
      continue;
    }
    if (!exported(node)) continue;
    if (ts.isFunctionDeclaration(node) && node.name?.text.startsWith("backfill")) {
      names.add(node.name.text);
    } else if (ts.isVariableStatement(node)) {
      for (const d of node.declarationList.declarations) {
        if (ts.isIdentifier(d.name) && d.name.text.startsWith("backfill")) names.add(d.name.text);
      }
    }
  }
  return [...names];
}

describe("the behaviour table covers every backfill that exists", () => {
  // The literal scan above proves an id is registered. It cannot prove the pass LINKS its finding
  // to an event, and an unlinked finding is not carried either — `supportingEventIds` drops it
  // before the window test. That check lives in the behaviour table, which can only check a pass
  // it has been given, so the table's completeness is what makes the pair airtight.
  //
  // Every source file, not just src/analysis's top level. The first version of this gate read one
  // directory without recursing, while the literal scan beside it walked the whole tree — so a pass
  // added in src/analysis/ai/ (36 .ts files live below that top level, and synthesisMerge.ts is
  // already there) would have been invisible to the very check meant to find it.
  //
  // A pass named something other than `backfill*` is still not caught. That is the convention all
  // three use and the one a fourth gets by matching the surrounding code; the alternative to
  // trusting it is trusting a comment, which is what this replaced.
  it("lists every exported backfill in src/", { timeout: 30_000 }, async () => {
    const files = await sources(SRC);
    const exported: string[] = [];
    for (const file of files) {
      exported.push(...exportedBackfillNames(await readFile(new URL(file, SRC), "utf8")));
    }

    expect(
      exported.length,
      "found no backfill passes — the walk is looking in the wrong place",
    ).toBeGreaterThan(0);
    expect(
      exported.sort(),
      "a deterministic backfill pass that the behaviour table in " +
        "tests/helpers/deterministicBackfills.ts does not run. Add it to BACKFILLS there: " +
        "registering its id prefix is only half of what it needs, and the other half — that it " +
        "back-links its finding to an event, without which the finding is not carried across a " +
        "narrowed window either — can only be checked by running the pass (#751/#758)",
    ).toEqual(BACKFILLS.map((b) => b.name).sort());
  });

  it("reads every export form, and only exported backfills", () => {
    // The detector watched working, for the same reason the literal scan has a fixture: a walk that
    // reports the three real passes looks identical whether it is right or has stopped seeing.
    // Every line here was missed by some earlier version of this scanner.
    const source = [
      "export function backfillOne(state) { return state; }",
      "export const backfillTwo = (state) => state;", // missed while it read declarations only
      "export const backfillFour = function (state) { return state; };",
      "function backfillFive(state) { return state; }", // no modifier here…
      "export { backfillFive };", // …the export is its own statement, and carries no modifier
      "export { helper as backfillSix };", // exported AS a backfill: that is the callable name
      "export default function backfillSeven(state) { return state; }", // a named default
      "function backfillEight(state) { return state; }",
      "export default backfillEight;", // an assignment: neither a declaration nor a list
      "function backfillNine(state) { return state; }",
      "export { backfillNine as default };", // the name is in the specifier's LEFT half
      "function backfillTen(state) { return state; }",
      "export { backfillTen as helper };", // exported OUT of the convention: the tree sees `helper`
      "export default function (state) { return state; }", // anonymous: no name to match
      "function backfillThree(state) { return state; }", // never exported: nothing can call it
      "export function detectSomething() {}", // exported, not a backfill
      "export type { backfillType };", // a type is not a pass
      "export { type backfillInline };", // nor is an inline type-only specifier
      "// export function backfillInProse() {} — a comment is not a declaration",
      'export const note = "export function backfillQuoted() {}";', // a string is not one either
    ].join("\n");

    expect(exportedBackfillNames(source).sort()).toEqual([
      "backfillEight",
      "backfillFive",
      "backfillFour",
      "backfillNine",
      "backfillOne",
      "backfillSeven",
      "backfillSix",
      "backfillTwo",
    ]);
  });
});
