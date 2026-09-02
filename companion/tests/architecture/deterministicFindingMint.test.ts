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

describe("the behaviour table covers every backfill that exists", () => {
  // The literal scan above proves an id is registered. It cannot prove the pass LINKS its finding
  // to an event, and an unlinked finding is not carried either — `supportingEventIds` drops it
  // before the window test. That check lives in the behaviour table, which can only check a pass
  // it has been given, so the table's completeness is what makes the pair airtight.
  //
  // `export function backfill*` is the naming every one of the three passes already uses, and it
  // is what a fourth will be called by anyone matching the surrounding code. A pass deliberately
  // named otherwise is not caught here — but it is not caught by a comment either, and this at
  // least fails for the ordinary case instead of trusting it.
  it("lists every `export function backfill*` in src/analysis", async () => {
    const dir = new URL("../../src/analysis/", import.meta.url);
    const exported: string[] = [];
    for (const entry of await readdir(dir, { withFileTypes: true })) {
      if (!entry.isFile() || !entry.name.endsWith(".ts")) continue;
      const source = await readFile(new URL(entry.name, dir), "utf8");
      const sf = ts.createSourceFile(entry.name, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
      for (const node of sf.statements) {
        if (
          ts.isFunctionDeclaration(node) &&
          node.name?.text.startsWith("backfill") &&
          node.modifiers?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword)
        ) {
          exported.push(node.name.text);
        }
      }
    }

    expect(
      exported.length,
      "found no backfill passes — the walk is looking in the wrong place",
    ).toBeGreaterThan(0);
    expect(
      exported.sort(),
      "a deterministic backfill pass that the behaviour table in " +
        "tests/analysis/deterministicFindingIds.test.ts does not run. Add it to BACKFILLS there: " +
        "registering its id prefix is only half of what it needs, and the other half — that it " +
        "back-links its finding to an event, without which the finding is not carried across a " +
        "narrowed window either — can only be checked by running the pass (#751/#758)",
    ).toEqual(BACKFILLS.map((b) => b.name).sort());
  });
});
