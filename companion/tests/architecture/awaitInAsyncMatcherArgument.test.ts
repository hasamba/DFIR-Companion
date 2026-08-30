// A test must not `await` inside the argument list of a `.rejects` / `.resolves` matcher.
//
// This guards a defect whose symptom names no cause. `tests/analysis/taggerStore.test.ts` asserted
// a conflict error like this:
//
//   await expect(store.save(rule, opened)).rejects.toMatchObject({
//     currentRevision: (await store.readActive()).revision,
//   });
//
// Every test in the file passed, and the file still failed about once in eight runs with
// "Vitest caught 1 unhandled error during the test run". It reddened master's Linux job on an
// unrelated PR, which is the cost: a failure that moves with machine load, reproduces on any
// branch, and blames a file whose assertions are all green.
//
// The cause is evaluation order. Arguments are evaluated BEFORE the call they belong to, so
// `store.save(...)` has already been issued and `.rejects` has attached nothing to it while
// `await store.readActive()` runs. Both sides do file I/O, so which finishes first is a coin toss;
// when the save rejects first, its rejection is momentarily unhandled and Node reports it. Node
// names the pathology itself if you listen for it — "PromiseRejectionHandledWarning: Promise
// rejection was handled asynchronously".
//
// The fix is always the same and costs one line: hoist the awaited value above the assertion, so
// nothing suspends between the promise and its handler.
//
//   const currentRevision = (await store.readActive()).revision;
//   await expect(store.save(rule, opened)).rejects.toMatchObject({ currentRevision });
//
// An await inside a nested function in the argument is NOT this bug — a callback body does not run
// during argument evaluation — so the scan below does not descend into one. It does still read a
// computed member name, which IS evaluated while the argument is built. And it matches through
// modifiers: `.rejects.not.toEqual(await x())` is the same hazard as `.rejects.toEqual(await x())`.
import { readdir, readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import ts from "typescript";
import { describe, expect, it } from "vitest";

const TESTS_DIR = fileURLToPath(new URL("../", import.meta.url));

/** Every *.test.ts under tests/, as repo-relative paths. */
async function testFiles(dir = TESTS_DIR, prefix = ""): Promise<string[]> {
  const found: string[] = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.isDirectory()) found.push(...(await testFiles(join(dir, entry.name), rel)));
    else if (entry.name.endsWith(".test.ts")) found.push(rel);
  }
  return found;
}

/**
 * Line numbers of every `.rejects.x(…)` / `.resolves.x(…)` call whose ARGUMENTS contain a
 * top-level `await`.
 *
 * The AST rather than a regex, because the hazard is a nesting property, not a text one: the await
 * can sit any number of braces deep inside an object literal, on its own line, or inside a template
 * literal, and it is harmless the moment it moves inside a callback. A regex cannot tell those
 * apart, and a gate with a hole is worse than no gate because it certifies the property it is not
 * checking.
 */
export function awaitingMatcherArgumentLines(source: string): number[] {
  const sourceFile = ts.createSourceFile("t.ts", source, ts.ScriptTarget.ES2022, true);
  const lines: number[] = [];

  /**
   * True when `node` contains an await that runs during argument evaluation.
   *
   * Two boundaries here, and the contract tests below exist because successive drafts got one each.
   * The walk must start ON the argument, not one level down, or an argument that IS a callback gets
   * flagged. And a function-like node is not wholly skippable: its BODY runs when the matcher
   * chooses to run it, but a COMPUTED MEMBER NAME is evaluated while the surrounding object literal
   * is being built — which is argument-evaluation time, the very window this gate guards.
   */
  const awaitsBeforeTheCall = (node: ts.Node): boolean => {
    let found = false;
    const walk = (n: ts.Node): void => {
      if (found) return;
      if (ts.isAwaitExpression(n)) {
        found = true;
        return;
      }
      if (ts.isFunctionLike(n)) {
        const { name } = n as ts.NamedDeclaration;
        if (name && ts.isComputedPropertyName(name)) walk(name);
        return;
      }
      ts.forEachChild(n, walk);
    };
    walk(node);
    return found;
  };

  /**
   * True when a matcher call hangs off a `.rejects` / `.resolves` chain.
   *
   * The whole chain, not only the link next to the matcher, because modifiers sit in that position:
   * `expect(p()).rejects.not.toEqual(…)` is exactly as unguarded as the plain form. The walk follows
   * property accesses only, so it stops at `expect(…)` rather than wandering into an unrelated
   * expression.
   */
  const isAsyncMatcherChain = (expr: ts.Expression): boolean => {
    let link: ts.Expression = expr;
    while (ts.isPropertyAccessExpression(link)) {
      if (link.name.text === "rejects" || link.name.text === "resolves") return true;
      link = link.expression;
    }
    return false;
  };

  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
      if (isAsyncMatcherChain(node.expression.expression) && node.arguments.some(awaitsBeforeTheCall)) {
        lines.push(sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile)).line + 1);
      }
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(sourceFile, visit);
  return lines;
}

/** Matches the sibling gate: bounded so a full sweep cannot hit macOS's 256-descriptor limit. */
const READ_CONCURRENCY = 32;

describe("a rejection handler is attached before anything else is awaited", () => {
  it("no test file awaits inside a .rejects/.resolves matcher argument", async () => {
    const files = await testFiles();
    const offenders: string[] = [];
    for (let i = 0; i < files.length; i += READ_CONCURRENCY) {
      const batch = await Promise.all(
        files.slice(i, i + READ_CONCURRENCY).map(async (rel) => {
          const source = await readFile(join(TESTS_DIR, rel), "utf8");
          // Parse only the files that could possibly match. The filter opens no hole: a call this
          // reports must contain one of these two property names verbatim.
          if (!source.includes("rejects") && !source.includes("resolves")) return [];
          return awaitingMatcherArgumentLines(source).map((line) => `tests/${rel}:${line}`);
        }),
      );
      offenders.push(...batch.flat());
    }

    expect(
      offenders,
      "Hoist the awaited value into a const above the assertion. Arguments are evaluated before " +
        "the matcher is called, so an await here runs while the promise has no handler — and the " +
        "file then fails intermittently with an unhandled rejection while every test in it passes.",
    ).toEqual([]);
  });

  // The gate is only worth its line count if it fails on the thing it claims to catch. These pin
  // the two axes a hand-written scanner gets wrong: the forms it must catch, and the ones it must
  // leave alone.
  it("catches the nested forms a regex would miss", () => {
    expect(
      awaitingMatcherArgumentLines("await expect(p()).rejects.toMatchObject({ r: await read() });"),
    ).toEqual([1]);
    expect(
      awaitingMatcherArgumentLines(
        "await expect(p()).rejects.toMatchObject({\n  a: { b: [await read()] },\n});",
      ),
    ).toEqual([1]);
    expect(awaitingMatcherArgumentLines("await expect(p()).resolves.toEqual(await read());")).toEqual([1]);
    expect(awaitingMatcherArgumentLines("await expect(p()).rejects.toThrow(`${await msg()}`);")).toEqual([1]);
    // Modifiers sit between the accessor and the matcher and change nothing about the hazard.
    expect(awaitingMatcherArgumentLines("await expect(p()).rejects.not.toEqual(await read());")).toEqual([1]);
    expect(awaitingMatcherArgumentLines("await expect(p()).resolves.not.toBe(await read());")).toEqual([1]);
    // A computed member name is evaluated while the object literal is built, so it runs here even
    // though the method body does not.
    expect(
      awaitingMatcherArgumentLines("await expect(p()).rejects.toMatchObject({ [await key()]() {} });"),
    ).toEqual([1]);
  });

  it("leaves the safe forms alone", () => {
    expect(awaitingMatcherArgumentLines("await expect(p()).rejects.toThrow(/nope/);")).toEqual([]);
    expect(awaitingMatcherArgumentLines("await expect(p()).rejects.toMatchObject({ r: known });")).toEqual(
      [],
    );
    // Awaited first, then asserted — the shape this gate is asking for.
    expect(
      awaitingMatcherArgumentLines(
        "const r = await read();\nawait expect(p()).rejects.toMatchObject({ r });",
      ),
    ).toEqual([]);
    // A callback body does not run during argument evaluation.
    expect(
      awaitingMatcherArgumentLines("await expect(p()).rejects.toSatisfy(async (e) => { await log(e); });"),
    ).toEqual([]);
    // Not an async matcher, despite the await and the modifier — a sync matcher has no promise
    // sitting there without a handler, so the await costs nothing.
    expect(awaitingMatcherArgumentLines("expect(x).toEqual(await read());")).toEqual([]);
    expect(awaitingMatcherArgumentLines("expect(x).not.toEqual(await read());")).toEqual([]);
  });
});
