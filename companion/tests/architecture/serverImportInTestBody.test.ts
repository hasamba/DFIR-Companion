// A test must not load the server module graph from inside a test body.
//
// This guards a defect that read as flake for months. Two files — custodyIntegrity.test.ts and
// custodyIntegrityScope.test.ts — reached the app with `await import("../../src/server.js")` inside
// an `it()`, rather than with the top-level `import { createApp }` that the other ~141 server tests
// use. Both forms cost the same: Vite transforms the whole server graph once per test file. The
// difference is WHERE the cost lands.
//
// A top-level import is transformed during COLLECTION, which has no per-test budget. A dynamic
// import inside an `it()` is transformed inside that test's `testTimeout`. Measured on a loaded
// 8-core Linux box, the transform took 25-45s against a 15s budget, so the test failed with
// "Test timed out in 15000ms" — and so did every later test in the same file, because each one
// awaited the same still-in-flight module promise and spent its own 15s waiting on it.
//
// The symptom names no cause: it is a timeout, not an assertion, it moves with machine load, and it
// reproduces on any branch. That is the shape of a failure people learn to re-run instead of read,
// which is what makes it worth a gate rather than a comment.
//
// Hoisting the import moved the same ~45s out of `tests` and into `collect`, and the files went
// from 4 failures to 32 passes with no change to the timeout. The rule is therefore about
// placement, not about duration: import the server at module scope.
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
 * Line numbers of every `import("…/server.js")` expression in `source`.
 *
 * The AST rather than a regex, because the call is trivially wrapped past any pattern a regex can
 * hold: a newline before the argument, a `void`/`.then()` form instead of `await`, or a
 * `Promise.all([import(a), import(b)])`. ts.forEachChild visits all of them; a regex tuned to
 * `await import("…")` sees none of them, and a gate with a hole is worse than no gate because it
 * certifies the property it is not checking.
 *
 * Only string-literal specifiers are reported. A computed specifier cannot be resolved statically,
 * and nothing in the suite uses one — if that changes, this reports nothing rather than guessing.
 */
export function serverImportLines(source: string): number[] {
  const sourceFile = ts.createSourceFile("t.ts", source, ts.ScriptTarget.ES2022, true);
  const lines: number[] = [];
  const visit = (node: ts.Node): void => {
    if (
      ts.isCallExpression(node) &&
      node.expression.kind === ts.SyntaxKind.ImportKeyword &&
      node.arguments.length > 0
    ) {
      const [specifier] = node.arguments;
      if (ts.isStringLiteralLike(specifier) && /(^|\/)server\.js$/.test(specifier.text)) {
        lines.push(sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile)).line + 1);
      }
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(sourceFile, visit);
  return lines;
}

/**
 * How many test files to read at once.
 *
 * Not unbounded. `Promise.all` over every file opens 672 descriptors at once, which is fine on
 * Linux (soft limit 1024 and up) and fails with EMFILE on macOS, whose default soft limit is 256 —
 * measured here: 256 and 512 both threw, 1024 and 4096 passed. A gate that fails on one platform
 * for a reason that has nothing to do with the rule it enforces is worse than no gate.
 *
 * Not one at a time either: the first draft awaited each file in turn and took the whole 15s budget
 * on a loaded machine, which is the failure this gate exists to prevent.
 *
 * 32 keeps the wall time flat (I/O-bound, and the parse is skipped for almost every file) while
 * leaving the rest of a 256-descriptor budget to Vitest's own open handles.
 */
const READ_CONCURRENCY = 32;

describe("the server module graph is imported at module scope", () => {
  it("no test file loads src/server.js with a dynamic import()", async () => {
    const files = await testFiles();
    const offenders: string[] = [];
    for (let i = 0; i < files.length; i += READ_CONCURRENCY) {
      const batch = await Promise.all(
        files.slice(i, i + READ_CONCURRENCY).map(async (rel) => {
          const source = await readFile(join(TESTS_DIR, rel), "utf8");
          // Parse only the files that could possibly match. Parsing all 672 took 11s of the 15s
          // budget on a loaded machine, which would have made this gate the next thing people
          // re-run instead of read. The filter opens no hole: serverImportLines only reports
          // string-literal specifiers, so a file it would flag must contain that literal text.
          if (!source.includes("server.js")) return [];
          return serverImportLines(source).map((line) => `tests/${rel}:${line}`);
        }),
      );
      offenders.push(...batch.flat());
    }

    expect(
      offenders,
      'Use a top-level `import { createApp } from "…/src/server.js"`. A dynamic import() pays the ' +
        "server graph's 25-45s transform inside the test's timeout budget, so the test fails with " +
        '"Test timed out" on a loaded machine. A top-level import pays it during collection, which ' +
        "is not timed.",
    ).toEqual([]);
  });

  // The gate is only worth its line count if it fails on the thing it claims to catch. These pin
  // the two axes that a hand-written scanner gets wrong: the forms it must catch, and the ones it
  // must leave alone.
  it("catches the wrapped forms a regex would miss", () => {
    expect(serverImportLines('const { createApp } = await import("../../src/server.js");')).toEqual([1]);
    expect(serverImportLines('const m = await import(\n  "../../src/server.js",\n);')).toEqual([1]);
    expect(serverImportLines('void import("../src/server.js").then((m) => m.createApp);')).toEqual([1]);
    expect(serverImportLines('await Promise.all([import("x"), import("../../src/server.js")]);')).toEqual([
      1,
    ]);
  });

  it("leaves the static import and unrelated dynamic imports alone", () => {
    expect(serverImportLines('import { createApp } from "../../src/server.js";')).toEqual([]);
    expect(serverImportLines('await import("../../src/analysis/stateTypes.js");')).toEqual([]);
    expect(serverImportLines('await import("node:fs/promises");')).toEqual([]);
    // Not the server entry, despite the substring.
    expect(serverImportLines('await import("../../src/http/originServer.js");')).toEqual([]);
  });
});
