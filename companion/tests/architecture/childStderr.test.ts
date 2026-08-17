// A test that provokes a script into refusing must not print that refusal onto the run's stderr.
//
// This is the guard for a defect that survived months of green runs. execFileSync's default `stdio`
// echoes the child's stderr to the parent as well as capturing it, so four negative tests — each
// asserting that a script correctly REFUSES a deliberately broken fixture — printed their refusals
// into every test run:
//
//   [inventory] FAIL: sections cover 2 lines but the inline script is 4. …
//   [split] REFUSING: … (×3)
//
// The inventory line was read, reasonably, as the real dashboard failing its coverage check. It was
// not: it describes a four-line fixture built inside the test, and the check passes against
// public/dashboard.html (1,774 lines, all covered). Nothing was broken except the output — which is
// its own defect, because a run that prints FAIL while everything passes teaches people to read
// past the word, and the guards exist precisely for the day it is real.
//
// Nothing guarded the property, so nothing noticed when four call sites acquired it. This does.
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { readFile, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import ts from "typescript";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { runScriptExpectingFailure } from "../helpers/runScript.js";

const TESTS = new URL("../", import.meta.url);

/**
 * Which stdio slot a spawn gives its child's STDERR, or null when that cannot be determined.
 *
 * Verified against Node rather than assumed, because half of these are not obvious:
 *
 *   stdio: "pipe"                          captured   (no stdio option)                    LEAKS
 *   stdio: ["ignore", "pipe", "pipe"]      captured   stdio: "inherit"                     LEAKS
 *   stdio: ["ignore", "pipe", "ignore"]    captured   stdio: ["ignore", "pipe", "inherit"] LEAKS
 *   stdio: ["ignore", "pipe"]              captured   stdio: ["ignore", "pipe", 2]         LEAKS
 *
 * The raw descriptor is why a keyword search cannot do this job: `2` IS the parent's stderr and
 * says nothing about itself. The short array is why counting elements cannot either — Node fills
 * the missing slots with "pipe".
 *
 * Anything that hides the answer — a spread in the options or in the array, a value that is not a
 * literal — returns null and is reported. Over-reporting costs someone one explicit stdio;
 * under-reporting cost this repo months of FAIL scrolling past on green runs.
 */
function stderrSlot(call: ts.CallExpression): string | null {
  const last = call.arguments.at(-1);
  if (!last || !ts.isObjectLiteralExpression(last)) return null; // no options object: the default
  let value: ts.Expression | undefined;
  for (const p of last.properties) {
    if (ts.isSpreadAssignment(p)) return null; // {...base} may carry an stdio we cannot see
    if (ts.isShorthandPropertyAssignment(p) && p.name.text === "stdio") return null;
    if (ts.isPropertyAssignment(p) && p.name.getText() === "stdio") value = p.initializer;
  }
  if (!value) return null;
  const literal = (n: ts.Node): string | null =>
    ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n) ? n.text : null;
  const whole = literal(value);
  if (whole) return whole; // a bare string applies to all three streams
  if (!ts.isArrayLiteralExpression(value)) return null;
  const slots = value.elements;
  if (slots.some((e) => ts.isSpreadElement(e))) return null; // the positions become unknowable
  if (slots.length < 3) return "pipe"; // Node fills the rest
  return literal(slots[2]);
}

const SPAWNS = new Set(["execFileSync", "execSync", "spawnSync"]);

/**
 * Line numbers of spawns in `source` whose child stderr would reach this process.
 *
 * PARSED, NOT SCANNED. Five review rounds found five defects in a hand-rolled text scanner, and
 * every one was lexical rather than about stdio: a call named in a comment read as real, a call
 * quoted as data read as real, a comment in front of a spread hid the spread, and filtering
 * strings out then hid a real call inside a template interpolation. Each fix was right and the
 * next edge case was already waiting. TypeScript is already a dependency here — scripts/
 * dashboard-inventory.mjs parses with it for the same reason — so the whole class goes away.
 */
export function unpipedSpawns(source: string): number[] {
  const sf = ts.createSourceFile("scan.ts", source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  const found: number[] = [];
  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node)) {
      const callee = node.expression;
      const name = ts.isPropertyAccessExpression(callee)
        ? callee.name.text
        : ts.isIdentifier(callee)
          ? callee.text
          : "";
      if (SPAWNS.has(name)) {
        const slot = stderrSlot(node);
        if (slot !== "pipe" && slot !== "ignore") {
          found.push(sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1);
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return found.sort((a, b) => a - b);
}

/** Every .ts file under tests/, as a path relative to tests/. */
async function testSources(dir: URL, prefix = ""): Promise<string[]> {
  const out: string[] = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      out.push(...(await testSources(new URL(`${entry.name}/`, dir), `${prefix}${entry.name}/`)));
    } else if (entry.name.endsWith(".ts")) {
      out.push(`${prefix}${entry.name}`);
    }
  }
  return out;
}

describe("tests do not leak a child process's stderr into the run", () => {
  // Two throwaway scripts standing in for the real ones: one that refuses the way check scripts do,
  // one that succeeds. Real files rather than `node -e`, because runScript's whole contract is
  // "given a script path, run it" and testing it through a flag would test a different call shape.
  let dir: string;
  let refuses: string;
  let succeeds: string;

  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), "dfir-stderr-"));
    refuses = join(dir, "refuses.mjs");
    succeeds = join(dir, "succeeds.mjs");
    writeFileSync(refuses, 'console.error("REFUSING: synthetic");\nprocess.exit(3);\n');
    writeFileSync(succeeds, "process.exit(0);\n");
  });

  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  // 30s, not the suite's 15s default. MEASURED at 7.7s on an idle machine — this parses every one
  // of the ~625 test files with the TypeScript compiler, so it is genuinely heavy rather than slow
  // by accident. At 51% of the default budget it was the first test to fail under any contention
  // (observed at 21s on a loaded run), which reads as flake and trains people to ignore it. The
  // headroom is for the machine, not for the test: if this ever approaches 30s the scan itself has
  // regressed and that is worth failing over.
  it("gives every spawn in the suite an explicit stdio that pipes stderr", { timeout: 30_000 }, async () => {
    // Structural, not behavioural, and deliberately so. The leak is invisible from inside the
    // process that leaks — the parent's stderr belongs to the test runner — so the cheap thing a
    // test can check is that no call site sets the leak up.
    const files = await testSources(TESTS);
    expect(files.length, "found no test sources — the walk is looking in the wrong place").toBeGreaterThan(
      10,
    );

    const offenders: string[] = [];
    for (const file of files) {
      // No file is exempt, including this one. It used to be skipped because its fixture — a list
      // of deliberately bad spawns written as strings — was reported as real code. Skipping was
      // the wrong fix: an exemption is a hole the size of whatever else is in the file. The
      // scanner now knows a quoted call from a call.
      const source = await readFile(new URL(file, TESTS), "utf8");
      offenders.push(...unpipedSpawns(source).map((line) => `${file}:${line}`));
    }

    expect(
      offenders,
      "these spawns would echo the child's stderr onto the run's own, which is how four refusal " +
        "messages came to print on every green run. Use tests/helpers/runScript.ts, or pass " +
        '`stdio: ["ignore", "pipe", "pipe"]` yourself',
    ).toEqual([]);
  });

  it("flags every spawn whose stderr reaches this process, and no others", () => {
    // The detector, watched working, against each form measured above. Scanning real files reports
    // "[]" both when every spawn is correct AND when the scan has quietly stopped recognising
    // spawns at all — two cases a file-walking assertion cannot tell apart on its own.
    //
    // The `2` case is why this reads the value instead of searching for "inherit": a raw file
    // descriptor leaks and contains no keyword to find. An earlier version of this guard passed it.
    const source = [
      'const a = execFileSync(node, [s], { encoding: "utf8" });', // 1: no stdio at all
      "const b = execFileSync(node, [s], {",
      '  encoding: "utf8",', // options wrapped across lines, as all four real leaks were
      "});", // reported at line 2, where the call starts
      'const c = execFileSync(node, [s], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });',
      'const d = spawnSync(node, [s], { stdio: "inherit" });', // 6: loudly does the default
      'const e = execFileSync(node, [s], { stdio: ["ignore", "pipe", "inherit"] });', // 7
      'const f = execFileSync(node, [s], { stdio: ["ignore", "pipe", 2] });', // 8: fd 2 IS our stderr
      'const g = execFileSync(node, [s], { stdio: ["ignore", "pipe"] });', // short: Node fills "pipe"
      "const h = execFileSync(node, [s], { stdio: whateverOptsSays });", // 10: not statically readable
      'const i = execFileSync(node, [s], { stdio: "pipe" });',
      'const j = execFileSync(node, [s], { stdio: ["ignore", "pipe", "ignore"] });',
      "const k = runScript(SCRIPT, [s]);", // not a spawn at all
      "const l = execFileSync(node, [s], { stdio: [...STDIO] });", // 14: spread hides the slots
      'const m = execFileSync(node, [s], { stdio: ["ignore", ...rest] });', // 15: same, partially
      "const n = execFileSync(node, [s], { stdio: [/* keep */ ...STDIO] });", // 16: comment first
      "const o = execFileSync(node, [s], {", // 17: and the same across lines
      "  stdio: [",
      "    // the usual triple",
      "    ...STDIO,",
      "  ],",
      "});",
      "// execFileSync(node, [s], {}) — a call in prose is not a call", // 23: must NOT be flagged
      'const p = describe("execFileSync(node, [s], {})", () => {});', // 24: nor is one quoted as data
      // 25: but a template INTERPOLATION is code, however much it looks like string innards.
      'const q = `${execFileSync(node, [s], { encoding: "utf8" })}`;',
    ].join("\n");

    expect(unpipedSpawns(source)).toEqual([1, 2, 6, 7, 8, 10, 14, 15, 16, 17, 25]);
  });

  it("agrees with what each stdio form actually does to a real child's stderr", () => {
    // The detector's table, checked against Node instead of against my reading of the docs.
    //
    // Every entry here was wrong in some earlier version of this guard: the first accepted any
    // `stdio` key at all, the second searched for the word "inherit" and so waved through the raw
    // descriptor. Both looked right. So each form is now RUN — a child that spawns a grandchild
    // which writes to stderr, with us capturing the child's stderr — and the observed leak is
    // asserted to match what unpipedSpawns() says about the same text.
    //
    // It also pins Node's behaviour rather than trusting it: if a short stdio array ever stopped
    // defaulting the missing slot to "pipe", this fails instead of the guard quietly going wrong.
    //
    // Only statically-readable forms belong here. A spread like `[...STDIO]` is flagged whatever it
    // expands to, so running it would compare a deliberate false positive against a clean result
    // and fail. That asymmetry is the design — over-reporting costs someone one explicit stdio,
    // under-reporting costs another few months of FAIL scrolling past — and it is pinned in the
    // fixture above instead.
    const forms = [
      "", // no stdio option at all
      ', stdio: "pipe"',
      ', stdio: "inherit"',
      ', stdio: ["ignore", "pipe", "pipe"]',
      ', stdio: ["ignore", "pipe", "inherit"]',
      ', stdio: ["ignore", "pipe", 2]',
      ', stdio: ["ignore", "pipe"]',
      ', stdio: ["ignore", "pipe", "ignore"]',
    ];

    for (const form of forms) {
      const options = `{ encoding: "utf8"${form} }`;
      const child = join(dir, "spawner.mjs");
      // Exits non-zero so runScriptExpectingFailure hands back the stderr it collected. Whether the
      // grandchild's "LEAKED" appears there is exactly the question — it can only have arrived by
      // escaping the inner spawn's stdio.
      writeFileSync(
        child,
        'import { execFileSync } from "node:child_process";\n' +
          "try {\n" +
          `  execFileSync(process.execPath, ["-e", 'console.error("LEAKED")'], ${options});\n` +
          "} catch {}\n" +
          "process.exit(7);\n",
      );

      const { status, stderr } = runScriptExpectingFailure(child, []);
      expect(status, "the probe child did not run").toBe(7);

      const leaks = stderr.includes("LEAKED");
      const flagged = unpipedSpawns(`execFileSync(node, [s], ${options});`).length > 0;
      expect(flagged, `stdio \`${form || "(absent)"}\`: leaks=${leaks}, detector says ${flagged}`).toBe(
        leaks,
      );
    }
  });

  it("still hands the refusal text to the test that asked for it", () => {
    // The complement, and the reason this pair is worth having: suppressing the echo is only
    // correct if the message is still there to assert on. A helper that swallowed stderr outright
    // would satisfy the test above and silently gut every refusal assertion in the suite.
    const { status, stderr } = runScriptExpectingFailure(refuses, []);
    expect(status).toBe(3);
    expect(stderr).toContain("REFUSING: synthetic");
  });

  it("fails loudly when a script it expected to refuse actually succeeds", () => {
    // A guard that has stopped guarding must not read as a pass. Under the old try/catch shape the
    // assertions lived in the catch block, so a script that stopped refusing ran no assertions at
    // all — an `expect.unreachable` call was the only thing between that and a green test, and it
    // had to be remembered at every call site.
    expect(() => runScriptExpectingFailure(succeeds, [])).toThrow(/exit non-zero, but it succeeded/);
  });
});
