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
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { runScriptExpectingFailure } from "../helpers/runScript.js";

const TESTS = new URL("../", import.meta.url);

/**
 * Line numbers of spawns in `source` that would echo the child's stderr onto this process's.
 *
 * The rule is the invariant itself — every spawn passes an explicit `stdio` that pipes stderr —
 * rather than "call the helper", which is only one way of satisfying it. Enforcing the proxy would
 * fail a spawn that is already correct, and a guard that fires on correct code gets relaxed by
 * whoever hits it next, usually by deleting it.
 *
 * Reads the argument list by matching parens rather than by line, because the four call sites that
 * caused this all wrapped their options object onto its own lines. A paren inside a string literal
 * would confuse the balance; none of these calls has one, and the failure mode is a false positive
 * naming a real line, which is the safe direction.
 */
export function unpipedSpawns(source: string): number[] {
  const found: number[] = [];
  const call = /\b(?:execFileSync|execSync|spawnSync)\s*\(/g;
  for (let m = call.exec(source); m; m = call.exec(source)) {
    const open = m.index + m[0].length - 1;
    let depth = 0;
    let i = open;
    for (; i < source.length; i++) {
      if (source[i] === "(") depth++;
      else if (source[i] === ")" && --depth === 0) break;
    }
    const args = source.slice(open + 1, i);
    // `stdio: "inherit"` is the loud way to do exactly what the default does quietly.
    if (!/\bstdio\s*:/.test(args) || /["']inherit["']/.test(args)) {
      found.push(source.slice(0, m.index).split("\n").length);
    }
  }
  return found;
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

  it("gives every spawn in the suite an explicit stdio that pipes stderr", async () => {
    // Structural, not behavioural, and deliberately so. The leak is invisible from inside the
    // process that leaks — the parent's stderr belongs to the test runner — so the cheap thing a
    // test can check is that no call site sets the leak up.
    const files = await testSources(TESTS);
    expect(files.length, "found no test sources — the walk is looking in the wrong place").toBeGreaterThan(
      10,
    );

    const offenders: string[] = [];
    for (const file of files) {
      // This file is the one place the offending shape appears as DATA — the fixture in the test
      // below is a string of deliberately bad spawns, and scanning it reports itself. Its own two
      // spawns go through the helper, so nothing here is exempted from the rule in practice.
      if (file === "architecture/childStderr.test.ts") continue;
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

  it("flags a spawn that omits stdio, and only that one", () => {
    // The detector, watched working. Scanning real files reports "[]" both when every spawn is
    // correct AND when the scan has quietly stopped recognising spawns at all — two cases a
    // file-walking assertion cannot tell apart on its own.
    const source = [
      'const a = execFileSync(node, [s], { encoding: "utf8" });', // 1: no stdio
      "const b = execFileSync(node, [s], {",
      '  encoding: "utf8",', // options wrapped across lines, as all four leaks were
      "});", // reported at line 2, where the call starts
      'const c = execFileSync(node, [s], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });',
      'const d = spawnSync(node, [s], { stdio: "inherit" });', // 6: loudly does the default
      "const e = runScript(SCRIPT, [s]);", // not a spawn at all
    ].join("\n");

    expect(unpipedSpawns(source)).toEqual([1, 2, 6]);
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
