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

  it("spawns scripts only through the stderr-capturing helper", async () => {
    // Structural, not behavioural, and deliberately so. The leak is invisible from inside the
    // process that leaks — the parent's stderr belongs to the test runner — so the cheap thing a
    // test can check is that no call site sets the leak up. One helper owns the `stdio` option;
    // any other spawn is a copy of the options object waiting to drop it again.
    const files = await testSources(TESTS);
    expect(files.length, "found no test sources — the walk is looking in the wrong place").toBeGreaterThan(
      10,
    );

    const offenders: string[] = [];
    for (const file of files) {
      if (file === "helpers/runScript.ts") continue;
      const source = await readFile(new URL(file, TESTS), "utf8");
      for (const [i, line] of source.split("\n").entries()) {
        // The call form, not the bare name: the helper is named in prose in more than one comment,
        // and a mention is not a spawn.
        if (/\b(?:execFileSync|spawnSync)\s*\(/.test(line)) offenders.push(`${file}:${i + 1}`);
      }
    }

    expect(
      offenders,
      "spawn scripts via tests/helpers/runScript.ts — a bare execFileSync echoes the child's " +
        "stderr onto the run's own, which is how four refusal messages came to print on every " +
        "green run",
    ).toEqual([]);
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
