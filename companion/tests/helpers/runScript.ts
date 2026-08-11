// Running one of scripts/*.mjs from a test, with the child's stderr CAPTURED rather than echoed.
//
// execFileSync's default `stdio` writes the child's stderr to the PARENT's stderr as well as into
// the thrown error. Every negative test — the ones whose whole point is that a script refuses —
// therefore printed that refusal into the test run's own output. Four did, on every run, for
// months:
//
//   [inventory] FAIL: sections cover 2 lines but the inline script is 4. …
//   [split] REFUSING: 1 statement(s) start inside 3-4 and end past it (3-5). …
//   [split] REFUSING: 1 guard stanza(s) inside 3-4 initialise OTHER features (4 initSomethingElse). …
//   [split] REFUSING: 1 guard stanza(s) inside 3-4 initialise OTHER features (4 initOther). …
//
// All four came from throwaway fixtures built inside the tests, and every test passed. That
// combination is the defect: a green run that prints FAIL teaches people to read past the word
// FAIL, so the day one of these guards fires against the real dashboard it scrolls by as more of
// the usual noise. A check nobody will believe has stopped being a check.
//
// Setting `stdio` explicitly is the whole fix — `error.stderr` is populated either way, so
// assertions on the refusal text are unaffected. These helpers exist so that stays true: the four
// call sites that leaked were four copies of one options object, and a fifth copy is how it comes
// back. childStderr.test.ts pins that no test spawns a script any other way.
import { execFileSync } from "node:child_process";

/** stderr into the result, never onto the parent's. stdin closed: none of these scripts read it. */
const STDIO = ["ignore", "pipe", "pipe"] as const;

/** Run `node <script> <args>` and return its stdout. Throws if the script exits non-zero. */
export function runScript(script: string, args: string[]): string {
  return execFileSync(process.execPath, [script, ...args], {
    encoding: "utf8",
    stdio: [...STDIO],
  });
}

/** Run it and parse stdout as JSON — the `--json` shape all of these scripts speak. */
export function runScriptJson<T>(script: string, args: string[]): T {
  return JSON.parse(runScript(script, args)) as T;
}

/**
 * Run it expecting a REFUSAL, returning the exit status and the stderr it refused with.
 *
 * Throws when the script SUCCEEDS, so a guard that has quietly stopped guarding fails the test
 * rather than skipping its assertions inside a catch block that never runs.
 */
export function runScriptExpectingFailure(
  script: string,
  args: string[],
): { status: number; stderr: string } {
  try {
    runScript(script, args);
  } catch (e) {
    const err = e as { status?: number; stderr?: string };
    return { status: err.status ?? 0, stderr: err.stderr ?? "" };
  }
  throw new Error(`expected \`${script} ${args.join(" ")}\` to exit non-zero, but it succeeded`);
}
