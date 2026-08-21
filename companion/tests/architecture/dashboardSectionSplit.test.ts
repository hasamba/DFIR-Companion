// The split that every remaining tier-3 extraction depends on: what becomes the module body, and
// what has to become its initializer.
//
// This exists because I got that split wrong by hand. Searching for lines beginning `document.`
// found three of the six load-time statements in the Settings → Tools block. The other three were
// bare `{ … }` blocks scoping a `const b` around one button, and shipping them in the module body
// would have left three buttons permanently dead — in a <head> script the query runs before the
// markup exists, binds nothing, and reports nothing. The first case below is exactly that shape.
import { describe, expect, it } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { runScript, runScriptExpectingFailure } from "../helpers/runScript.js";

// fileURLToPath, NOT `.pathname`: on Windows `.pathname` yields "/D:/a/..." and Node
// resolves that against the drive as "D:\\D:\\a\\...", so the script is never found.
const SCRIPT = fileURLToPath(new URL("../../scripts/dashboard-section-split.mjs", import.meta.url));

/** Write a throwaway dashboard whose inline script is exactly `body`, one statement per line. */
const dashboardWith = (body: string[]): { dir: string; path: string } => {
  const dir = mkdtempSync(join(tmpdir(), "dfir-split-"));
  const path = join(dir, "dashboard.html");
  writeFileSync(path, ["<html><body>", "<script>", ...body, "</script>", "</body></html>"].join("\n"));
  return { dir, path };
};

const args = (path: string, from: number, to: number): string[] => [
  String(from),
  String(to),
  "--json",
  "--html",
  path,
];

const split = (path: string, from: number, to: number) => JSON.parse(runScript(SCRIPT, args(path, from, to)));

/**
 * The refusal cases. These go through the helper so the `[split] REFUSING: …` line each one is
 * PROVOKING is captured rather than printed onto the run's own stderr — three of them were, on
 * every green run, describing throwaway fixtures rather than anything wrong with the dashboard.
 */
const splitExpectingFailure = (path: string, from: number, to: number) =>
  runScriptExpectingFailure(SCRIPT, args(path, from, to));

describe("dashboard section split", () => {
  it("puts a bare block that wires a button into the initializer, not the body", () => {
    // The exact statement shape that a line-based search misses. It does not begin with `document.`
    // and it is not an expression statement — it is a block — but it runs the instant the script is
    // parsed, which is all that matters.
    const { dir, path } = dashboardWith([
      "  function addThing() {}", // line 3
      '  { const b = document.getElementById("addBtn"); if (b) b.onclick = addThing; }', // line 4
    ]);
    try {
      const r = split(path, 3, 4);
      expect(r.declarations).toEqual([[3, 3]]);
      expect(r.runsAtLoad).toEqual([[4, 4]]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("counts anything that is not a declaration as running at load", () => {
    // Deliberately not "does the statement mention the DOM". A timer or a fetch kicked off at load
    // is just as much initializer work, and a DOM-shaped test would leave both in the module body.
    const { dir, path } = dashboardWith([
      "  function f() {}",
      "  const x = 1;",
      "  let y = 2;",
      "  setInterval(f, 1000);",
      "  fetch('/x');",
      "  if (window.something) f();",
    ]);
    try {
      const r = split(path, 3, 8);
      expect(r.declarations).toEqual([
        [3, 3],
        [4, 4],
        [5, 5],
      ]);
      expect(r.runsAtLoad).toEqual([
        [6, 6],
        [7, 7],
        [8, 8],
      ]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("warns about a declaration whose initializer reads the DOM", () => {
    // `const overlay = document.getElementById("x")` is a VariableStatement, so "is this a
    // declaration" files it under module body — where, in a <head> script, it evaluates to null
    // before the markup exists and every later use of it silently does nothing. It is neither
    // cleanly body nor cleanly initializer, so it is reported separately instead of guessed at.
    const { dir, path } = dashboardWith([
      '  const overlay = document.getElementById("overlay");',
      "  function usesIt() { overlay.hidden = true; }",
      "  const plain = 1;",
    ]);
    try {
      const r = split(path, 3, 5);
      expect(r.domInDeclaration).toEqual([[3, 3]]);
      // Still counted as declarations — the warning is additional, not a reclassification.
      expect(r.declarations).toEqual([
        [3, 3],
        [4, 4],
        [5, 5],
      ]);
      expect(r.runsAtLoad).toEqual([]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("refuses a range that cuts a statement in half", () => {
    // Line numbers go stale as soon as another feature is extracted, and copying a truncated range
    // produces JavaScript that does not parse. Refusing beats handing back half a function.
    const { dir, path } = dashboardWith([
      "  function whole() {", // 3
      "    return 1;", // 4
      "  }", // 5
    ]);
    try {
      const { status, stderr } = splitExpectingFailure(path, 3, 4);
      expect(status).toBe(1);
      expect(stderr).toContain("REFUSING");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("accepts that same range once it covers the whole statement", () => {
    // The complement, so the test above cannot pass because of an unrelated crash.
    const { dir, path } = dashboardWith(["  function whole() {", "    return 1;", "  }"]);
    try {
      const r = split(path, 3, 5);
      expect(r.declarations).toEqual([[3, 5]]);
      expect(r.runsAtLoad).toEqual([]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("refuses a range that encloses another feature's guard stanza", () => {
    // What an extraction leaves behind sits between banner comments, so a section's line range can
    // enclose a stanza that is not its own. Take one into a module and that OTHER feature simply
    // stops being initialised — no error, no failing unit test, nothing on screen. It happened
    // twice in #415 (initHostRanking, initDataAct) and both times a lifecycle gate caught it only
    // after the module had been written.
    const { dir, path } = dashboardWith([
      "  function mine() {}",
      '  if (typeof initSomethingElse !== "undefined") initSomethingElse();',
    ]);
    try {
      const { status, stderr } = splitExpectingFailure(path, 3, 4);
      expect(status).toBe(1);
      expect(stderr).toContain("initSomethingElse");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('catches the === "function" guard form too, not just !== "undefined"', () => {
    // The page uses both forms interchangeably. A detector that knows only one is worse than none,
    // because it reports clean and gets trusted — that exact half-match let a ticket-integrations
    // stanza travel into a module earlier in #415, and let initHypotheses through here on the
    // first try.
    const { dir, path } = dashboardWith([
      "  function mine() {}",
      '  if (typeof initOther === "function") initOther();',
    ]);
    try {
      const { status, stderr } = splitExpectingFailure(path, 3, 4);
      expect(status).toBe(1);
      expect(stderr).toContain("initOther");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("accepts the same block once the foreign stanza is outside the range", () => {
    // The complement: a rule that refused everything would read as caution and stop the work.
    const { dir, path } = dashboardWith([
      "  function mine() {}",
      '  if (typeof initSomethingElse !== "undefined") initSomethingElse();',
    ]);
    try {
      const r = split(path, 3, 3);
      expect(r.declarations).toEqual([[3, 3]]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("rejects a nonsense range rather than reporting an empty split", () => {
    // An empty result reads as "this block needs no initializer", which is the one wrong answer
    // that gets acted on without being questioned.
    const { dir, path } = dashboardWith(["  function f() {}"]);
    try {
      expect(splitExpectingFailure(path, 40, 10).status).toBe(2);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
