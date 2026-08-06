// The split that every remaining tier-3 extraction depends on: what becomes the module body, and
// what has to become its initializer.
//
// This exists because I got that split wrong by hand. Searching for lines beginning `document.`
// found three of the six load-time statements in the Settings → Tools block. The other three were
// bare `{ … }` blocks scoping a `const b` around one button, and shipping them in the module body
// would have left three buttons permanently dead — in a <head> script the query runs before the
// markup exists, binds nothing, and reports nothing. The first case below is exactly that shape.
import { describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const SCRIPT = new URL("../../scripts/dashboard-section-split.mjs", import.meta.url).pathname;

/** Write a throwaway dashboard whose inline script is exactly `body`, one statement per line. */
const dashboardWith = (body: string[]): { dir: string; path: string } => {
  const dir = mkdtempSync(join(tmpdir(), "dfir-split-"));
  const path = join(dir, "dashboard.html");
  writeFileSync(path, ["<html><body>", "<script>", ...body, "</script>", "</body></html>"].join("\n"));
  return { dir, path };
};

const split = (path: string, from: number, to: number) =>
  JSON.parse(
    execFileSync(process.execPath, [SCRIPT, String(from), String(to), "--json", "--html", path], {
      encoding: "utf8",
    }),
  );

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

  it("refuses a range that cuts a statement in half", () => {
    // Line numbers go stale as soon as another feature is extracted, and copying a truncated range
    // produces JavaScript that does not parse. Refusing beats handing back half a function.
    const { dir, path } = dashboardWith([
      "  function whole() {", // 3
      "    return 1;", // 4
      "  }", // 5
    ]);
    try {
      execFileSync(process.execPath, [SCRIPT, "3", "4", "--json", "--html", path], {
        encoding: "utf8",
      });
      expect.unreachable("accepted a range ending inside a function body");
    } catch (e) {
      const err = e as { status?: number; stderr?: string };
      expect(err.status).toBe(1);
      expect(err.stderr ?? "").toContain("REFUSING");
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

  it("rejects a nonsense range rather than reporting an empty split", () => {
    // An empty result reads as "this block needs no initializer", which is the one wrong answer
    // that gets acted on without being questioned.
    const { dir, path } = dashboardWith(["  function f() {}"]);
    try {
      execFileSync(process.execPath, [SCRIPT, "40", "10", "--json", "--html", path], {
        encoding: "utf8",
      });
      expect.unreachable("accepted a range that ends before it starts");
    } catch (e) {
      expect((e as { status?: number }).status).toBe(2);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
