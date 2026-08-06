// The inventory of what is left in dashboard.html's inline script must be able to see all of it.
//
// #415's complaint is that no inventory of the remaining features exists anywhere in the repo, so
// each extraction has picked a block by eye and measured it by hand. scripts/dashboard-inventory.mjs
// is that inventory. This suite guards the one property that makes it trustworthy: it accounts for
// every line. A block sitting outside every banner comment would be invisible to it, and an
// inventory with a hole in it is worse than none — it reads as "that is everything".
//
// IT DELIBERATELY DOES NOT ASSERT THAT scripts/dashboard-inventory.json IS CURRENT. The route
// inventory does pin its artifact, and that works because routes change rarely. This file changes
// on every extraction — the whole point of the project it serves — so pinning the snapshot would
// fail CI on each one and be regenerated without being read, which is how a ledger stops meaning
// anything. The JSON is a planning snapshot; the invariant is what is enforced.
import { describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const SCRIPT = new URL("../../scripts/dashboard-inventory.mjs", import.meta.url).pathname;

const run = (): {
  inlineScript: { lines: number };
  covered: number;
  ready: number;
  sections: {
    label: string;
    start: number;
    end: number;
    size: number;
    stateEscapes: string[];
    publish: string[];
    moduleScopeDom: number;
  }[];
} => JSON.parse(execFileSync(process.execPath, [SCRIPT, "--json"], { encoding: "utf8" }));

describe("dashboard extraction inventory", () => {
  const report = run();

  it("accounts for every line of the inline script", () => {
    expect(report.covered).toBe(report.inlineScript.lines);
  });

  it("finds the inline script at all", () => {
    // A zero-line result would satisfy the coverage check above (0 === 0) while telling us nothing.
    // The target in ARCHITECTURE.md is 2,000 lines; anything at or below that means either the
    // project finished or the locator broke, and both deserve a human looking at this file.
    expect(report.inlineScript.lines).toBeGreaterThan(2000);
    expect(report.sections.length).toBeGreaterThan(10);
  });

  it("gives every section a non-empty range and label", () => {
    for (const s of report.sections) {
      expect(s.label, `section at ${s.start} has no label`).not.toBe("");
      expect(s.end, `section "${s.label}" ends before it starts`).toBeGreaterThanOrEqual(s.start);
      expect(s.size).toBe(s.end - s.start + 1);
    }
  });

  it("separates state escapes from published functions", () => {
    // The distinction is the whole value of the measurement: counted together, a block whose
    // functions are called from elsewhere — the ordinary case, which `window` publication handles —
    // is indistinguishable from one whose mutable state is read from elsewhere, which is the actual
    // blocker. If these two lists ever share a name, one of them is classifying by the wrong kind.
    for (const s of report.sections) {
      const overlap = s.publish.filter((n) => s.stateEscapes.includes(n));
      expect(overlap, `"${s.label}" lists ${overlap.join(", ")} as both`).toEqual([]);
    }
  });

  it("reports the ready count as the sections with no state escapes", () => {
    const ready = report.sections.filter((s) => s.stateEscapes.length === 0).length;
    expect(report.ready).toBe(ready);
  });

  it("exits non-zero when code sits outside every section", () => {
    // The coverage check is the guard, so it has to be watched failing. Build a dashboard whose
    // inline block opens with code BEFORE its first banner comment — the shape of a feature the
    // inventory cannot see — and confirm the script refuses rather than reporting a tidy subset.
    const dir = mkdtempSync(join(tmpdir(), "dfir-inv-"));
    const broken = join(dir, "dashboard.html");
    writeFileSync(
      broken,
      [
        "<html><body>",
        "<script>",
        "  var strayFeatureNobodyBannered = 1;", // outside every section
        "  function stray() { return strayFeatureNobodyBannered; }",
        "  // ---- A real section ----",
        "  var owned = 2;",
        "</script>",
        "</body></html>",
      ].join("\n"),
    );
    try {
      execFileSync(process.execPath, [SCRIPT, "--html", broken, "--json"], { encoding: "utf8" });
      expect.unreachable("inventory accepted a dashboard with code outside every section");
    } catch (e) {
      const err = e as { status?: number; stderr?: string };
      expect(err.status, "expected a non-zero exit").toBeGreaterThan(0);
      expect(err.stderr ?? "").toContain("invisible to this inventory");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("accepts that same dashboard once the stray code is bannered", () => {
    // The complement: without it, the test above passes for any reason the script exits non-zero —
    // a syntax error, a bad path, a crash — and would keep passing after the guard was deleted.
    const dir = mkdtempSync(join(tmpdir(), "dfir-inv-"));
    const fixed = join(dir, "dashboard.html");
    writeFileSync(
      fixed,
      [
        "<html><body>",
        "<script>",
        "  // ---- Stray, now owned ----",
        "  var strayFeatureNobodyBannered = 1;",
        "  function stray() { return strayFeatureNobodyBannered; }",
        "  // ---- A real section ----",
        "  var owned = 2;",
        "</script>",
        "</body></html>",
      ].join("\n"),
    );
    try {
      const out = execFileSync(process.execPath, [SCRIPT, "--html", fixed, "--json"], {
        encoding: "utf8",
      });
      const r = JSON.parse(out);
      expect(r.covered).toBe(r.inlineScript.lines);
      expect(r.sections.map((s: { label: string }) => s.label)).toEqual([
        "Stray, now owned",
        "A real section",
      ]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
