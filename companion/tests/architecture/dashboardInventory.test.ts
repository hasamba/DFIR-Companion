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
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
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
    maxFanout: number;
    sharedMachinery: string[];
    moduleScopeDom: number;
    boundElsewhere: string[];
    needsInitializer: boolean;
    clusters: number[];
    looksLikeTwoFeatures: boolean;
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

  it("counts a section ready only when its state stays put AND it holds no shared machinery", () => {
    // Both halves matter. `render()` sits inside the "Now investigator cockpit" banner with 22 call
    // sites elsewhere on the page: by state escapes alone that section reads as 437 ready lines,
    // when extracting it as written would move the page's central render function into a feature
    // module. Dropping the shared-machinery half takes the headline from 61 sections to 65 — the
    // four it lets through are the ones most likely to break the page.
    const ready = report.sections.filter(
      (s) => s.stateEscapes.length === 0 && s.sharedMachinery.length === 0,
    );
    expect(report.ready).toBe(ready.length);
    expect(report.ready).toBeLessThan(report.sections.filter((s) => s.stateEscapes.length === 0).length);
  });

  it("flags the cockpit section as holding shared machinery", () => {
    // The concrete case the signal exists for. If `render` ever stops being reported here, either it
    // moved (fine — update this) or the fan-out measurement broke (not fine).
    const cockpit = report.sections.find((s) => s.label.includes("cockpit"));
    expect(cockpit, "the cockpit banner is gone — re-point this test").toBeDefined();
    expect(cockpit!.sharedMachinery).toContain("render");
    expect(cockpit!.maxFanout).toBeGreaterThanOrEqual(10);
  });

  it("never reports a fan-out below the shared-machinery threshold it flagged", () => {
    for (const s of report.sections) {
      if (s.sharedMachinery.length) {
        expect(
          s.maxFanout,
          `"${s.label}" flags shared machinery but reports fanout ${s.maxFanout}`,
        ).toBeGreaterThanOrEqual(10);
      }
    }
  });

  it("counts a bare call from a sibling module as a reason to publish", () => {
    // The one direction the inventory was blind in, and the blindness is silent: a module in
    // public/js calling a page function by bare name is not an identifier anywhere in the inline
    // AST, so the name reads as block-local, the extraction does not publish it, and nothing fails
    // until someone loads the page. I very nearly shipped this scan as a no-op — it looked correct
    // and the headline count did not move — so it is pinned here rather than assumed.
    const dir = mkdtempSync(join(tmpdir(), "dfir-inv-"));
    mkdirSync(join(dir, "js"));
    writeFileSync(
      join(dir, "dashboard.html"),
      [
        "<html><body>",
        "<script>",
        "  // ---- Lonely feature ----",
        "  function calledOnlyBySibling() { return 1; }",
        "  function calledByNobody() { return 2; }",
        "</script>",
        "</body></html>",
      ].join("\n"),
    );
    writeFileSync(join(dir, "js", "sibling.js"), "calledOnlyBySibling();\n");
    try {
      const r = JSON.parse(
        execFileSync(process.execPath, [SCRIPT, "--html", join(dir, "dashboard.html"), "--json"], {
          encoding: "utf8",
        }),
      );
      const only = r.sections.find((s: { label: string }) => s.label === "Lonely feature");
      expect(only.publish).toContain("calledOnlyBySibling");
      // The complement: a function nothing calls must NOT be published, or "publish" degenerates
      // into "every function", and the measurement stops distinguishing anything.
      expect(only.publish).not.toContain("calledByNobody");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("ignores a sibling's mention of a name inside a comment", () => {
    // Why the sibling scan parses instead of grepping. `render(` appears 23 times across public/js
    // by grep and adds nothing by AST, because those are prose in comments. A grep-based version of
    // this scan would inflate every fan-out with commentary.
    const dir = mkdtempSync(join(tmpdir(), "dfir-inv-"));
    mkdirSync(join(dir, "js"));
    writeFileSync(
      join(dir, "dashboard.html"),
      [
        "<html><body>",
        "<script>",
        "  // ---- Lonely feature ----",
        "  function mentionedInProse() { return 1; }",
        "</script>",
        "</body></html>",
      ].join("\n"),
    );
    writeFileSync(join(dir, "js", "sibling.js"), "// mentionedInProse() is documented here.\n");
    try {
      const r = JSON.parse(
        execFileSync(process.execPath, [SCRIPT, "--html", join(dir, "dashboard.html"), "--json"], {
          encoding: "utf8",
        }),
      );
      const only = r.sections.find((s: { label: string }) => s.label === "Lonely feature");
      expect(only.publish).toEqual([]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("flags a block whose controls are bound by some other top-level statement", () => {
    // `moduleScopeDom: 0` means the block wires nothing. It does NOT mean nothing wires the block —
    // the page has a shared modal-wiring block that binds the controls for every modal in one
    // place, hundreds of lines from the feature. Two extractions in a row scored zero here and
    // still needed an initializer, because moving the functions out turns those bindings into bare
    // references evaluated at load, and a 404 is then a ReferenceError before the WebSocket
    // connects rather than one dead modal.
    const dir = mkdtempSync(join(tmpdir(), "dfir-inv-"));
    writeFileSync(
      join(dir, "dashboard.html"),
      [
        "<html><body>",
        "<script>",
        "  // ---- The feature ----",
        "  function closeThing() {}",
        "  // ---- Somewhere else entirely ----",
        '  document.getElementById("x").onclick = closeThing;',
        "</script>",
        "</body></html>",
      ].join("\n"),
    );
    try {
      const r = JSON.parse(
        execFileSync(process.execPath, [SCRIPT, "--html", join(dir, "dashboard.html"), "--json"], {
          encoding: "utf8",
        }),
      );
      const feature = r.sections.find((s: { label: string }) => s.label === "The feature");
      expect(feature.moduleScopeDom).toBe(0);
      expect(feature.boundElsewhere).toEqual(["closeThing"]);
      expect(feature.needsInitializer).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("does not flag a name that is only called from inside a callback", () => {
    // The distinction the flag lives or dies on. `onclick = closeThing` READS closeThing as the
    // page loads; `onclick = () => closeThing()` does not — it reads it when someone clicks, by
    // which time the facade stub or the real module is there either way. Without this the flag
    // would fire on nearly every section and mean nothing.
    const dir = mkdtempSync(join(tmpdir(), "dfir-inv-"));
    writeFileSync(
      join(dir, "dashboard.html"),
      [
        "<html><body>",
        "<script>",
        "  // ---- The feature ----",
        "  function closeThing() {}",
        "  // ---- Somewhere else entirely ----",
        '  document.getElementById("x").onclick = () => closeThing();',
        "</script>",
        "</body></html>",
      ].join("\n"),
    );
    try {
      const r = JSON.parse(
        execFileSync(process.execPath, [SCRIPT, "--html", join(dir, "dashboard.html"), "--json"], {
          encoding: "utf8",
        }),
      );
      const feature = r.sections.find((s: { label: string }) => s.label === "The feature");
      expect(feature.boundElsewhere).toEqual([]);
      expect(feature.needsInitializer).toBe(false);
      // Still an escape that must be published — only the load-time urgency differs.
      expect(feature.publish).toContain("closeThing");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("flags a banner that covers two families of functions that never call each other", () => {
    // Three sections in a row turned out to be two features sharing a heading that named only one.
    // The worst was "Push ingest token (#84)": 222 lines of which 47 are the push token and the rest
    // are the Velociraptor bundle builder belonging to the feature ABOVE the banner. Extracting to
    // the banner would have cut a live feature in half.
    const dir = mkdtempSync(join(tmpdir(), "dfir-inv-"));
    writeFileSync(
      join(dir, "dashboard.html"),
      [
        "<html><body>",
        "<script>",
        "  // ---- One banner, two features ----",
        "  function aOne() { return aTwo(); }",
        "  function aTwo() { return 1; }",
        "  function bOne() { return bTwo(); }",
        "  function bTwo() { return 2; }",
        "</script>",
        "</body></html>",
      ].join("\n"),
    );
    try {
      const r = JSON.parse(
        execFileSync(process.execPath, [SCRIPT, "--html", join(dir, "dashboard.html"), "--json"], {
          encoding: "utf8",
        }),
      );
      const only = r.sections[0];
      expect(only.clusters).toEqual([2, 2]);
      expect(only.looksLikeTwoFeatures).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("does not flag one feature just because it has several functions", () => {
    // The complement, and the one that keeps this usable: without it the flag could fire on every
    // section and mean nothing. One reference joining the two halves is enough to make them one.
    const dir = mkdtempSync(join(tmpdir(), "dfir-inv-"));
    writeFileSync(
      join(dir, "dashboard.html"),
      [
        "<html><body>",
        "<script>",
        "  // ---- One banner, one feature ----",
        "  function aOne() { return aTwo(); }",
        "  function aTwo() { return bOne(); }",
        "  function bOne() { return bTwo(); }",
        "  function bTwo() { return 2; }",
        "</script>",
        "</body></html>",
      ].join("\n"),
    );
    try {
      const r = JSON.parse(
        execFileSync(process.execPath, [SCRIPT, "--html", join(dir, "dashboard.html"), "--json"], {
          encoding: "utf8",
        }),
      );
      expect(r.sections[0].clusters).toEqual([4]);
      expect(r.sections[0].looksLikeTwoFeatures).toBe(false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
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
