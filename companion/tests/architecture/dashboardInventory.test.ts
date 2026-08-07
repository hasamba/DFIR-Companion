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
    coreMachinery: string[];
    isCoreMachinery: boolean;
    isStateHub: boolean;
    vocabulary: string[];
    isDispatchBlock: boolean;
    foreignStanzas: string[];
  }[];
} => JSON.parse(execFileSync(process.execPath, [SCRIPT, "--json"], { encoding: "utf8" }));

describe("dashboard extraction inventory", () => {
  const report = run();

  it("accounts for every line of the inline script", () => {
    expect(report.covered).toBe(report.inlineScript.lines);
  });

  it("finds the inline script, and it is under the 2,000-line target", () => {
    // This assertion used to read `toBeGreaterThan(2000)` as a tripwire: "at or below the target
    // means either the project finished or the locator broke, and both deserve a human looking at
    // this file." It fired at 1,965. The project finished — #415 took the block from 16,634 lines
    // to under target across 105 extractions.
    //
    // It is now a ratchet in the other direction: a floor proves the locator still works (a broken
    // one reports zero, which would satisfy any upper bound), and the target is the ceiling.
    expect(
      report.inlineScript.lines,
      "locator broke — a zero-line result passes any ceiling",
    ).toBeGreaterThan(200);
    expect(report.inlineScript.lines, "the inline script grew back past #415's target").toBeLessThan(2000);
    expect(report.sections.length).toBeGreaterThan(5);
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

  it("counts a section ready only when its state stays put, it holds no shared machinery, AND it is not core machinery", () => {
    // All three matter. `render()` sits inside the "Now investigator cockpit" banner with 22 call
    // sites elsewhere on the page: by state escapes alone that section reads as 437 ready lines,
    // when extracting it as written would move the page's central render function into a feature
    // module. Dropping the shared-machinery half takes the headline from 61 sections to 65 — the
    // four it lets through are the ones most likely to break the page.
    //
    // The third condition was added after this test had already been written, and the test did not
    // notice — because it re-implemented the filter instead of asserting the property. The report
    // grew an isCoreMachinery flag, the ready count went on ignoring it, and a copy of the same
    // omission sat here agreeing. So the property is asserted separately below, where a future
    // fourth condition cannot be silently dropped from both places at once.
    const ready = report.sections.filter(
      (s) => s.stateEscapes.length === 0 && s.sharedMachinery.length === 0 && !s.isCoreMachinery,
    );
    expect(report.ready).toBe(ready.length);
    expect(report.ready).toBeLessThan(report.sections.filter((s) => s.stateEscapes.length === 0).length);
  });

  it("never advertises core machinery as ready, however clean it looks", () => {
    // The property, not the filter. A core-machinery section can have zero state escapes and zero
    // shared machinery and still be the page's central dispatch — that combination is exactly what
    // produced an extraction that had to be reverted, which is why the flag exists at all.
    const core = report.sections.filter((s) => s.isCoreMachinery);
    expect(
      core.length,
      "no section is marked core machinery — the flag stopped being computed",
    ).toBeGreaterThan(0);
    const readyCore = core.filter((s) => s.stateEscapes.length === 0 && s.sharedMachinery.length === 0);
    // This is the interesting case: core sections that the other two filters would wave through.
    expect(
      readyCore.length,
      "no core section is otherwise-clean, so this test proves nothing today",
    ).toBeGreaterThan(0);
    expect(report.ready + readyCore.length).toBeGreaterThan(report.ready);
    const readyLabels = new Set(
      report.sections
        .filter((s) => s.stateEscapes.length === 0 && s.sharedMachinery.length === 0 && !s.isCoreMachinery)
        .map((s) => s.label),
    );
    for (const s of core) {
      expect(readyLabels.has(s.label), `"${s.label}" is core machinery but counted ready`).toBe(false);
    }
  });

  it("still reports SOME section's shared machinery, whatever the biggest fan-out is now", () => {
    // This has been re-pointed twice, and the second time is the reason it is now written this way.
    // It first named `render` under the cockpit banner; render got its own banner; then #415 moved
    // render out of dashboard.html entirely. Each time the failure read "the fan-out measurement
    // broke" when the truth was "the thing moved" — the two cases the original note distinguished,
    // reported as the wrong one.
    //
    // So it no longer names a function. The signal is working if SOMETHING with a real fan-out is
    // reported, and the complement below is what makes that meaningful.
    const withShared = report.sections.filter((s) => s.sharedMachinery.length > 0);
    expect(
      withShared.length,
      "no section reports shared machinery at all — the fan-out measurement broke",
    ).toBeGreaterThan(0);
    for (const s of withShared) {
      expect(
        s.maxFanout,
        `"${s.label}" flags shared machinery but reports fanout ${s.maxFanout}`,
      ).toBeGreaterThanOrEqual(10);
    }
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

  it("counts a lone FUNCTION as a second feature, but not a lone constant", () => {
    // The check's first real miss. `doAsk` — the AI Ask box, forty-four lines with its own controls
    // — sat under the "Import undo / redo (#76)" banner referencing nothing around it and referenced
    // by nothing in the block, so it was a component of one and the original filter dropped every
    // singleton as noise. A lone lookup table is noise; a lone function is a feature.
    const dir = mkdtempSync(join(tmpdir(), "dfir-inv-"));
    writeFileSync(
      join(dir, "dashboard.html"),
      [
        "<html><body>",
        "<script>",
        "  // ---- One banner, a feature and a stowaway ----",
        "  function aOne() { return aTwo(); }",
        "  function aTwo() { return 1; }",
        "  const SMALL_TABLE = { a: 1 };",
        "  function stowaway() {",
        ...Array.from({ length: 10 }, (_, i) => `    const line${i} = ${i};`),
        "    return 0;",
        "  }",
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
      // aOne+aTwo is a cluster of two; stowaway is a cluster of one that counts; SMALL_TABLE is a
      // singleton that does not.
      expect(r.sections[0].clusters).toEqual([2, 1]);
      expect(r.sections[0].looksLikeTwoFeatures).toBe(true);
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

  it("flags the guard stanza an earlier extraction left inside this section's range", () => {
    // When a feature moves out, a three-line guard replaces it, and those lines land between two
    // banner comments — so the inventory files them under whichever section encloses them. They
    // belong to the feature that already left. The NSRL block's range ended with six such lines
    // from the Settings → Tools extraction, and copying the range wholesale put a call to the
    // page's dfirFeatureUnavailable inside a module, where it does not exist.
    const dir = mkdtempSync(join(tmpdir(), "dfir-inv-"));
    mkdirSync(join(dir, "js"));
    writeFileSync(
      join(dir, "js", "dashboard-gone.js"),
      "function initGone() {}\nwindow.initGone = initGone;\n",
    );
    writeFileSync(
      join(dir, "dashboard.html"),
      [
        "<html><body>",
        "<script>",
        "  // ---- A feature that is still here ----",
        "  function stillHere() {}",
        '  if (typeof initGone !== "undefined") initGone();',
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
      expect(r.sections[0].foreignStanzas).toEqual(["5 initGone"]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('catches the `=== "function"` guard idiom as well as `!== "undefined"`', () => {
    // The file uses both, and matching only one is worse than matching neither — it reads as
    // coverage. The first version required the literal `undefined` and missed
    // `if (typeof initTicketIntegrations === "function")`. That stanza sat inside the very next
    // block extracted, travelled into the module, and stopped the ticket integrations initialising
    // at all — silently, because the page was otherwise fine. Widening the pattern took the count
    // from 7 sections to 15.
    const dir = mkdtempSync(join(tmpdir(), "dfir-inv-"));
    mkdirSync(join(dir, "js"));
    writeFileSync(join(dir, "js", "dashboard-gone.js"), "window.initGone = function () {};\n");
    writeFileSync(
      join(dir, "dashboard.html"),
      [
        "<html><body>",
        "<script>",
        "  // ---- A feature that is still here ----",
        "  function stillHere() {}",
        '  if (typeof initGone === "function") initGone();',
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
      expect(r.sections[0].foreignStanzas).toEqual(["5 initGone"]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("does not flag a typeof guard for a name no module publishes", () => {
    // The page guards plenty of its own optional things. Only a guard for a name an extracted
    // module publishes is someone else's stanza; without this the flag would fire on those too.
    const dir = mkdtempSync(join(tmpdir(), "dfir-inv-"));
    mkdirSync(join(dir, "js"));
    writeFileSync(join(dir, "js", "dashboard-gone.js"), "window.initGone = function () {};\n");
    writeFileSync(
      join(dir, "dashboard.html"),
      [
        "<html><body>",
        "<script>",
        "  // ---- A feature that is still here ----",
        "  function stillHere() {}",
        '  if (typeof someBrowserThing !== "undefined") stillHere();',
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
      expect(r.sections[0].foreignStanzas).toEqual([]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("names the sections that hold the page's own spine", () => {
    // Cohesion cannot tell core machinery from a feature — machinery calls itself more tightly than
    // any feature does. The spine functions are therefore named rather than inferred.
    //
    // This used to pin `connect` under the "Cross-case capture warning" banner, the block that
    // taught the lesson. #415 has since moved connect, proceedConnect and render into modules, so
    // the assertion is about the RULE holding, not about where one name lives.
    for (const s of report.sections) {
      expect(s.isCoreMachinery).toBe(s.coreMachinery.length > 0 || s.isStateHub || s.isDispatchBlock);
    }
  });

  it("flags a heavily-called name as page vocabulary, not as the section's own", () => {
    // esc() sat under the "Background jobs" banner with 101 call sites across the page. Nothing in
    // this file flagged it: the banner was wrong, and the escape count says nothing because it
    // counts readers of mutable STATE and esc is a function. Extracting that block would have made
    // every escaped string on the page depend on the jobs module loading. Call count is the signal.
    const dir = mkdtempSync(join(tmpdir(), "dfir-inv-"));
    mkdirSync(join(dir, "js"), { recursive: true });
    const heavy = Array.from({ length: 30 }, (_, i) => `  function use${i}() { return shout("x"); }`);
    writeFileSync(
      join(dir, "dashboard.html"),
      [
        "<html><body>",
        "<script>",
        "  // ---- Owner ----",
        "  const shout = (s) => String(s).toUpperCase();",
        "  const quiet = (s) => String(s).toLowerCase();",
        ...heavy,
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
      const sec = r.sections.find((s: { label: string }) => s.label === "Owner");
      expect(sec.vocabulary.join(" "), "30 call sites is vocabulary").toContain("shout");
      // The complement: a name called once must NOT be flagged, or every declaration reads as
      // vocabulary and the signal means nothing.
      expect(sec.vocabulary.join(" "), "a one-use helper is not vocabulary").not.toContain("quiet");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("counts a const-declared arrow function as a function, not as state", () => {
    // The distinction this whole file is built on: a FUNCTION referenced from outside its block is
    // the ordinary case (publish it), a mutable BINDING is the blocker. Keying that on the
    // declaration keyword got it wrong for `const hq = (s) => ...`, and reported "Bulk finding
    // operations" as eight-blocked when three of its escapes are state and five are helpers.
    const dir = mkdtempSync(join(tmpdir(), "dfir-inv-"));
    mkdirSync(join(dir, "js"), { recursive: true });
    writeFileSync(
      join(dir, "dashboard.html"),
      [
        "<html><body>",
        "<script>",
        "  // ---- Helpers and state ----",
        '  const quote = (s) => `"${s}"`;',
        "  const named = function (s) { return s; };",
        "  let counter = 0;",
        "  const table = { a: 1 };",
        "  // ---- Reader ----",
        "  function useThem() { return quote(named(String(counter))) + table.a; }",
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
      const sec = r.sections.find((s: { label: string }) => s.label === "Helpers and state");
      // Both function forms are publishable, neither is a state escape.
      expect(sec.publish).toContain("quote");
      expect(sec.publish).toContain("named");
      expect(sec.stateEscapes).not.toContain("quote");
      expect(sec.stateEscapes).not.toContain("named");
      // The complement: real bindings must STILL be counted, or the fix has just blinded the gate.
      expect(sec.stateEscapes).toContain("counter");
      expect(sec.stateEscapes).toContain("table");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("flags a section that is core by the state it declares, not by any function it names", () => {
    // The name list above misses a whole shape. The 397-line block under the "Theme picker" banner
    // declares ws, SEV, aiEnabled, lastIocs, tlPage, iocPage, timelineSort and twenty more — the
    // page's central state — and not one core FUNCTION, so it was waved through as the largest
    // remaining feature. It is not a feature; it is the state every feature reads, filed under
    // whichever banner happened to sit above it.
    const hubs = report.sections.filter((s) => s.isStateHub);
    expect(hubs.length, "no state hubs — the threshold has drifted out of range").toBeGreaterThan(0);
    for (const h of hubs) {
      expect(h.isCoreMachinery, `${h.label} is a state hub but not flagged core`).toBe(true);
      expect(h.stateEscapes.length).toBeGreaterThanOrEqual(12);
    }
  });

  it("does not call an ordinary feature a state hub", () => {
    // The complement. A threshold low enough to catch every feature would quietly empty the queue,
    // which reads as "nothing left to extract" rather than as a broken rule.
    const ordinary = report.sections.filter((s) => !s.isStateHub);
    expect(ordinary.length, "every section is a state hub — the threshold is too low").toBeGreaterThan(
      report.sections.length / 2,
    );
    for (const s of ordinary) {
      expect(
        s.stateEscapes.length,
        `${s.label} escapes ${s.stateEscapes.length} yet is not a hub`,
      ).toBeLessThan(12);
    }
  });

  it("does not flag an ordinary feature as core machinery", () => {
    // The complement: without it, a list that matched everything would read as caution.
    const dir = mkdtempSync(join(tmpdir(), "dfir-inv-"));
    writeFileSync(
      join(dir, "dashboard.html"),
      [
        "<html><body>",
        "<script>",
        "  // ---- An ordinary feature ----",
        "  function loadThing() {}",
        "  function renderThingRow() {}",
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
      // renderThingRow must NOT match on a prefix — the list is exact names, not shapes.
      expect(r.sections[0].coreMachinery).toEqual([]);
      expect(r.sections[0].isCoreMachinery).toBe(false);
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
