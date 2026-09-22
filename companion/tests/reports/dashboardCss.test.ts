import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { STATIC_ASSETS } from "../../src/http/staticAssets.js";

// THE STYLESHEET IS EIGHT FILES SINCE #415, and splitting one file into eight introduces exactly
// one failure mode that splitting cannot be blamed for anywhere else in the page.
//
// A byte-identity check on the concatenation proves the cascade is unchanged — same rules, same
// order, same bytes — and it is what the split was verified with. But it is INVARIANT to which part
// a given rule lands in, and it says nothing at all about a part that never loads. Both of those
// gaps meet at `@keyframes`, which resolves by NAME across the whole document rather than by
// document order. Drop one <link> and the seven that remain are still perfectly ordered; nothing is
// un-overridden, no region is unstyled, and any animation whose keyframe lived in the missing part
// simply stops.
//
// The case this was written for: `@keyframes spin`, cut into dashboard-timeline.css. Its ONLY
// consumer is `animation:spin 1s linear infinite` inside a data-safe-style attribute in the markup,
// which public/js/safe-dom.js hoists into a runtime stylesheet. So a grep for "spin" across the CSS
// finds the definition and no uses, and it reads as dead code to anyone regrouping these files.

/** `p` is a site-absolute path as the markup writes it, e.g. "/css/a11y.css". */
const url = (p: string) => new URL(`../../../public${p}`, import.meta.url);
const html = readFileSync(url("/dashboard.html"), "utf8");

/** Every `/css/` sheet the page links, in document order. The order IS the cascade. */
const linked = [...html.matchAll(/<link[^>]+href="(\/css\/[^"]+)"/g)].map((m) => m[1]);
const css = linked.map((h) => readFileSync(url(h), "utf8")).join("\n");

describe("the split stylesheet is wired the way the cascade needs", () => {
  it("drops the cluster separators wherever the grouping itself is dissolved", () => {
    const css = readFileSync(new URL("../../../public/css/dashboard-toolbar.css", import.meta.url), "utf8");
    // Below the narrow breakpoint .tb-group becomes display:contents, so a separator left behind
    // would float between controls that no longer read as clusters.
    const narrow = css.slice(css.indexOf("@media (max-width: 900px)"));
    expect(narrow).toMatch(/\.tb-sep\s*\{[^}]*display:\s*none/);
    expect(css).toMatch(/\.tb-sep\s*\{[^}]*width:\s*1px/);
  });

  it("links at least the eight dashboard parts plus a11y", () => {
    // Guards the guard: every assertion below is vacuous if the extraction found nothing.
    expect(linked.length, "no /css/ links found — the regex or the markup moved").toBeGreaterThan(8);
    expect(linked.filter((h) => h.startsWith("/css/dashboard-"))).toHaveLength(8);
  });

  it("serves every stylesheet it links", () => {
    // A miss here is a 404 in production while every test passes — the #415 recipe's step 2, and
    // the reason a11y.css and the eight parts are all explicit keys rather than a served directory.
    const unregistered = linked.filter((h) => !(h in STATIC_ASSETS));
    expect(unregistered, "linked but not in STATIC_ASSETS — 404 in production").toEqual([]);
  });

  it("links them in the same order they are registered", () => {
    // The parts are a pure byte split of one file, so a specificity tie that used to be resolved by
    // one rule sitting later in the file is now resolved by it sitting in a later PART. Registration
    // order is the readable record of that; if the two ever disagree, one of them is a typo.
    const registered = Object.keys(STATIC_ASSETS).filter((k) => k.startsWith("/css/dashboard-"));
    expect(linked.filter((h) => h.startsWith("/css/dashboard-"))).toEqual(registered);
  });

  it("keeps a11y.css last in the cascade", () => {
    // Documented at the link itself and enforced nowhere until now.
    expect(linked[linked.length - 1]).toBe("/css/a11y.css");
  });

  it("defines every keyframe any animation names, somewhere in the union", () => {
    const defined = new Set([...css.matchAll(/@keyframes\s+([A-Za-z_-][\w-]*)/g)].map((m) => m[1]));
    expect(defined.size, "no @keyframes found at all — this check would pass vacuously").toBeGreaterThan(0);

    // `animation-name: x` and the name slot of the `animation` shorthand, from the CSS...
    const used = new Set<string>();
    for (const m of css.matchAll(/animation-name:\s*([^;}]+)/g)) {
      for (const n of m[1].split(",")) used.add(n.trim());
    }
    // ...and from the markup's style / data-safe-style attributes, which is where `spin` lives and
    // the only reason this check is not a tautology over the CSS alone.
    for (const m of html.matchAll(/(?:data-safe-style|style)="([^"]*)"/g)) {
      for (const a of m[1].matchAll(/animation:\s*([A-Za-z_-][\w-]*)/g)) used.add(a[1]);
      for (const a of m[1].matchAll(/animation-name:\s*([A-Za-z_-][\w-]*)/g)) used.add(a[1]);
    }
    for (const m of css.matchAll(/animation:\s*([^;}]+)/g)) {
      // Shorthand: the name is the one token that is not a time, a count, or a known keyword.
      for (const tok of m[1].split(/[\s,]+/)) {
        if (
          !tok ||
          /^\d/.test(tok) ||
          /^(infinite|linear|ease|ease-in|ease-out|ease-in-out|alternate|alternate-reverse|reverse|normal|both|forwards|backwards|none|running|paused|step-start|step-end|cubic-bezier.*|steps.*|var.*)$/.test(
            tok,
          )
        ) {
          continue;
        }
        used.add(tok.replace(/[;{}]/g, ""));
      }
    }

    const missing = [...used].filter((n) => n && !defined.has(n));
    expect(
      missing,
      "an animation names a keyframe no linked stylesheet defines — a keyframe resolves by NAME " +
        "across the document, so this is what a dropped <link> costs, with nothing else to show for it",
    ).toEqual([]);
    // And the case that motivated the check is really covered, not merely absent.
    expect(used, "the data-safe-style spinner is the reason this reads the markup too").toContain("spin");
  });
});

// The toolbar settles ~7.5s after load — the AI status text arrives and the scope group reflows —
// and pushes <main> down under a reader who has already started reading. CLS measured 0.744 on
// desktop. The two toolbar selects already reserve a width; these two did not. #884.
describe("late-arriving toolbar content reserves its space", () => {
  it("reserves a width for the AI status pill", () => {
    expect(css).toMatch(/#aiStatus\s*\{[^}]*min-width:/);
  });

  it("reserves a height for the scope group, which can wrap to a second row", () => {
    expect(css).toMatch(/\.scope-group\s*\{[^}]*min-height:/);
  });
});

// Adding the viewport meta (#880) makes the narrow layout execute for the first time. Several
// children already collapsed at a breakpoint (.now-group, .hyp-rev-cols, .wiz-row) but the page's
// own two-column grid never did — at 375px it resolved to a 291px and a 112px column.
describe("the page grid collapses once the narrow layout can actually run", () => {
  it("drops main to a single column on a narrow viewport", () => {
    expect(css).toMatch(
      /@media[^{]*max-width:\s*900px[^{]*\{[^}]*main\s*\{[^}]*grid-template-columns:\s*1fr/,
    );
  });
});

// fitToolbar() adds .icons-only when the toolbar would wrap, and the compacting rule sets
// font-size:0 on its buttons. #dashViewMenu lives inside #toolbarMain, so once its entries became
// real <button>s that rule started blanking every label in the popover.
describe("compacting the toolbar does not blank the view menu", () => {
  it("exempts the view-menu entries from the icons-only font collapse", () => {
    const rule = /\.toolbar-main\.icons-only button(?::not\([^)]*\))*\s*\{[^}]*font-size:\s*0/;
    const m = css.match(rule);
    expect(m, "the icons-only font-size:0 rule was not found").not.toBeNull();
    expect(m![0]).toContain(":not(.dv-item)");
  });
});

// The group labels (#1540) were approved on one condition: the toolbar gets no taller. Measured
// before and after, .toolbar-main stays 38px at 2560px and the header stays 116px — because the
// label is out of flow and draws into the gap the header already leaves above the scope row.
// Put the label back in flow and every one of those numbers grows by its line box.
describe("the toolbar group labels cost the row no height", () => {
  it("takes the label out of flow", () => {
    const rule = css.match(/\.tb-group-label\s*\{[^}]*\}/);
    expect(rule, ".tb-group-label has no rule").not.toBeNull();
    expect(rule![0], "an in-flow label makes the toolbar taller").toMatch(/position:\s*absolute/);
  });

  it("anchors the label to the group's centre, which every group shares", () => {
    // .toolbar-main centres its items, so a group holding a 38px <select> and one holding 31px
    // buttons only put their labels on the same line if the offset is measured from the centre.
    expect(css).toMatch(/\.tb-group-label\s*\{[^}]*top:\s*calc\(50%/);
  });

  it("lets a group wrap inside itself rather than stack the row", () => {
    // A .tb-group is atomic to flex line-breaking. Without an internal wrap a group that does not
    // fit moves to the next row whole, and a narrow window gets a tall stack of near-empty rows.
    expect(css).toMatch(/\.tb-group\s*\{[^}]*flex-wrap:\s*wrap/);
  });

  it("dissolves the grouping below the page's narrow breakpoint", () => {
    // Atomic groups cost a phone real height (measured: +11px at 700px, +40px at 375px). Below
    // 900px the grouping is undone with display:contents, which restores the pre-#1540 reflow.
    expect(css).toMatch(/@media[^{]*max-width:\s*900px[^{]*\{[^}]*\.tb-group\s*\{[^}]*display:\s*contents/);
  });

  it("never leaves a label drawn over an empty group", () => {
    expect(css).toMatch(/\.tb-group:not\(:has\(> :not\(\.tb-group-label\)\)\)\s*\{[^}]*display:\s*none/);
  });
});
