import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

interface Api {
  renderHostDuplicates(pending: unknown[]): string;
}

const panel = loadDashboardModule<Api>("dashboard-host-duplicates.js", ["dashboard-escape.js"]);

const pair = { canonical: "win11.windomain.local", other: "win11", reason: "shortname-fqdn" };

describe("host duplicates panel", () => {
  it("renders nothing when there is no pending pair", () => {
    expect(panel.renderHostDuplicates([])).toBe("");
  });

  it("names both spellings and offers both actions", () => {
    const html = panel.renderHostDuplicates([pair]);
    expect(html).toContain("win11.windomain.local");
    expect(html).toContain("data-hd-merge");
    expect(html).toContain("data-hd-dismiss");
  });

  it("says synthesis is blocked", () => {
    expect(panel.renderHostDuplicates([pair]).toLowerCase()).toContain("analysis is on hold");
  });

  it("escapes a hostile host name", () => {
    const html = panel.renderHostDuplicates([{ ...pair, other: "<img src=x onerror=alert(1)>" }]);
    expect(html).not.toContain("<img src=x");
    expect(html).toContain("&lt;img");
  });

  it("escapes attribute-breakout characters in a hostile host name", () => {
    // A quote-free payload cannot tell escAttr from esc: escAttr is esc PLUS quote-escaping
    // (public/js/dashboard-escape.js), so a payload with no `"` or `'` passes identically either
    // way. This one carries both quote flavours, so it only stays safe if the quote-escaping half
    // actually ran on the attribute.
    const hostile = `<img src=x onerror=alert(1)>" onmouseover="alert(2)'`;
    const html = panel.renderHostDuplicates([{ ...pair, other: hostile }]);
    // Anchored to the attribute itself (`data-hd-other="`), not searched for anywhere in the page:
    // the <code> text rendering uses esc() too and correctly leaves quotes unescaped there — text
    // content needs no quote-escaping, only attribute values do — so an unanchored check would
    // find the same raw quotes in a position where they are actually safe.
    expect(html).not.toContain('data-hd-other="&lt;img src=x onerror=alert(1)&gt;" onmouseover="alert(2)');
    expect(html).toContain(
      'data-hd-other="&lt;img src=x onerror=alert(1)&gt;&quot; onmouseover=&quot;alert(2)&#39;"',
    );
  });
});

// ── Reachability (#575 follow-up) ────────────────────────────────────────────────────────────────
//
// Everything above tests the panel's HTML. None of it could catch the reported bug, which was that
// the analyst never SAW that HTML: the Now view lists its visible sections and hides every other,
// sec-host-duplicates was not on the list, and the header chip's handler called scrollIntoView on a
// display:none element — a no-op. So a held synthesis had no reachable release anywhere in the
// default view. These read the markup and the module source, because that is where the bug lived.
describe("host duplicates panel reachability", () => {
  const markup = readFileSync(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
  const module = readFileSync(
    new URL("../../../public/js/dashboard-host-duplicates.js", import.meta.url),
    "utf8",
  );

  it("declares the section's gate closed in markup so it cannot flash before paint runs", () => {
    expect(markup).toMatch(/<section id="sec-host-duplicates" data-gate-open=""/);
  });

  it("opens the gate exactly when a pair is pending, and defers display to applySectionsVis", () => {
    expect(module).toMatch(/gateOpen = pending\.length \? "1" : ""/);
    expect(module).toMatch(/applySectionsVis\(\)/);
  });

  // The gate alone is not enough: applyViewLayout has already written `false` into SECTIONS_VIS_KEY
  // for this section on any dashboard that has ever shown the Now view, and it carries a gated
  // section's stored choice through untouched. Without this, the gate opens onto a section the
  // stored preference still hides.
  it("forces the stored visibility on while a pair is pending", () => {
    expect(module).toMatch(/SECTIONS_VIS_KEY/);
    expect(module).toMatch(/vis\["sec-host-duplicates"\] = true/);
  });

  it("puts both gate chips in the status cluster, after the AI status pill", () => {
    const ai = markup.indexOf('id="aiStatus"');
    const duplicates = markup.indexOf('id="hostDuplicatesBadge"');
    const presidio = markup.indexOf('id="presidioPendingBadge"');
    expect(ai).toBeGreaterThan(-1);
    expect(duplicates).toBeGreaterThan(ai);
    expect(presidio).toBeGreaterThan(ai);
  });
});
