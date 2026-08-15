import { describe, it, expect } from "vitest";
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
