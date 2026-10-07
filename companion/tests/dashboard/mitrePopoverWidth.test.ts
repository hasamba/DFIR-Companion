import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

// The MITRE technique detail box was a fixed 340px, so event descriptions wrapped every few words
// and the list read as a narrow column. It is now 640px, capped to the section, and the code that
// places it uses its real width instead of a hard-coded 340.
const css = readFileSync(new URL("../../../public/css/mitre-matrix.css", import.meta.url), "utf8");
const js = readFileSync(new URL("../../../public/js/dashboard-mitre-matrix.js", import.meta.url), "utf8");

describe("MITRE technique popover width", () => {
  it("is 640px wide, and never wider than its section", () => {
    const rule = css.match(/\.mm-popover\s*\{[^}]*\}/)?.[0] ?? "";
    expect(rule).toContain("width: 640px");
    expect(rule).toContain("max-width: calc(100% - 8px)");
    expect(rule).not.toContain("width: 340px");
  });

  it("keeps the box inside the section by its measured width", () => {
    expect(js).toContain("pop.offsetWidth");
    expect(js).not.toContain("s.width - 340");
  });
});
