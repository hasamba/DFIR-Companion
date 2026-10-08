import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";

// The swimlane's lane-name column was a fixed 160px, so full host names were cut
// ("HOST-WITH-A-LONG-NAME.corp.example." for HOST-WITH-A-LONG-NAME.corp.example.com). It now sizes to its longest name.
// The "View as table" screen-reader alternative under the chart was removed on request.

const read = (rel: string) => readFile(new URL(`../../../${rel}`, import.meta.url), "utf8");

describe("swimlane lane labels", () => {
  it("sizes the label column to its longest name instead of a fixed 160px", async () => {
    const css = await read("public/css/dashboard-toolbar.css");
    const rule = css.match(/\.swimlane-labels\s*\{[^}]*\}/)?.[0] ?? "";
    expect(rule).toContain("width: max-content");
    expect(rule).toContain("min-width: 160px");
    expect(rule).not.toMatch(/(^|[\s;{])width:\s*160px/);
  });

  it("sizes the PNG export's label column from the on-screen one, not a constant", async () => {
    const js = await read("public/js/dashboard-swimlane.js");
    expect(js).not.toContain("const labelW = 160;");
    expect(js).toContain("swimlaneLabels");
    expect(js).not.toContain("l.label.length > 22");
  });
});

describe("swimlane table alternative removal", () => {
  it("leaves no table host, script tag or render call behind", async () => {
    const html = await read("public/dashboard.html");
    const js = await read("public/js/dashboard-swimlane.js");
    expect(html).not.toContain("swimlaneTableAlt");
    expect(html).not.toContain("describe-as-table");
    expect(js).not.toContain("DfirChartTable");
  });
});
