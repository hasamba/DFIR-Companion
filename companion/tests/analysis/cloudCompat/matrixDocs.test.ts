import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { COMPAT_ROWS, DOC_TABLE_HEADER, docRow } from "./matrix.js";

// The manual's "Cloud tools" table is the published face of matrix.ts (#2300): every row the tests
// assert must appear on the page exactly, and the page must carry no row the tests do not assert.
const page = readFileSync(new URL("../../../../mkdocs-docs/reference/importing.md", import.meta.url), "utf8");
const section = page.slice(
  page.indexOf("## Cloud tools"),
  page.indexOf("\n## ", page.indexOf("## Cloud tools") + 1),
);

describe("cloud compat — the published matrix matches the tested one (#2300)", () => {
  it("the page has a Cloud tools section that says the fixtures are synthetic", () => {
    expect(section.startsWith("## Cloud tools")).toBe(true);
    expect(section).toMatch(/synthetic/i);
    expect(section).toMatch(/not been checked against real tool output/i);
  });

  it("every tested row is on the page, verbatim, and nothing else is in the table", () => {
    const start = section.indexOf(DOC_TABLE_HEADER[0]);
    expect(start).toBeGreaterThan(-1);
    const table = section
      .slice(start)
      .split("\n")
      .filter((l, i, all) => l.startsWith("|") && all.slice(0, i).every((p) => p.startsWith("|")));
    expect(table).toEqual([...DOC_TABLE_HEADER, ...COMPAT_ROWS.map(docRow)]);
  });
});
