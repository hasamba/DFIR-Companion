import { describe, expect, it } from "vitest";
import { blockMd, cellMd, oneLineMd } from "../../src/reports/mdText.js";

describe("oneLineMd", () => {
  it("collapses every newline so the value cannot leave its line", () => {
    expect(oneLineMd("Beacon\r\n\n## Forged")).toBe("Beacon ## Forged");
  });

  it("keeps the whole value — nothing is truncated away", () => {
    expect(oneLineMd("a\nb\nc")).toBe("a b c");
  });
});

describe("blockMd escapes what would restructure the report", () => {
  it("escapes an ATX heading", () => {
    expect(blockMd("## Forged")).toBe("\\## Forged");
  });

  it("escapes an indented ATX heading without losing its indentation", () => {
    expect(blockMd("   ## Forged")).toBe("   \\## Forged");
  });

  it("escapes a setext underline", () => {
    expect(blockMd("Forged\n===")).toBe("Forged\n\\===");
  });

  it("escapes a thematic break", () => {
    expect(blockMd("above\n---\nbelow")).toBe("above\n\\---\nbelow");
  });
});

describe("blockMd leaves ordinary prose alone", () => {
  // The other half of the contract. Over-escaping would put stray backslashes through every
  // AI-written description in every report, which is a worse deliverable than the one this guards.
  it("keeps bullet lists", () => {
    expect(blockMd("- first\n- second")).toBe("- first\n- second");
  });

  it("keeps numbered lists, emphasis and code spans", () => {
    const prose = "1. **PsExec** ran\n2. it wrote `svc.exe`";
    expect(blockMd(prose)).toBe(prose);
  });

  it("keeps a hash that does not open a heading", () => {
    // "#1" is not an ATX heading in CommonMark — a heading needs whitespace after the hashes.
    expect(blockMd("ticket #1 covers this")).toBe("ticket #1 covers this");
    expect(blockMd("#hashtag")).toBe("#hashtag");
  });

  it("keeps blank lines, so paragraphs still separate", () => {
    expect(blockMd("one\n\ntwo")).toBe("one\n\ntwo");
  });
});

describe("cellMd", () => {
  it("escapes the cell separator and flattens newlines", () => {
    expect(cellMd("a|b\nc")).toBe("a\\|b c");
  });
});
