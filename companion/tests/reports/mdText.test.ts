import { describe, expect, it } from "vitest";
import { blockMd, cellMd, codeSpanMd, oneLineMd } from "../../src/reports/mdText.js";

describe("codeSpanMd (#2052)", () => {
  it("wraps plain text in a single-backtick span", () => {
    expect(codeSpanMd("C:\\Users\\bob\\evidence.csv")).toBe("` C:\\Users\\bob\\evidence.csv `");
  });

  it("uses a fence longer than any backtick run inside the text", () => {
    expect(codeSpanMd("a`b``c")).toBe("``` a`b``c ```");
  });

  it("flattens newlines so the span stays on its line", () => {
    expect(codeSpanMd("x\n## Forged\r\ny")).toBe("` x ## Forged y `");
  });
});

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

describe("blockMd escapes a setext underline of any length (#1898)", () => {
  // CommonMark accepts ONE '-' as a setext H2 underline, so "Forged\n-" opened a section.
  it.each([
    ["Forged\n-", "Forged\n\\-"],
    ["Forged\n- ", "Forged\n\\- "],
    ["Forged\n   -", "Forged\n   \\-"],
    ["Forged\n=", "Forged\n\\="],
    ["Forged\n-\t", "Forged\n\\-\t"],
  ])("escapes %j", (input, expected) => {
    expect(blockMd(input)).toBe(expected);
  });

  it("escapes an underline inside a list item, at any continuation indent", () => {
    expect(blockMd("- Forged\n  -")).toBe("- Forged\n  \\-");
    expect(blockMd("10. Forged\n    -")).toBe("10. Forged\n    \\-");
  });

  it("escapes after a blockquote marker, so the quote stays a quote", () => {
    expect(blockMd("> Forged\n> -")).toBe("> Forged\n> \\-");
    expect(blockMd("> ## Forged")).toBe("> \\## Forged");
    expect(blockMd(">> Forged\n>> ==")).toBe(">> Forged\n>> \\==");
  });

  it("escapes an ATX heading opened inside a list item", () => {
    expect(blockMd("- # Forged")).toBe("- \\# Forged");
    expect(blockMd("1. ## Forged")).toBe("1. \\## Forged");
    expect(blockMd("> - ## Forged")).toBe("> - \\## Forged");
  });

  it("stays fast on a very long line of list markers", () => {
    const t0 = performance.now();
    blockMd("- ".repeat(100_000) + "x");
    blockMd("> ".repeat(100_000) + "x");
    expect(performance.now() - t0).toBeLessThan(1000);
  });

  it("leaves list items and dashes inside prose alone", () => {
    expect(blockMd("- item\n- second")).toBe("- item\n- second");
    expect(blockMd("range 1-5\n-x")).toBe("range 1-5\n-x");
    expect(blockMd("> quoted text")).toBe("> quoted text");
  });
});

describe("blockMd escapes a block that would run past the end of the text (#1918)", () => {
  // An unclosed fence or raw-HTML block runs to the end of the document, so every later report
  // section would render as code. Finding text does not need code blocks; inline code spans stay.
  it.each([
    ["x\n```\nfoo", "x\n\\`\\`\\`\nfoo"],
    ["```js", "\\`\\`\\`js"],
    ["  ~~~~", "  \\~\\~\\~\\~"],
    ["- ```", "- \\`\\`\\`"],
    ["> ~~~", "> \\~\\~\\~"],
    ["<pre>", "\\<pre>"],
    ["<SCRIPT src=x>", "\\<SCRIPT src=x>"],
    ["<!-- hide", "\\<!-- hide"],
    ["<![CDATA[", "\\<![CDATA["],
    ["<?php", "\\<?php"],
  ])("escapes %j", (input, expected) => {
    expect(blockMd(input)).toBe(expected);
  });

  it("leaves inline code spans and ordinary tags in prose alone", () => {
    expect(blockMd("ran `whoami` then ``a`b``")).toBe("ran `whoami` then ``a`b``");
    expect(blockMd("the <pre> tag")).toBe("the <pre> tag");
    expect(blockMd("``two only")).toBe("``two only");
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

describe("control characters become visible Control Pictures (#9)", () => {
  it("cellMd maps NUL and other C0 controls, and DEL", () => {
    expect(cellMd("A\u0000B\u0001C\u007FD")).toBe("A␀B␁C␡D");
  });

  it("oneLineMd maps NUL and other C0 controls, and DEL", () => {
    expect(oneLineMd("A\u0000B\u001BC\u007F")).toBe("A␀B␛C␡");
  });

  it("blockMd maps C0 controls but keeps TAB and line structure", () => {
    expect(blockMd("a\u0000b\tc\nd\u0007e")).toBe("a␀b\tc\nd␇e");
  });
});

describe("blockMd treats a lone CR as a line break, as marked does (#9)", () => {
  it("escapes a heading forged after a lone CR", () => {
    expect(blockMd("benign\r## Heading")).toBe("benign\n\\## Heading");
  });

  it("escapes a thematic break forged after a lone CR", () => {
    expect(blockMd("above\r---\rbelow")).toBe("above\n\\---\nbelow");
  });
});
