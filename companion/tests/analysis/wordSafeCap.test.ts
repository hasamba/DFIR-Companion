import { describe, expect, it } from "vitest";
import { capAtWord } from "../../src/analysis/wordSafeCap.js";

// A shortened title never keeps part of a word: a fragment (half an email or host name) matches no
// anonymiser detector, so it would survive into a redacted export.

describe("capAtWord", () => {
  it("returns a title within the cap unchanged (trimmed)", () => {
    expect(capAtWord("  short title  ", 20)).toBe("short title");
  });

  it("drops a word the cap would split and ends on the ellipsis", () => {
    expect(capAtWord("login by alice@example.invalid from host", 20)).toBe("login by…");
  });

  it("keeps a whole word that ends exactly at the cap", () => {
    expect(capAtWord("alpha beta gamma", 11)).toBe("alpha beta…");
  });

  it("keeps only the ellipsis when the first word alone exceeds the cap", () => {
    expect(capAtWord("averyveryverylongusername@example.invalid did it", 10)).toBe("…");
    expect(capAtWord("averyveryverylongusername@example.invalid", 10)).toBe("…");
  });

  it("never exceeds the cap", () => {
    for (const text of ["a bb ccc dddd eeeee", "x".repeat(50), "word ".repeat(20)]) {
      for (let max = 1; max < 30; max++) expect(capAtWord(text, max).length).toBeLessThanOrEqual(max);
    }
  });
});
