import { describe, it, expect } from "vitest";
import { SubstringIndex } from "../../src/analysis/substringIndex.js";

function bruteForce(patterns: string[], text: string): string[] {
  const out: string[] = [];
  patterns.forEach((p, idx) => {
    if (!p) return;
    for (let at = text.indexOf(p); at >= 0; at = text.indexOf(p, at + 1)) out.push(`${idx}@${at}`);
  });
  return out.sort();
}

function indexed(patterns: string[], text: string): string[] {
  const out: string[] = [];
  new SubstringIndex(patterns).forEachMatch(text, (p, start) => out.push(`${p}@${start}`));
  return out.sort();
}

describe("SubstringIndex", () => {
  it("reports overlapping, nested and repeated occurrences", () => {
    const patterns = ["he", "she", "his", "hers", "e", "", "she"];
    expect(indexed(patterns, "ushers shehis")).toEqual(bruteForce(patterns, "ushers shehis"));
  });

  it("matches a brute-force scan on random small-alphabet input", () => {
    let seed = 7;
    const rand = (n: number) => (seed = (seed * 1103515245 + 12345) % 2147483648) % n;
    const word = (len: number) => Array.from({ length: len }, () => "ab.1"[rand(4)]).join("");
    for (let round = 0; round < 200; round++) {
      const patterns = Array.from({ length: 1 + rand(8) }, () => word(1 + rand(5)));
      const text = word(rand(60));
      expect(indexed(patterns, text)).toEqual(bruteForce(patterns, text));
    }
  });

  it("finds nothing with no patterns, and handles non-ASCII text", () => {
    expect(indexed([], "anything")).toEqual([]);
    expect(indexed(["ü.exe"], "run c:\\tmp\\ü.exe now")).toEqual(["0@11"]);
  });
});
