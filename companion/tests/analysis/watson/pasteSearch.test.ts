import { describe, expect, it } from "vitest";
import {
  pasteHead,
  searchPaste,
  WATSON_PASTE_MAX_BYTES,
} from "../../../src/analysis/ai/watson/pasteSearch.js";

describe("searchPaste", () => {
  it("never returns more than maxLines and reports truncation", () => {
    const big = Array.from({ length: 500_000 }, (_, i) => `row ${i} upd.exe`).join("\n");
    const r = searchPaste(big, ["upd.exe"]);
    expect(r.excerpt.split("\n").length).toBeLessThanOrEqual(200);
    expect(r.truncated).toBe(true);
    expect(r.matchedLines).toBe(500_000);
  });
  it("treats regex metacharacters literally", () => {
    expect(searchPaste("a.b\naxb", ["a.b"]).matchedLines).toBe(1);
  });
  it("prefixes line numbers and includes one line of context", () => {
    expect(searchPaste("x\nHIT\ny", ["hit"]).excerpt).toBe("1: x\n2: HIT\n3: y");
  });
  it("does not duplicate overlapping context", () => {
    const r = searchPaste("a\nhit\nhit\nb\nc", ["hit"]);
    expect(r.excerpt).toBe("1: a\n2: hit\n3: hit\n4: b");
    expect(r.truncated).toBe(false);
  });
  it("matches any of several terms and honors context 0", () => {
    const r = searchPaste("a\nfoo\nb\nBAR\nc", ["foo", "bar"], { context: 0 });
    expect(r.excerpt).toBe("2: foo\n4: BAR");
    expect(r.matchedLines).toBe(2);
  });
  it("returns empty for no terms or no match", () => {
    expect(searchPaste("abc", [])).toEqual({ excerpt: "", matchedLines: 0, truncated: false });
    expect(searchPaste("abc", ["zzz"]).matchedLines).toBe(0);
  });
  it("caps the excerpt at 24000 chars", () => {
    const text = Array.from({ length: 100 }, () => `hit ${"x".repeat(1000)}`).join("\n");
    const r = searchPaste(text, ["hit"], { maxLines: 200 });
    expect(r.excerpt.length).toBeLessThanOrEqual(24000);
    expect(r.truncated).toBe(true);
    expect(r.matchedLines).toBe(100);
  });
  it("clips an over-long matching line and still returns later matches", () => {
    const text = `hit ${"x".repeat(30000)}\nhit one\nhit two`;
    const r = searchPaste(text, ["hit"], { context: 0 });
    const lines = r.excerpt.split("\n");
    expect(lines).toHaveLength(3);
    expect(lines[0]!.endsWith(" …[clipped]")).toBe(true);
    expect(lines[0]!.length).toBeLessThan(2100);
    expect(lines[1]).toBe("2: hit one");
    expect(lines[2]).toBe("3: hit two");
    expect(r.truncated).toBe(true);
  });
  it("strips carriage returns", () => {
    const r = searchPaste("x\r\nHIT\r\ny\r\n", ["hit"]);
    expect(r.excerpt).toBe("1: x\n2: HIT\n3: y");
  });
  it("adds no phantom line after a trailing newline", () => {
    expect(searchPaste("a\nhit\n", ["hit"]).excerpt).toBe("1: a\n2: hit");
  });
  it("matches nothing for a whitespace-only term and trims terms", () => {
    expect(searchPaste("a b\nc", ["  "]).matchedLines).toBe(0);
    expect(searchPaste("a b\nc", [" c "]).matchedLines).toBe(1);
  });
  it("supports context = 2", () => {
    const r = searchPaste("1\n2\n3\nhit\n5\n6\n7", ["hit"], { context: 2 });
    expect(r.excerpt).toBe("2: 2\n3: 3\n4: hit\n5: 5\n6: 6");
  });
});

describe("pasteHead", () => {
  it("returns numbered whole lines within maxChars", () => {
    expect(pasteHead("aaa\nbbb\nccc", 14)).toBe("1: aaa\n2: bbb");
    expect(pasteHead("short")).toBe("1: short");
  });
  it("strips CR and adds no phantom line", () => {
    expect(pasteHead("a\r\nb\r\n")).toBe("1: a\n2: b");
  });
  it("cuts a single over-long line", () => {
    expect(pasteHead("x".repeat(100), 10)).toBe(`1: ${"x".repeat(7)}`);
  });
  it("exports the 50 MB cap", () => {
    expect(WATSON_PASTE_MAX_BYTES).toBe(52_428_800);
  });
});
