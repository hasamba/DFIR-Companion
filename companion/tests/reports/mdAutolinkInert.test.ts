import { describe, expect, it } from "vitest";
import { Marked } from "marked";
import { escapeHtmlMd, proseLineMd } from "../../src/reports/mdInline.js";
import { blockMd, cellMd, oneLineMd } from "../../src/reports/mdText.js";

// A GFM bare-URL autolink runs to the next whitespace or `<`, so it swallowed the backslash of an
// escape right after the URL and left the escaped character live. Judged by rendering through marked.

const TAG = "<img src=x onerror=y>";
const URLS = [
  "https://x.example",
  "http://x.example/p",
  "ftp://x.example",
  "www.x.example",
  "HTTPS://X.example",
];

function html(md: string): string {
  return new Marked({ gfm: true }).parse(md, { async: false });
}

function expectInert(md: string): void {
  expect(html(md)).not.toMatch(/<img/i);
}

/** The visible text marked renders, tags stripped and entities decoded. */
function visible(md: string): string {
  return html(md)
    .replace(/<[^>]+>/g, "")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&amp;/g, "&")
    .trim();
}

describe("bare URL directly before escaped HTML", () => {
  for (const url of URLS) {
    it(`escapeHtmlMd keeps ${url}<tag> inert`, () => {
      expectInert(escapeHtmlMd(url + TAG));
      expect(visible(escapeHtmlMd(url + TAG))).toBe(url + TAG);
    });
  }

  it("a URL whose host holds a second trigger is inert too", () => {
    expectInert(escapeHtmlMd("https://www.x.example" + TAG));
  });

  it("the line, block and cell helpers keep it inert", () => {
    expectInert(oneLineMd("see https://x.example" + TAG));
    expectInert(blockMd("see https://x.example" + TAG));
    expectInert(`| a |\n| - |\n| ${cellMd("https://x.example" + TAG)} |`);
  });

  it("a control character between the URL and the tag cannot join them", () => {
    for (const ws of ["\t", "\v", "\f"]) {
      const v = "https://x.example" + ws + TAG;
      expectInert(`| a |\n| - |\n| ${cellMd(v)} |`);
      expectInert(oneLineMd(v));
      expectInert(blockMd(v));
    }
  });

  it("a bare URL running into a code span keeps the span literal", () => {
    const md = proseLineMd("https://x.example/`" + TAG + "`");
    expectInert(md);
    expect(html(md)).toContain("<code>&lt;img src=x onerror=y&gt;</code>");
  });

  it("leaves a URL followed by whitespace untouched, and code spans literal", () => {
    expect(escapeHtmlMd("https://x.example <b>")).toBe("https://x.example \\<b\\>");
    expect(proseLineMd("go https://x.example `a<b`")).toBe("go https://x.example `a<b`");
  });

  it("does not escape twice", () => {
    const once = escapeHtmlMd("https://x.example" + TAG);
    expect(visible(once)).toBe("https://x.example" + TAG);
    expect(once.match(/\\:/g)).toHaveLength(1);
  });
});
