import { describe, expect, it } from "vitest";
import { Marked } from "marked";
import { blockMd, cellMd, oneLineMd } from "../../src/reports/mdText.js";
import { breakLinkSyntaxMd } from "../../src/reports/mdInline.js";

// An image written in case data must never load when the Markdown report is opened: a remote image
// is a tracking beacon (it tells the attacker who opened the report, when, and from where). The
// http(s)/mailto allow-list keeps plain TEXT links live, but an `![` opener breaks the `](` after
// it whatever the scheme. Judged by rendering through marked, a CommonMark reader.

function html(md: string): string {
  return new Marked({ gfm: true }).parse(md, { async: false });
}

const HELPERS = { blockMd, cellMd, oneLineMd };

describe("images from case data stay inert in the Markdown report", () => {
  it.each([
    "![x](https://attacker.invalid/beacon.png)",
    "![x](http://attacker.invalid/b.gif)",
    "![](https://attacker.invalid/b.gif)",
    '![x](https://attacker.invalid/b.gif "title")',
    "![a [nested] label](https://attacker.invalid/b.gif)",
    "see ![x](mailto:a@example.invalid) here",
    "[![x](https://attacker.invalid/b.gif)](https://example.invalid/page)",
  ])("%s renders no <img>", (input) => {
    for (const [name, fn] of Object.entries(HELPERS)) {
      const out = html(fn(input));
      expect(out, name).not.toMatch(/<img/i);
    }
  });

  it("breaks the image's `](` while the plain link around it stays live", () => {
    const out = blockMd("[![x](https://a.invalid/b.gif)](https://example.invalid/page)");
    expect(out).toBe("[![x]\\(https://a.invalid/b.gif)](https://example.invalid/page)");
    expect(html(out)).toMatch(/<a href="https:\/\/example\.invalid\/page"/);
  });

  it("keeps plain http(s) and mailto text links live, as today", () => {
    const md = "[w](https://example.invalid/x) and [m](mailto:soc@example.invalid)";
    expect(blockMd(md)).toBe(md);
    expect(html(blockMd(md))).toMatch(/<a href="https:\/\/example\.invalid\/x"/);
  });

  it("does not treat an escaped bang or bracket as an image opener", () => {
    expect(breakLinkSyntaxMd("\\![w](https://example.invalid/x)")).toBe("\\![w](https://example.invalid/x)");
    expect(breakLinkSyntaxMd("!\\[w](https://example.invalid/x)")).toBe("!\\[w](https://example.invalid/x)");
  });

  it("leaves an image opener closed before a non-link alone, and a later text link live", () => {
    const md = "![a] then [w](https://example.invalid/x)";
    expect(breakLinkSyntaxMd(md)).toBe(md);
  });

  it("is idempotent", () => {
    const once = breakLinkSyntaxMd("![x](https://a.invalid/b.gif) [w](https://example.invalid/x)");
    expect(breakLinkSyntaxMd(once)).toBe(once);
  });
});
