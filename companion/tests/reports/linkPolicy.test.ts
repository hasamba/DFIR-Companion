import { describe, expect, it } from "vitest";
import { isAbsoluteWebLink } from "../../src/reports/linkPolicy.js";

describe("isAbsoluteWebLink (#2053, #2072)", () => {
  it.each([
    "https://ok.example/",
    "HTTPS://ok.example/x",
    "http://ok.example/",
    "mailto:a@b.c",
    "https:\\\\host\\share",
  ])("accepts %s", (href) => {
    expect(isAbsoluteWebLink(href)).toBe(true);
  });

  it.each([
    "//fileserver/share",
    "\\\\fileserver\\share",
    "/\\evil/x",
    "\\/evil/x",
    "relative/path",
    "#a",
    "",
    "javascript:alert(1)",
    "file://fileserver/share",
    "data:image/png;base64,AAAA",
    "hxxps://a[.]b/",
    " https://x",
    "http://",
  ])("rejects %s", (href) => {
    expect(isAbsoluteWebLink(href)).toBe(false);
  });
});
