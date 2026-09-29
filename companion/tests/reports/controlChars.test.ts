import { describe, expect, it } from "vitest";
import { xmlSafeText } from "../../src/reports/controlChars.js";

// Characters XML 1.0 forbids in a document. A single one makes word/document.xml unparseable.
const XML_FORBIDDEN =
  /[\u0000-\u0008\u000B\u000C\u000E-\u001F￾￿]|[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

describe("xmlSafeText", () => {
  it("maps each forbidden C0 control to its visible Control Picture", () => {
    expect(xmlSafeText("A\u0000B\u0001C\u0008D\u000BE\u000CF\u000EG\u001FH")).toBe("A␀B␁C␈D␋E␌F␎G␟H");
  });

  it("keeps TAB, LF and CR, which XML allows and Markdown needs", () => {
    expect(xmlSafeText("a\tb\nc\rd")).toBe("a\tb\nc\rd");
  });

  it("maps U+FFFE, U+FFFF and lone surrogates to U+FFFD", () => {
    expect(xmlSafeText("x￾y￿z\uD800w\uDC00v")).toBe("x�y�z�w�v");
  });

  it("keeps a valid surrogate pair (an astral character) intact", () => {
    expect(xmlSafeText("emoji 😀 ok")).toBe("emoji 😀 ok");
  });

  it("leaves no XML-forbidden character behind", () => {
    let all = "";
    for (let c = 0; c < 0x20; c++) all += String.fromCharCode(c);
    all += "￾￿𐏿";
    expect(XML_FORBIDDEN.test(xmlSafeText(all))).toBe(false);
  });
});
