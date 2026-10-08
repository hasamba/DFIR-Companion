import { describe, expect, it } from "vitest";
import { csvNulPicture, mdControlPictures, xmlSafeText } from "../../src/reports/controlChars.js";

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

// A finding title carrying the raw U+202E of an RLO-masqueraded file name reverses the rest of the
// line in every Markdown viewer, spreadsheet and Word document (#2027). Each report seam shows it.
describe("bidi controls at the report seams", () => {
  const title = "Payload (\u202ecod.3aka3.scr) on SCRANTON";
  const shown = "Payload (<RLO>cod.3aka3.scr) on SCRANTON";

  it("Markdown, CSV and DOCX text show a bidi control as a visible marker", () => {
    expect(mdControlPictures(title)).toBe("Payload (‹RLO›cod.3aka3.scr) on SCRANTON");
    expect(csvNulPicture(title)).toBe(shown);
    expect(xmlSafeText(title)).toBe(shown);
  });

  // `<RLO>` is an HTML tag to a Markdown renderer, so GitHub and other viewers hid the marker, and a
  // path's own backslash ("victim\<RLO>") escaped the bracket instead. ‹ › mean nothing to Markdown.
  it("Markdown uses a marker no renderer reads as HTML, even after a path backslash", () => {
    const md = mdControlPictures("C:\\victim\\\u202ecod.3aka3.scr");
    expect(md).toBe("C:\\victim\\\u2039RLO\u203acod.3aka3.scr");
    expect(md).not.toMatch(/[<>]/);
  });
});
