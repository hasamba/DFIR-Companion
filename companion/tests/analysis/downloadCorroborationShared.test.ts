import { describe, it, expect } from "vitest";
import { neutral } from "../../src/analysis/downloadCorroborationShared.js";

// #1200: the control-character strip inside neutral() was once written with literal raw control
// bytes in the source file, which made git treat the whole file as binary (no diff hunks, no
// blame). It also covered code points \u007f-\u00c2 rather than the intended \u007f-\u009f (DEL +
// C1 controls), which would have stripped legitimate accented Latin-1 letters.
describe("neutral", () => {
  it("strips C0/C1 control characters", () => {
    expect(neutral("a\u0000b\u001fc\u007fd\u009fe")).toBe("a b c d e");
  });

  it("does not strip accented Latin-1 letters just past the DEL/C1 range", () => {
    const s = "caf\u00e9 \u00c0\u00c1\u00c2";
    expect(neutral(s)).toBe(s);
  });

  it("turns brackets into parentheses", () => {
    expect(neutral("[foo]")).toBe("(foo)");
  });
});
