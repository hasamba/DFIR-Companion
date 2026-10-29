import { describe, expect, it } from "vitest";
import { startCaptureBlockReason } from "../src/captureToggle.js";

// The keyboard shortcut used to set REC with no case selected (#2257): the badge said recording
// was on while every capture returned "select a case".
describe("startCaptureBlockReason", () => {
  it("refuses to start without a case", () => {
    expect(startCaptureBlockReason({ caseId: "" }, true)).toBe("select a case before capturing");
  });

  it("treats a blank case id as no case", () => {
    expect(startCaptureBlockReason({ caseId: "   " }, true)).toBe("select a case before capturing");
  });

  it("names the missing case before the missing site access", () => {
    expect(startCaptureBlockReason({ caseId: "" }, false)).toBe("select a case before capturing");
  });

  it("refuses to start on a site without access", () => {
    expect(startCaptureBlockReason({ caseId: "CASE-1" }, false)).toBe(
      "site access is required; open the extension on this site",
    );
  });

  it("allows starting with a case and site access", () => {
    expect(startCaptureBlockReason({ caseId: "CASE-1" }, true)).toBeUndefined();
  });
});
