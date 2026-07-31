import { describe, expect, it } from "vitest";
import { announcementText } from "../../../public/js/a11y/announcer.js";

describe("announcementText", () => {
  it("prefixes job updates", () => {
    expect(announcementText("job", "Import finished")).toBe("Job: Import finished");
  });

  it("prefixes errors", () => {
    expect(announcementText("error", "Upload failed")).toBe("Error: Upload failed");
  });

  it("prefixes AI updates", () => {
    expect(announcementText("ai", "Synthesis complete")).toBe("AI: Synthesis complete");
  });

  it("collapses whitespace so screen readers do not read ragged text", () => {
    expect(announcementText("job", "Import   finished\n\nnow")).toBe("Job: Import finished now");
  });

  it("returns an empty string for empty detail, so nothing is announced", () => {
    expect(announcementText("job", "   ")).toBe("");
  });
});
