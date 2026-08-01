import { describe, expect, it } from "vitest";
import { announcementText, isAssertive } from "../../../public/js/a11y/announcer.js";

describe("isAssertive", () => {
  it("interrupts for failures, which must not wait behind routine progress", () => {
    expect(isAssertive("second opinion error: timed out")).toBe(true);
    expect(isAssertive("Correlation profile save failed")).toBe(true);
    expect(isAssertive("Unable to reach the provider")).toBe(true);
    expect(isAssertive("connect to a case first")).toBe(false);
  });

  it("waits politely for ordinary progress", () => {
    expect(isAssertive("running second opinion…")).toBe(false);
    expect(isAssertive("Correlation profile saved")).toBe(false);
  });

  it("does not fire on a substring inside a longer word", () => {
    // "unerroring" and "classified" must not be read as failures.
    expect(isAssertive("unerroring progress")).toBe(false);
  });
});

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
