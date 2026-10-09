import { describe, it, expect } from "vitest";
import { deepPassFallbackNote } from "../../src/routes/deepPass.js";

// #2076: the job warning and activity-log line name the batches another model read, so a deep
// pass whose reads fell back after a safety stop is not credited to the configured model.
describe("deepPassFallbackNote (#2076)", () => {
  it("names the count and the fallback model", () => {
    expect(deepPassFallbackNote({ batchesOnFallback: 2, fallbackModel: "gpt-6-sol" })).toBe(
      "2 batch(es) read by the fallback model gpt-6-sol after a safety stop",
    );
  });

  it("says nothing when the fallback read nothing", () => {
    expect(deepPassFallbackNote({ batchesOnFallback: 0 })).toBe("");
    expect(deepPassFallbackNote({})).toBe("");
  });
});
