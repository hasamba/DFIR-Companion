import { describe, it, expect } from "vitest";
import { withRetry } from "../../src/analysis/ai/retry.js";
import { OcrRedactionError } from "../../src/analysis/ocrRedact.js";

// #1952: an OCR failure on a screenshot repeats on the same bytes, so retrying it only delays the
// error the analyst needs to see.

describe("retry policy — OCR redaction failure", () => {
  it("does not retry an OcrRedactionError", async () => {
    let calls = 0;
    const run = withRetry(
      async () => {
        calls += 1;
        throw new OcrRedactionError(1, "tesseract crashed");
      },
      3,
      1,
    );
    await expect(run).rejects.toBeInstanceOf(OcrRedactionError);
    expect(calls, "an OCR failure must stop on the first throw").toBe(1);
  });
});
