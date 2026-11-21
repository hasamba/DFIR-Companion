import { describe, expect, it } from "vitest";
import { constants } from "node:buffer";
import {
  DROP_WHOLE_READ_SAFE_BYTES,
  dropOversizeReason,
  dropWholeReadCeiling,
  dropWholeReadLimitNote,
} from "../../src/analysis/dropScan.js";

// #2813 — a drop file under DFIR_DROP_MAX_BYTES is read whole into one string, and the engine cannot
// build a string past constants.MAX_STRING_LENGTH (about 512 MB). Raising the cap above that made
// every file in between fail with the engine's own error. The whole-read ceiling is now the smaller
// of the cap and a safe limit, so a bigger file takes the streamed path or a clear refusal.

const MB = 1024 * 1024;

describe("drop whole-read ceiling (#2813)", () => {
  it("derives the safe limit from the engine's string limit, in bytes, with headroom", () => {
    expect(Number.isSafeInteger(DROP_WHOLE_READ_SAFE_BYTES)).toBe(true);
    expect(DROP_WHOLE_READ_SAFE_BYTES).toBeGreaterThan(0);
    expect(DROP_WHOLE_READ_SAFE_BYTES).toBeLessThan(constants.MAX_STRING_LENGTH);
    // Headroom, but not so much that the default 200 MB cap is ever lowered.
    expect(DROP_WHOLE_READ_SAFE_BYTES).toBeGreaterThan(200 * MB);
  });

  it("keeps a cap below the safe limit as it is", () => {
    expect(dropWholeReadCeiling(200 * MB)).toBe(200 * MB);
    expect(dropWholeReadCeiling(4096, 8192)).toBe(4096);
  });

  it("lowers a cap above the safe limit to the safe limit", () => {
    expect(dropWholeReadCeiling(4_000_000_000)).toBe(DROP_WHOLE_READ_SAFE_BYTES);
    expect(dropWholeReadCeiling(4096, 1024)).toBe(1024);
  });

  it("a file between the safe limit and a raised cap is over the ceiling (takes the streamed path)", () => {
    const fileBytes = 723 * MB;
    const ceiling = dropWholeReadCeiling(4_000_000_000);
    expect(fileBytes).toBeGreaterThan(ceiling);
  });
});

describe("drop oversize wording (#2813)", () => {
  it("under a configured cap keeps today's sentence", () => {
    expect(dropOversizeReason(300 * MB, 200 * MB)).toBe(
      "too large (300 MB > 200 MB cap) — use Import-from-path",
    );
    expect(dropWholeReadLimitNote(200 * MB)).toBe("");
  });

  it("at the safe limit says raising the setting does not help, never the engine's error", () => {
    const reason = dropOversizeReason(2048, 1024, 1024);
    expect(reason).toMatch(/DFIR_DROP_MAX_BYTES does not lift it/);
    expect(reason).toMatch(/stream/);
    expect(reason).not.toMatch(/Import-from-path/);
    expect(reason).not.toMatch(/0x1fffffe8|Cannot create a string/);
    expect(dropWholeReadLimitNote(1024, 1024)).toMatch(/DFIR_DROP_MAX_BYTES does not lift it/);
  });
});
