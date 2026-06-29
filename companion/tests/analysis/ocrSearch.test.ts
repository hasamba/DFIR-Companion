import { describe, it, expect } from "vitest";
import {
  extractOcrText,
  searchOcrIndex,
  isOcrSearchEnabled,
  type OcrIndex,
} from "../../src/analysis/ocrSearch.js";
import type { OcrWord } from "../../src/analysis/ocrRedact.js";

const word = (text: string, confidence = 90): OcrWord => ({
  text,
  bbox: { x: 0, y: 0, w: 10, h: 10 },
  confidence,
});

function indexOf(entries: Array<{ file: string; text: string }>): OcrIndex {
  const idx: OcrIndex = {};
  for (const e of entries) {
    idx[e.file] = { screenshotFile: e.file, text: e.text, ocrAt: "2026-06-29T00:00:00Z", wordCount: e.text.split(" ").length };
  }
  return idx;
}

describe("extractOcrText", () => {
  it("joins legible words and drops low-confidence/empty ones", () => {
    const words = [word("C:\\>"), word("mimikatz.exe", 80), word("garbage", 30), word("  ")];
    expect(extractOcrText(words)).toBe("C:\\> mimikatz.exe");
  });

  it("honours a custom confidence threshold", () => {
    const words = [word("keep", 65), word("drop", 55)];
    expect(extractOcrText(words, 60)).toBe("keep");
  });

  it("returns an empty string when nothing survives", () => {
    expect(extractOcrText([word("x", 10)])).toBe("");
    expect(extractOcrText([])).toBe("");
  });
});

describe("searchOcrIndex", () => {
  const index = indexOf([
    { file: "001.webp", text: "Running mimikatz on the host, mimikatz dumped creds" },
    { file: "002.webp", text: "A clean console with nothing suspicious" },
    { file: "003.webp", text: "found Mimikatz signature once" },
  ]);

  it("matches case-insensitively and ranks by match count", () => {
    const hits = searchOcrIndex(index, "mimikatz");
    expect(hits.map((h) => h.screenshotFile)).toEqual(["001.webp", "003.webp"]);
    expect(hits[0].matchCount).toBe(2);
    expect(hits[1].matchCount).toBe(1);
  });

  it("returns a snippet around the first match", () => {
    const hits = searchOcrIndex(index, "signature", { maxSnippet: 5 });
    expect(hits).toHaveLength(1);
    expect(hits[0].snippet).toContain("signature");
    expect(hits[0].snippet).toContain("…");
  });

  it("returns nothing for a blank query", () => {
    expect(searchOcrIndex(index, "")).toEqual([]);
    expect(searchOcrIndex(index, "   ")).toEqual([]);
  });

  it("returns nothing when there is no match", () => {
    expect(searchOcrIndex(index, "cobaltstrike")).toEqual([]);
  });

  it("tie-breaks equal match counts by filename for stable ordering", () => {
    const idx = indexOf([
      { file: "zzz.webp", text: "alpha" },
      { file: "aaa.webp", text: "alpha" },
    ]);
    expect(searchOcrIndex(idx, "alpha").map((h) => h.screenshotFile)).toEqual(["aaa.webp", "zzz.webp"]);
  });
});

describe("isOcrSearchEnabled", () => {
  it("defaults on when unset", () => {
    expect(isOcrSearchEnabled({})).toBe(true);
  });

  it("is off for the documented off-switches", () => {
    for (const v of ["off", "false", "no", "0", "OFF", " False "]) {
      expect(isOcrSearchEnabled({ DFIR_OCR_SEARCH: v })).toBe(false);
    }
  });

  it("stays on for any other value", () => {
    expect(isOcrSearchEnabled({ DFIR_OCR_SEARCH: "on" })).toBe(true);
    expect(isOcrSearchEnabled({ DFIR_OCR_SEARCH: "1" })).toBe(true);
  });
});
