import { describe, it, expect } from "vitest";
import sharp from "sharp";
import { computeHash, hammingDistance, isDuplicate } from "../../src/dedup/perceptualHash.js";
import { DEFAULT_DUP_THRESHOLD } from "../../src/ingest/captureIngest.js";

async function solidImage(r: number, g: number, b: number) {
  return sharp({
    create: { width: 320, height: 320, channels: 3, background: { r, g, b } },
  }).png().toBuffer();
}

// A dark "screenshot" with light horizontal bars at the given y positions — a stand-in for a
// log/table page: identical UI chrome (dark background), different rows of content. This is the
// exact shape that an 8x8 average-hash wrongly collapsed into a single duplicate.
async function pageWithRows(rows: number[]): Promise<Buffer> {
  const W = 320, H = 320;
  return sharp({ create: { width: W, height: H, channels: 3, background: { r: 18, g: 20, b: 26 } } })
    .composite(rows.map((y) => ({
      input: { create: { width: W, height: 10, channels: 3, background: { r: 220, g: 220, b: 220 } } },
      top: y, left: 0,
    })))
    .png()
    .toBuffer();
}

describe("perceptualHash", () => {
  it("computeHash returns a 128-char hex string (512-bit dual dHash)", async () => {
    const hash = await computeHash(await solidImage(120, 120, 120));
    expect(hash).toMatch(/^[0-9a-f]{128}$/);
  });

  it("identical images have hamming distance 0", async () => {
    const img = await solidImage(80, 80, 80);
    const a = await computeHash(img);
    const b = await computeHash(img);
    expect(hammingDistance(a, b)).toBe(0);
  });

  it("isDuplicate is true for identical, false for clearly different", async () => {
    const grayHash = await computeHash(await solidImage(128, 128, 128));
    const sameHash = await computeHash(await solidImage(128, 128, 128));
    expect(isDuplicate(grayHash, sameHash, 5)).toBe(true);

    const split = await sharp({
      create: { width: 320, height: 320, channels: 3, background: { r: 0, g: 0, b: 0 } },
    })
      .composite([{
        input: { create: { width: 320, height: 160, channels: 3, background: { r: 255, g: 255, b: 255 } } },
        top: 0, left: 0,
      }])
      .png().toBuffer();
    const splitHash = await computeHash(split);
    expect(isDuplicate(grayHash, splitHash, 5)).toBe(false);
  });

  // Regression for the false-duplicate bug: two pages with the SAME chrome but DIFFERENT rows
  // of content must NOT be flagged as duplicates at the default threshold, while a re-capture
  // of the same page must be (distance 0).
  it("distinguishes pages that share chrome but show different content rows", async () => {
    const pageA = await computeHash(await pageWithRows([20, 60, 100, 140, 180]));
    const pageAagain = await computeHash(await pageWithRows([20, 60, 100, 140, 180]));
    const pageB = await computeHash(await pageWithRows([35, 75, 115, 205, 250, 290]));

    // Same page recaptured → identical.
    expect(hammingDistance(pageA, pageAagain)).toBe(0);
    expect(isDuplicate(pageA, pageAagain, DEFAULT_DUP_THRESHOLD)).toBe(true);

    // Different content rows → well beyond the default threshold (the old 8x8 hash failed here).
    expect(hammingDistance(pageA, pageB)).toBeGreaterThan(DEFAULT_DUP_THRESHOLD);
    expect(isDuplicate(pageA, pageB, DEFAULT_DUP_THRESHOLD)).toBe(false);
  });

  it("hammingDistance throws on mismatched lengths", () => {
    expect(() => hammingDistance("ff", "ffff")).toThrow();
  });
});
