import { describe, it, expect } from "vitest";
import sharp from "sharp";
import { computeHash, hammingDistance, isDuplicate } from "../../src/dedup/perceptualHash.js";

async function solidImage(r: number, g: number, b: number) {
  return sharp({
    create: { width: 64, height: 64, channels: 3, background: { r, g, b } },
  }).png().toBuffer();
}

describe("perceptualHash", () => {
  it("computeHash returns a 16-char hex string", async () => {
    const hash = await computeHash(await solidImage(120, 120, 120));
    expect(hash).toMatch(/^[0-9a-f]{16}$/);
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

    // A half-black/half-white image differs strongly from a flat gray image.
    const split = await sharp({
      create: { width: 64, height: 64, channels: 3, background: { r: 0, g: 0, b: 0 } },
    })
      .composite([{
        input: { create: { width: 64, height: 32, channels: 3, background: { r: 255, g: 255, b: 255 } } },
        top: 0, left: 0,
      }])
      .png().toBuffer();
    const splitHash = await computeHash(split);
    expect(isDuplicate(grayHash, splitHash, 5)).toBe(false);
  });

  it("hammingDistance throws on mismatched lengths", () => {
    expect(() => hammingDistance("ff", "ffff")).toThrow();
  });
});
