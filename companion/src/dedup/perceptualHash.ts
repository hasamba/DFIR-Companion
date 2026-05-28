import sharp from "sharp";

// Average-hash: 8x8 grayscale, threshold against mean -> 64-bit hash (16 hex chars).
export async function computeHash(image: Buffer): Promise<string> {
  const { data } = await sharp(image)
    .greyscale()
    .resize(8, 8, { fit: "fill" })
    .raw()
    .toBuffer({ resolveWithObject: true });

  const pixels = Array.from(data.subarray(0, 64));
  const mean = pixels.reduce((sum, v) => sum + v, 0) / pixels.length;

  let bits = "";
  for (const v of pixels) bits += v >= mean ? "1" : "0";

  let hex = "";
  for (let i = 0; i < 64; i += 4) {
    hex += parseInt(bits.slice(i, i + 4), 2).toString(16);
  }
  return hex;
}

export function hammingDistance(a: string, b: string): number {
  if (a.length !== b.length) {
    throw new Error(`hash length mismatch: ${a.length} vs ${b.length}`);
  }
  let distance = 0;
  for (let i = 0; i < a.length; i++) {
    let nibble = parseInt(a[i], 16) ^ parseInt(b[i], 16);
    while (nibble) {
      distance += nibble & 1;
      nibble >>= 1;
    }
  }
  return distance;
}

export function isDuplicate(a: string, b: string, threshold: number): boolean {
  return hammingDistance(a, b) <= threshold;
}
