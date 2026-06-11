import sharp from "sharp";

// Perceptual hash used to skip re-analyzing a screenshot that is essentially the same frame
// as the one before it (e.g. a timer firing on a static screen). For forensic evidence the
// failure that matters is a FALSE duplicate — dropping a genuinely different screenshot — so
// the hash must be discriminating enough to tell apart two pages that share the same UI chrome
// (toolbar, table header, columns) but show different rows/text. A DFIR analyst paging through
// a log table is the common case.
//
// We use a 16x16 **difference hash (dHash)** computed in BOTH directions → 512 bits:
//   - horizontal: each cell vs its right neighbour  (captures where text starts/ends in a row)
//   - vertical:   each cell vs the cell below       (captures which ROWS carry content)
// dHash keys on *local* brightness gradients rather than a single global average, so it is
// stable for a true re-capture (≈0 distance, immune to a slight brightness shift) yet sensitive
// to content. Doing it in both directions matters: a horizontal-only dHash is blind to a page
// that differs only in which rows have text — exactly the log-table case. A low-resolution
// average-hash (the previous 8x8 implementation) collapsed the whole message region into a few
// cells that landed identically no matter what text they held, which is why dense text/log
// screenshots used to be wrongly flagged as duplicates.
const GRID = 16; // 16x16 per direction → 2 * 256 = 512 bits = 128 hex chars.

export async function computeHash(image: Buffer): Promise<string> {
  const base = sharp(image).greyscale(); // single-channel; resize fit:"fill" maps the whole frame

  // Horizontal: (GRID+1) x GRID, compare each pixel to its right neighbour.
  const h = await base.clone().resize(GRID + 1, GRID, { fit: "fill" }).raw().toBuffer({ resolveWithObject: true });
  // Vertical: GRID x (GRID+1), compare each pixel to the one below it.
  const v = await base.clone().resize(GRID, GRID + 1, { fit: "fill" }).raw().toBuffer({ resolveWithObject: true });

  const hch = h.info.channels; // 1 for greyscale, read defensively in case of RGB(A)
  const vch = v.info.channels;
  const hl = (x: number, y: number): number => h.data[(y * (GRID + 1) + x) * hch];
  const vl = (x: number, y: number): number => v.data[(y * GRID + x) * vch];

  let bits = "";
  for (let y = 0; y < GRID; y++) {
    for (let x = 0; x < GRID; x++) bits += hl(x, y) < hl(x + 1, y) ? "1" : "0";
  }
  for (let y = 0; y < GRID; y++) {
    for (let x = 0; x < GRID; x++) bits += vl(x, y) < vl(x, y + 1) ? "1" : "0";
  }

  let hex = "";
  for (let i = 0; i < bits.length; i += 4) {
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
