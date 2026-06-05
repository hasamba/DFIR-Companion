// Generate the dashboard favicons + apple-touch icon from the master favicon emblem
// (public/DFIR_Companion_favicon.png — the "D + magnifier" mark). The source ships the mark small
// and centred on an opaque light-gray background. We:
//   1. flood-fill that outer background to TRANSPARENT from the image edges. The mark's own light
//      internals (charts, magnifier glass, doc/person icons) are walled off by its dark-blue body,
//      so an edge-seeded fill can't reach them — only the surrounding background clears.
//   2. trim to the mark's bounding box and resize with `fit: cover`, so the mark fills the icon
//      edge-to-edge instead of sitting small on a white square.
// Lanczos keeps the downsample sharp. Re-run after changing the favicon:  npm run icons
import sharp from "sharp";
import { fileURLToPath } from "node:url";

const pub = fileURLToPath(new URL("../../public/", import.meta.url));
const src = pub + "DFIR_Companion_favicon.png";

// Read the source as RGBA, then flood-fill the edge-connected light background to transparent.
const { data, info } = await sharp(src).ensureAlpha().raw().toBuffer({ resolveWithObject: true });
const W = info.width, H = info.height;
const buf = Buffer.from(data); // RGBA (4 channels)
const isBg = (i: number) => buf[i] > 185 && buf[i + 1] > 185 && buf[i + 2] > 185; // near the light-gray bg
const visited = new Uint8Array(W * H);
const stack: number[] = [];
const seed = (x: number, y: number) => { if (x >= 0 && y >= 0 && x < W && y < H) stack.push(y * W + x); };
for (let x = 0; x < W; x++) { seed(x, 0); seed(x, H - 1); }
for (let y = 0; y < H; y++) { seed(0, y); seed(W - 1, y); }
while (stack.length) {
  const p = stack.pop()!;
  if (visited[p]) continue;
  visited[p] = 1;
  if (!isBg(p * 4)) continue;            // reached the emblem body — stop (keeps internal light pixels)
  buf[p * 4 + 3] = 0;                     // clear alpha → transparent
  const x = p % W, y = (p / W) | 0;
  seed(x + 1, y); seed(x - 1, y); seed(x, y + 1); seed(x, y - 1);
}

const emblem = sharp(buf, { raw: { width: W, height: H, channels: 4 } });

const SIZES: Array<{ name: string; size: number }> = [
  { name: "favicon-16.png", size: 16 },
  { name: "favicon-32.png", size: 32 },
  { name: "apple-touch-icon.png", size: 180 },
];

for (const { name, size } of SIZES) {
  await emblem
    .clone()
    .trim({ threshold: 10 })                                    // crop the (now transparent) border to the mark
    .resize(size, size, { fit: "cover", kernel: "lanczos3" })   // fill the canvas edge-to-edge
    .png({ compressionLevel: 9 })
    .toFile(pub + name);
  console.log(`wrote public/${name} (${size}x${size})`);
}
