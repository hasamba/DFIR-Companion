// Generate the dashboard favicons + apple-touch icon from the master logo. We crop to the
// "D + magnifier" emblem (dropping the "DFIR COMPANION" wordmark, which turns to mush at icon
// sizes) and downsample with Lanczos so the small icons stay razor-sharp. Re-run after changing
// the logo:  npm run icons
import sharp from "sharp";
import { fileURLToPath } from "node:url";

const pub = fileURLToPath(new URL("../../public/", import.meta.url));
const src = pub + "dfir-companion-logo.jpg";

const meta = await sharp(src).metadata();
const W = meta.width!, H = meta.height!;

// Square crop over the emblem (fractions of the 1:1 master), tuned to exclude the wordmark.
const CROP = { left: 0.24, top: 0.12, side: 0.50 };
const region = {
  left: Math.round(CROP.left * W), top: Math.round(CROP.top * H),
  width: Math.round(CROP.side * W), height: Math.round(CROP.side * H),
};

const SIZES: Array<{ name: string; size: number }> = [
  { name: "favicon-16.png", size: 16 },
  { name: "favicon-32.png", size: 32 },
  { name: "apple-touch-icon.png", size: 180 },
];

for (const { name, size } of SIZES) {
  await sharp(src)
    .extract(region)
    .resize(size, size, { fit: "cover", kernel: "lanczos3" })
    .png({ compressionLevel: 9 })
    .toFile(pub + name);
  console.log(`wrote public/${name} (${size}x${size})`);
}
