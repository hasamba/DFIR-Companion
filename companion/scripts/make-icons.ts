// Generate the dashboard favicons + apple-touch icon from the master favicon emblem
// (public/DFIR_Companion_favicon.png — the "D + magnifier" mark on transparency). It is already
// square and wordmark-free, so we just Lanczos-downsample to each size (no crop). `contain` keeps
// the whole mark even if a future source isn't perfectly square. Re-run after changing the
// favicon:  npm run icons
import sharp from "sharp";
import { fileURLToPath } from "node:url";

const pub = fileURLToPath(new URL("../../public/", import.meta.url));
const src = pub + "DFIR_Companion_favicon.png";

const SIZES: Array<{ name: string; size: number }> = [
  { name: "favicon-16.png", size: 16 },
  { name: "favicon-32.png", size: 32 },
  { name: "apple-touch-icon.png", size: 180 },
];

for (const { name, size } of SIZES) {
  await sharp(src)
    .resize(size, size, { fit: "contain", background: { r: 0, g: 0, b: 0, alpha: 0 }, kernel: "lanczos3" })
    .png({ compressionLevel: 9 })
    .toFile(pub + name);
  console.log(`wrote public/${name} (${size}x${size})`);
}
