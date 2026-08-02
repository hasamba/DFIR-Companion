import { describe, it, expect } from "vitest";
import sharp from "sharp";

/**
 * sharp / libvips version floor (#423).
 *
 * GHSA-f88m-g3jw-g9cj marks every sharp below 0.35.0 as affected by inherited libvips
 * vulnerabilities, two of them high severity. This matters here more than it does for a typical
 * consumer: DFIR Companion decodes UNTRUSTED evidence with sharp — capture ingest accepts GIF,
 * PNG, JPEG and WebP, and both screenshot redaction (imageRedact) and OCR composition (ocrRedact)
 * push those bytes through the native decoder.
 *
 * A version assertion is a weak test in general, but it is the right shape for this one: it can
 * only fail on a downgrade, and a downgrade is exactly the regression worth catching. The
 * lockfile can be edited by a resolution, a merge, or a well-meaning "revert the dependency bump".
 */
function parse(version: string): [number, number, number] {
  const [major, minor, patch] = version.split("-")[0].split(".").map(Number);
  return [major, minor, patch];
}

function atLeast(actual: string, floor: string): boolean {
  const a = parse(actual);
  const f = parse(floor);
  for (let i = 0; i < 3; i++) {
    if (a[i] !== f[i]) return a[i] > f[i];
  }
  return true;
}

describe("sharp is past the vulnerable libvips releases", () => {
  it("resolves sharp 0.35.0 or newer", () => {
    expect(atLeast(sharp.versions.sharp, "0.35.0")).toBe(true);
  });

  it("ships a libvips at or past 8.17", () => {
    // sharp 0.35's prebuilt binaries carry libvips 8.18.x; 8.17 is the floor that leaves room for
    // a legitimate prebuilt variation without letting an 8.15-era binary back in.
    expect(atLeast(sharp.versions.vips, "8.17.0")).toBe(true);
  });

  it("still decodes each format capture ingest accepts", async () => {
    // The upgrade is only useful if the decoders the ingest path advertises still work. A 1x1 of
    // each, round-tripped through the same sharp() entry point imageRedact uses.
    const source = sharp({ create: { width: 4, height: 4, channels: 3, background: "#204060" } });
    for (const format of ["png", "jpeg", "gif", "webp"] as const) {
      const encoded = await source.clone().toFormat(format).toBuffer();
      const meta = await sharp(encoded).metadata();
      expect(meta.format).toBe(format);
      expect(meta.width).toBe(4);
    }
  });
});
