/**
 * Visual smoke test for the OCR screenshot anonymization (PR #41 / issue #19).
 *
 * Runs the REAL Tesseract.js OCR runner + ocrRedactImage over an image and writes the
 * before/after PNGs so you can eyeball the black redaction boxes. The unit tests mock the
 * OCR runner; this exercises the actual WASM path end-to-end.
 *
 * Usage (from companion/):
 *   npm run ocr:demo                 # generates a synthetic screenshot with known entities
 *   npm run ocr:demo -- path\to\screenshot.png   # redact a real screenshot instead
 *
 * Output goes to companion/scripts/ocr-demo-out/{input,redacted}.png
 *
 * NOTE: first run downloads the Tesseract WASM core + English model (~10-15MB) and caches it.
 * That is the ONLY network call — the image itself never leaves the machine.
 */
import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import sharp from "sharp";
import {
  ocrRedactImage,
  TesseractOcrRunner,
} from "../src/analysis/ocrRedact.js";
import type { AnonPolicy, KnownEntities } from "../src/analysis/anonymize.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const OUT_DIR = path.join(__dirname, "ocr-demo-out");

// Same shape the case derives at runtime: enable all categories + a few known victim entities.
const POLICY: AnonPolicy = {
  enabled: true,
  categories: { IP: true, EMAIL: true, USER: true, HOST: true, DOMAIN: true, PATH: true, CMD: true, REG: true },
  redactSecrets: false,
};

const KNOWN: KnownEntities = {
  hosts: ["VICTIM-PC"],
  accounts: ["CORP\\admin"],
  internalDomains: ["corp.local"],
};

// Words that SHOULD be redacted (in KNOWN / internal-IP) vs. words that must survive.
const REDACT = ["VICTIM-PC", "corp.local", "10.0.0.5"];
const KEEP = ["hello", "world", "8.8.8.8"]; // 8.8.8.8 is public → preserved by design

/** Render a synthetic "console screenshot" PNG with crisp text Tesseract can read. */
async function makeSyntheticImage(): Promise<Buffer> {
  const lines = [
    "Host:        VICTIM-PC",
    "Domain:      corp.local",
    "Internal IP: 10.0.0.5",
    "Public C2:   8.8.8.8",
    "Note:        hello world",
  ];
  const lineHeight = 44;
  const width = 640;
  const height = lineHeight * lines.length + 40;
  const texts = lines
    .map(
      (l, i) =>
        `<text x="24" y="${48 + i * lineHeight}" font-family="DejaVu Sans Mono, Consolas, monospace" ` +
        `font-size="26" fill="#111">${l}</text>`,
    )
    .join("");
  const svg =
    `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}">` +
    `<rect width="${width}" height="${height}" fill="#ffffff"/>${texts}</svg>`;
  return sharp(Buffer.from(svg)).png().toBuffer();
}

async function main(): Promise<void> {
  const argPath = process.argv[2];
  const input = argPath
    ? await fs.readFile(path.resolve(argPath))
    : await makeSyntheticImage();

  await fs.mkdir(OUT_DIR, { recursive: true });
  await fs.writeFile(path.join(OUT_DIR, "input.png"), input);

  const runner = new TesseractOcrRunner();

  // Show what OCR actually saw + which words the anonymizer flags (transparency).
  const words = await runner.recognize(input);
  console.log(`\nOCR read ${words.length} word(s):`);
  for (const w of words) {
    console.log(
      `  "${w.text}"  conf=${w.confidence.toFixed(0)}  ` +
        `bbox=(${w.bbox.x},${w.bbox.y} ${w.bbox.w}x${w.bbox.h})`,
    );
  }

  const result = await ocrRedactImage(input, POLICY, KNOWN, runner);
  await fs.writeFile(path.join(OUT_DIR, "redacted.png"), result.buffer);

  console.log(`\nRedaction applied: ${result.changed ? "YES (boxes composited)" : "NO (nothing matched)"}`);
  if (result.redactions.length > 0) {
    console.log(`Boxed words: ${result.redactions.map((w) => w.text).join(", ")}`);
  }

  if (!argPath) {
    // Self-check against the synthetic expectations.
    const seen = new Set(words.map((w) => w.text.replace(/[:,]/g, "")));
    const matchedExpected = REDACT.filter((r) => [...seen].some((s) => s.includes(r) || r.includes(s)));
    console.log(`\nExpected-redacted entities OCR found: ${matchedExpected.join(", ") || "(none — text may not have OCR'd cleanly)"}`);
    console.log(`Expected-kept tokens (must NOT be boxed): ${KEEP.join(", ")}`);
  }

  console.log(`\nWrote:`);
  console.log(`  ${path.join(OUT_DIR, "input.png")}`);
  console.log(`  ${path.join(OUT_DIR, "redacted.png")}`);
  console.log(`\nOpen both side by side — redacted entities should be under black boxes,`);
  console.log(`"hello world" and the public IP 8.8.8.8 should remain visible.\n`);
}

main().catch((err) => {
  console.error("ocr-redact-demo failed:", err);
  process.exit(1);
});
