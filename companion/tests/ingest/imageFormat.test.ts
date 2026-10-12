// detectImageFormat decides a capture's stored filename and MIME type (#425), so its answer is part
// of the evidence record. These cases pin the magic-number table and the 12-byte floor directly,
// rather than only through the capture routes that call it (#2170).
import { describe, expect, it } from "vitest";
import { detectImageFormat } from "../../src/ingest/imageFormat.js";

const pad = (head: number[] | string | Buffer, len = 16): Buffer => {
  const start = typeof head === "string" ? Buffer.from(head, "ascii") : Buffer.from(head);
  return Buffer.concat([start, Buffer.alloc(Math.max(0, len - start.length))]);
};

const PNG_SIG = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
const JPEG_SIG = [0xff, 0xd8, 0xff, 0xe0];
const WEBP_SIG = Buffer.concat([Buffer.from("RIFF"), Buffer.from([0x24, 0, 0, 0]), Buffer.from("WEBPVP8 ")]);

describe("detectImageFormat — accepted formats", () => {
  it.each([
    ["PNG", pad(PNG_SIG), { ext: ".png", mimeType: "image/png" }],
    ["JPEG", pad(JPEG_SIG), { ext: ".jpg", mimeType: "image/jpeg" }],
    ["GIF87a", pad("GIF87a"), { ext: ".gif", mimeType: "image/gif" }],
    ["GIF89a", pad("GIF89a"), { ext: ".gif", mimeType: "image/gif" }],
    ["WebP", pad(WEBP_SIG), { ext: ".webp", mimeType: "image/webp" }],
  ])("identifies %s by its magic number", (_name, bytes, expected) => {
    expect(detectImageFormat(bytes)).toEqual(expected);
  });

  it("accepts a buffer of exactly 12 bytes (the floor)", () => {
    expect(detectImageFormat(pad(PNG_SIG, 12))).toEqual({ ext: ".png", mimeType: "image/png" });
  });

  it("does not mutate the buffer it inspects", () => {
    const bytes = pad(PNG_SIG);
    const before = Buffer.from(bytes);
    detectImageFormat(bytes);
    expect(bytes.equals(before)).toBe(true);
  });
});

describe("detectImageFormat — rejected input", () => {
  it.each([
    ["an empty buffer", Buffer.alloc(0)],
    ["an 11-byte valid PNG prefix (under the 12-byte floor)", pad(PNG_SIG, 11)],
    ["a 4-byte PNG prefix", Buffer.from(PNG_SIG.slice(0, 4))],
    [
      "a RIFF container that is WAVE, not WEBP",
      pad(Buffer.concat([Buffer.from("RIFF"), Buffer.alloc(4), Buffer.from("WAVE")])),
    ],
    ["a UTF-8 BOM before a PNG signature", pad([0xef, 0xbb, 0xbf, ...PNG_SIG])],
    ["a PNG signature with the wrong lead byte", pad([0x88, 0x50, 0x4e, 0x47])],
    ["plain text", pad("hello world, not an image")],
    ["all zero bytes", Buffer.alloc(64)],
    [
      "fixed pseudo-random bytes",
      Buffer.from([0x13, 0x37, 0xca, 0xfe, 0xba, 0xbe, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
    ],
  ])("returns null for %s", (_name, bytes) => {
    expect(detectImageFormat(bytes)).toBeNull();
  });
});
