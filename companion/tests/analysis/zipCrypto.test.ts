import { describe, it, expect } from "vitest";
import { zipCryptoDecrypt } from "../../src/analysis/zipCrypto.js";
import { crc32 } from "../../src/analysis/zipArchive.js";

// Produced by Info-ZIP: `zip -P infected zc.zip sample.bin`
// sample.bin content is exactly "MZ fake sample payload\n" (23 bytes, STORED).
const ZC_ZIP_B64 =
  "UEsDBAoACQAAAGWB/VzrJ0KsIwAAABcAAAAKABwAc2FtcGxlLmJpblVUCQAD7vtpau77aWp1eAsAAQToAwAABOgDAACSY93uO3OX" +
  "/aoYARCx5Jfbd3EGx/7tlqbVxQgzvT21C/Kx6FBLBwjrJ0KsIwAAABcAAABQSwECHgMKAAkAAABlgf1c6ydCrCMAAAAXAAAACgAY" +
  "AAAAAAABAAAAtIEAAAAAc2FtcGxlLmJpblVUBQAD7vtpanV4CwABBOgDAAAE6AMAAFBLBQYAAAAAAQABAFAAAAB3AAAAAAA=";

// Pull the single entry's raw (still encrypted) bytes straight out of the archive, so this test
// exercises the cipher alone and does not depend on readZip.
function rawEntry(archive: Buffer): { data: Buffer; crc: number; modTime: number } {
  let eocd = -1;
  for (let i = archive.length - 22; i >= 0; i--) {
    if (archive.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  }
  const ptr = archive.readUInt32LE(eocd + 16);
  const modTime = archive.readUInt16LE(ptr + 12);
  const crc = archive.readUInt32LE(ptr + 16);
  const compSize = archive.readUInt32LE(ptr + 20);
  const nameLen = archive.readUInt16LE(ptr + 28);
  const localOffset = archive.readUInt32LE(ptr + 42);
  const dataStart = localOffset + 30 + archive.readUInt16LE(localOffset + 26) + archive.readUInt16LE(localOffset + 28);
  return { data: archive.subarray(dataStart, dataStart + compSize), crc, modTime };
}

describe("zipCryptoDecrypt", () => {
  const archive = Buffer.from(ZC_ZIP_B64, "base64");

  it("decrypts an Info-ZIP ZipCrypto entry with the correct password", () => {
    const { data, crc } = rawEntry(archive);
    const body = zipCryptoDecrypt(data, "infected").subarray(12);
    expect(body.toString("utf8")).toBe("MZ fake sample payload\n");
    expect(crc32(body)).toBe(crc);
  });

  it("produces a check byte matching the mod-time high byte when flag bit 3 is set", () => {
    // Regression guard: Info-ZIP sets the data-descriptor flag, so the check byte is the
    // mod-time high byte, NOT the CRC high byte. Verifying only against the CRC rejects a
    // correct password.
    const { data, crc, modTime } = rawEntry(archive);
    const checkByte = zipCryptoDecrypt(data, "infected")[11];
    expect(checkByte).toBe(modTime >> 8);
    expect(checkByte).not.toBe(crc >>> 24);
  });

  it("produces a different check byte for a wrong password", () => {
    const { data, modTime } = rawEntry(archive);
    expect(zipCryptoDecrypt(data, "wrongpw")[11]).not.toBe(modTime >> 8);
  });
});
