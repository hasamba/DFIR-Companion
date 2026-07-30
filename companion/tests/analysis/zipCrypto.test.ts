import { describe, it, expect } from "vitest";
import { inflateRawSync } from "node:zlib";
import {
  zipCryptoDecrypt, parseAesExtra, aesDecrypt, ZipPasswordError,
} from "../../src/analysis/zipCrypto.js";
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

// 7-Zip: `7z a -tzip -pinfected -mem=AES256 aes.zip sample.bin` — 23 bytes, STORED, one AES block.
const AES_ZIP_B64 =
  "UEsDBDMAAQBjAGaB/VwAAAAAMwAAABcAAAAKAAsAc2FtcGxlLmJpbgGZBwACAEFFAwAAjSVbocfmvx3PE5161dsvWZeAGwRMGhH+" +
  "U3dNZiO2mA/QMCMLIAwEGRmcHEdlOo1WBP7zUEsBAj8DMwABAGMAZoH9XAAAAAAzAAAAFwAAAAoALwAAAAAAAAAggLSBAAAAAHNh" +
  "bXBsZS5iaW4KACAAAAAAAAEAGAC4I7e5Wx/dAQAAAAAAAAAAAAAAAAAAAAABmQcAAgBBRQMAAFBLBQYAAAAAAQABAGcAAABmAAAA" +
  "AAA=";

// Same command over a 1000-byte file → 294 ciphertext bytes = 19 AES blocks, DEFLATED then encrypted.
// This is the fixture that fails if the CTR counter is big-endian.
const AES_BIG_ZIP_B64 =
  "UEsDBDMAAQBjALCB/VwAAAAAQgEAAOgDAAAHAAsAYmlnLmJpbgGZBwACAEFFAwgAznxy0fDFGikZitS/zL9C4cbtevTbRU9oSTcl" +
  "90FtHMR8/3kflzvaMYkSLR8tD73AyKE98yGd339dy1TAMd+ClE8kfG9F9akAmxdF1CkVwIMhrshTKOuTtFYkI1Lgnp9qcabmsPlR" +
  "Cbj2lmanL1wdagvK8fyCVk/Q4p3cHAy+FWPOhXIzkAyyl22OQKeXKJiOaN99my8geQJqtHcRVXGlZWnJCUGqgGYrhy/kJIEBxPTu" +
  "QDRqYoGVbexXewZBktHQxIz8lbf0dCAeSYvl+VWLaWXMZTFircZ2cgjsUqOP07aI189Xmlsqe6h2kW/Y9I8CzjnPrQ8ay0Bq8+8c" +
  "RkB/ZFZbyB7oUjVemEC43tOVT0WJstYNe8KsGRnMGk9SOphoOlPwXvDTC//zkvt7bgARk4XCevvxLMBn1ZjP8MylZGZztVBLAQI/" +
  "AzMAAQBjALCB/VwAAAAAQgEAAOgDAAAHAC8AAAAAAAAAIIC0gQAAAABiaWcuYmluCgAgAAAAAAABABgAymVADVwf3QEAAAAAAAAA" +
  "AAAAAAAAAAAAAZkHAAIAQUUDCABQSwUGAAAAAAEAAQBkAAAAcgEAAAAA";

// Entry data plus its central-directory extra field, without going through readZip.
function rawEntryWithExtra(archive: Buffer): { data: Buffer; extra: Buffer } {
  let eocd = -1;
  for (let i = archive.length - 22; i >= 0; i--) {
    if (archive.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  }
  const ptr = archive.readUInt32LE(eocd + 16);
  const compSize = archive.readUInt32LE(ptr + 20);
  const nameLen = archive.readUInt16LE(ptr + 28);
  const extraLen = archive.readUInt16LE(ptr + 30);
  const localOffset = archive.readUInt32LE(ptr + 42);
  const dataStart = localOffset + 30 + archive.readUInt16LE(localOffset + 26) + archive.readUInt16LE(localOffset + 28);
  return {
    data: archive.subarray(dataStart, dataStart + compSize),
    extra: archive.subarray(ptr + 46 + nameLen, ptr + 46 + nameLen + extraLen),
  };
}

describe("parseAesExtra", () => {
  it("reads AE version, strength, and the real compression method", () => {
    const { extra } = rawEntryWithExtra(Buffer.from(AES_ZIP_B64, "base64"));
    expect(parseAesExtra(extra)).toEqual({ aeVersion: 2, strength: 3, actualMethod: 0 });
  });

  it("returns null when there is no 0x9901 field", () => {
    expect(parseAesExtra(Buffer.alloc(0))).toBeNull();
  });
});

describe("aesDecrypt", () => {
  it("decrypts a single-block AES-256 entry", () => {
    const { data } = rawEntryWithExtra(Buffer.from(AES_ZIP_B64, "base64"));
    const { plaintext, macOk } = aesDecrypt(data, "infected", 3);
    expect(plaintext.toString("utf8")).toBe("MZ fake sample payload\n");
    expect(macOk).toBe(true);
  });

  it("decrypts a multi-block entry across all 19 AES blocks", () => {
    // Guards the little-endian counter. With a big-endian counter the first 16 bytes match and
    // everything after is garbage, so only a multi-block fixture catches it.
    const { data, extra } = rawEntryWithExtra(Buffer.from(AES_BIG_ZIP_B64, "base64"));
    const params = parseAesExtra(extra);
    expect(params).not.toBeNull();
    expect(params!.actualMethod).toBe(8);   // deflated before encryption
    const { plaintext, macOk } = aesDecrypt(data, "infected", params!.strength);
    expect(macOk).toBe(true);
    const expected = Buffer.from(Array.from({ length: 1000 }, (_, i) => (i * 7 + 3) % 256));
    expect(inflateRawSync(plaintext).equals(expected)).toBe(true);
  });

  it("throws ZipPasswordError with reason wrong-password for a bad password", () => {
    const { data } = rawEntryWithExtra(Buffer.from(AES_ZIP_B64, "base64"));
    expect(() => aesDecrypt(data, "wrongpw", 3)).toThrow(ZipPasswordError);
    try {
      aesDecrypt(data, "wrongpw", 3);
    } catch (err) {
      expect((err as ZipPasswordError).reason).toBe("wrong-password");
    }
  });
});
