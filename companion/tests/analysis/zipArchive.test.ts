import { describe, it, expect } from "vitest";
import { inflateRawSync } from "node:zlib";
import { createZip, readZip, crc32, type ZipEntry } from "../../src/analysis/zipArchive.js";
import { ZipPasswordError } from "../../src/analysis/zipCrypto.js";

const EOCD_SIG = 0x06054b50;
const LOCAL_SIG = 0x04034b50;

describe("crc32", () => {
  it("matches known CRC-32 values", () => {
    // CRC-32 of the ASCII string "123456789" is the canonical 0xCBF43926.
    expect(crc32(Buffer.from("123456789"))).toBe(0xcbf43926);
    expect(crc32(Buffer.alloc(0))).toBe(0);
  });
});

describe("createZip / readZip", () => {
  const entries: ZipEntry[] = [
    { path: "REDACTION-NOTES.txt", data: Buffer.from("hello redacted world", "utf8") },
    { path: "report/report.md", data: Buffer.from("# Report\n\nANON_HOST_1 did things.\n", "utf8") },
    { path: "screenshots/shot-001.png", data: Buffer.from([0x89, 0x50, 0x4e, 0x47, 1, 2, 3, 4, 5]) },
  ];

  it("round-trips entries through createZip → readZip", () => {
    const archive = createZip(entries);
    const back = readZip(archive);
    expect(back.map((e) => e.path)).toEqual(entries.map((e) => e.path));
    for (let i = 0; i < entries.length; i++) {
      expect(back[i].data.equals(entries[i].data)).toBe(true);
    }
  });

  it("emits a valid EOCD with the correct entry count", () => {
    const archive = createZip(entries);
    const idx = archive.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
    expect(idx).toBeGreaterThanOrEqual(0);
    expect(archive.readUInt32LE(idx)).toBe(EOCD_SIG);
    expect(archive.readUInt16LE(idx + 10)).toBe(entries.length);
  });

  it("starts with a local file header and stores DEFLATE-compressed data a standard tool can inflate", () => {
    const archive = createZip(entries);
    expect(archive.readUInt32LE(0)).toBe(LOCAL_SIG);
    // First entry: parse its local header and inflate the payload independently of readZip.
    const nameLen = archive.readUInt16LE(26);
    const extraLen = archive.readUInt16LE(28);
    const compSize = archive.readUInt32LE(18);
    const dataStart = 30 + nameLen + extraLen;
    const inflated = inflateRawSync(archive.subarray(dataStart, dataStart + compSize));
    expect(inflated.equals(entries[0].data)).toBe(true);
  });

  it("is deterministic for identical inputs", () => {
    expect(createZip(entries).equals(createZip(entries))).toBe(true);
  });

  it("handles an empty entry list and empty file data", () => {
    expect(readZip(createZip([]))).toEqual([]);
    const back = readZip(createZip([{ path: "empty.txt", data: Buffer.alloc(0) }]));
    expect(back).toHaveLength(1);
    expect(back[0].data.length).toBe(0);
  });

  it("rejects a buffer that is not a ZIP", () => {
    expect(() => readZip(Buffer.from("definitely not a zip"))).toThrow(/EOCD/);
  });
});

describe("readZip — zip-bomb guard (#247)", () => {
  // A real zip-bomb-style entry: highly compressible data (zeros) that inflates far larger than
  // its compressed size. createZip's DEFLATE compresses this down to a tiny archive, exactly the
  // shape a crafted .dfircase archive would exploit. maxEntryBytes/maxTotalBytes override the
  // (deliberately huge, 512MB/2GB) production defaults so this runs fast without allocating
  // gigabytes — the mechanism under test (zlib's maxOutputLength aborting mid-inflation) doesn't
  // care about the absolute cap size, only that inflation is capped BEFORE full materialization.
  const bomb = (n: number) => Buffer.alloc(n, 0);

  it("rejects an entry whose inflated size exceeds the per-entry cap — without fully inflating it", () => {
    const archive = createZip([{ path: "bomb.bin", data: bomb(10 * 1024 * 1024) }]); // 10MB of zeros
    expect(() => readZip(archive, { maxEntryBytes: 1024 * 1024, maxTotalBytes: 1024 * 1024 * 1024 }))
      .toThrow(/possible zip bomb/i);
  });

  it("allows an entry within the cap", () => {
    const archive = createZip([{ path: "fine.bin", data: bomb(1000) }]);
    expect(() => readZip(archive, { maxEntryBytes: 10_000, maxTotalBytes: 10_000 })).not.toThrow();
  });

  it("rejects when several entries are each under the per-entry cap but exceed the TOTAL cap", () => {
    const archive = createZip([
      { path: "a.bin", data: bomb(6000) },
      { path: "b.bin", data: bomb(6000) },
    ]);
    // Each entry (6000) is under maxEntryBytes (10000), but together they exceed maxTotalBytes (10000).
    expect(() => readZip(archive, { maxEntryBytes: 10_000, maxTotalBytes: 10_000 }))
      .toThrow(/possible zip bomb/i);
  });

  it("uses the real (512 MB / 2 GB) production defaults when no override is given", () => {
    // Doesn't need to actually allocate 512MB — an entry well under the default cap must still
    // round-trip cleanly with the defaults active, proving they don't accidentally reject normal
    // archives (e.g. a real forensic case's screenshots/state).
    const archive = createZip([{ path: "normal.bin", data: Buffer.from("just a normal file", "utf8") }]);
    expect(() => readZip(archive)).not.toThrow();
  });
});

// Same two fixtures as tests/analysis/zipCrypto.test.ts — see that file for how they were produced.
const ZC_ZIP_B64 =
  "UEsDBAoACQAAAGWB/VzrJ0KsIwAAABcAAAAKABwAc2FtcGxlLmJpblVUCQAD7vtpau77aWp1eAsAAQToAwAABOgDAACSY93uO3OX" +
  "/aoYARCx5Jfbd3EGx/7tlqbVxQgzvT21C/Kx6FBLBwjrJ0KsIwAAABcAAABQSwECHgMKAAkAAABlgf1c6ydCrCMAAAAXAAAACgAY" +
  "AAAAAAABAAAAtIEAAAAAc2FtcGxlLmJpblVUBQAD7vtpanV4CwABBOgDAAAE6AMAAFBLBQYAAAAAAQABAFAAAAB3AAAAAAA=";
const AES_ZIP_B64 =
  "UEsDBDMAAQBjAGaB/VwAAAAAMwAAABcAAAAKAAsAc2FtcGxlLmJpbgGZBwACAEFFAwAAjSVbocfmvx3PE5161dsvWZeAGwRMGhH+" +
  "U3dNZiO2mA/QMCMLIAwEGRmcHEdlOo1WBP7zUEsBAj8DMwABAGMAZoH9XAAAAAAzAAAAFwAAAAoALwAAAAAAAAAggLSBAAAAAHNh" +
  "bXBsZS5iaW4KACAAAAAAAAEAGAC4I7e5Wx/dAQAAAAAAAAAAAAAAAAAAAAABmQcAAgBBRQMAAFBLBQYAAAAAAQABAGcAAABmAAAA" +
  "AAA=";

describe("readZip with encrypted entries", () => {
  it("reads a ZipCrypto entry when given the password", () => {
    const back = readZip(Buffer.from(ZC_ZIP_B64, "base64"), { password: "infected" });
    expect(back).toHaveLength(1);
    expect(back[0].path).toBe("sample.bin");
    expect(back[0].data.toString("utf8")).toBe("MZ fake sample payload\n");
  });

  it("reads an AES-256 entry when given the password", () => {
    const back = readZip(Buffer.from(AES_ZIP_B64, "base64"), { password: "infected" });
    expect(back).toHaveLength(1);
    expect(back[0].path).toBe("sample.bin");
    expect(back[0].data.toString("utf8")).toBe("MZ fake sample payload\n");
  });

  it("throws password-required when an encrypted entry gets no password", () => {
    try {
      readZip(Buffer.from(AES_ZIP_B64, "base64"));
      throw new Error("expected readZip to throw");
    } catch (err) {
      expect(err).toBeInstanceOf(ZipPasswordError);
      expect((err as ZipPasswordError).reason).toBe("password-required");
    }
  });

  it("throws wrong-password for a bad ZipCrypto password", () => {
    try {
      readZip(Buffer.from(ZC_ZIP_B64, "base64"), { password: "nope" });
      throw new Error("expected readZip to throw");
    } catch (err) {
      expect(err).toBeInstanceOf(ZipPasswordError);
      expect((err as ZipPasswordError).reason).toBe("wrong-password");
    }
  });

  it("still round-trips unencrypted archives unchanged", () => {
    const archive = createZip([{ path: "a.txt", data: Buffer.from("plain") }]);
    expect(readZip(archive)[0].data.toString()).toBe("plain");
    // A password on an unencrypted archive is simply ignored.
    expect(readZip(archive, { password: "infected" })[0].data.toString()).toBe("plain");
  });
});
