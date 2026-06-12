import { describe, it, expect } from "vitest";
import { inflateRawSync } from "node:zlib";
import { createZip, readZip, crc32, type ZipEntry } from "../../src/analysis/zipArchive.js";

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
