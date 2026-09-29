import { describe, it, expect } from "vitest";
import { mkdtemp, readFile, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import {
  CASE_ZIP_MAX_COMPRESSION_RATIO,
  DEFAULT_CASE_ZIP_LIMITS,
  extractCaseZipEntry,
  listCaseZipEntries,
  readCaseZipEntry,
} from "../../src/analysis/caseZipReader.js";
import { createZip } from "../../src/analysis/zipArchive.js";
import { buildRawZip, deflatedEntry, deflatedZeros, storedEntry } from "../helpers/rawZip.js";

// #1828: the case-package ZIP reader must refuse a bomb before memory grows, and stream the rest.

const MiB = 1024 * 1024;

async function scratch(): Promise<string> {
  return mkdtemp(join(tmpdir(), "dfir-casezip-"));
}

describe("listCaseZipEntries — refused from the central directory, before any inflate", () => {
  it("lists a normal archive written by createZip", () => {
    const zip = createZip([
      { path: "case.json", data: Buffer.from('{"caseId":"INC-1"}') },
      { path: "state/notes.md", data: Buffer.from("notes") },
    ]);
    expect(listCaseZipEntries(zip).map((e) => [e.name, e.size])).toEqual([
      ["case.json", 18],
      ["state/notes.md", 5],
    ]);
  });

  it("refuses one honest high-ratio entry as a possible zip bomb", async () => {
    const { body, crc } = await deflatedZeros(64 * MiB);
    const zip = buildRawZip([{ name: "big.bin", body, method: 8, crc, size: 64 * MiB }]);
    expect(64 * MiB).toBeGreaterThan(body.length * CASE_ZIP_MAX_COMPRESSION_RATIO);
    expect(() => listCaseZipEntries(zip)).toThrow(/not a valid case archive: .*big\.bin.*zip bomb/);
  });

  it("refuses a bomb split into many entries each under the per-entry ratio threshold", async () => {
    const piece = await deflatedZeros(900 * 1024);
    const zip = buildRawZip(
      Array.from({ length: 8 }, (_, i) => ({
        name: `p${i}.bin`,
        ...piece,
        method: 8 as const,
        size: 900 * 1024,
      })),
    );
    expect(() => listCaseZipEntries(zip)).toThrow(/the archive inflates .* zip bomb/);
  });

  it("refuses an entry over the per-entry cap and an archive over the total cap", () => {
    const zip = createZip([
      { path: "a.bin", data: Buffer.alloc(3000, 1) },
      { path: "b.bin", data: Buffer.alloc(3000, 2) },
    ]);
    const limits = { ...DEFAULT_CASE_ZIP_LIMITS, ratioMinBytes: Infinity };
    expect(() => listCaseZipEntries(zip, { ...limits, maxEntryBytes: 2000 })).toThrow(
      /a\.bin.*over the 2000 byte cap/,
    );
    expect(() => listCaseZipEntries(zip, { ...limits, maxTotalBytes: 5000 })).toThrow(
      /past the 5000 byte cap/,
    );
  });

  it("refuses two entries that share the same bytes (overlapping-file bomb)", () => {
    const one = deflatedEntry("a.bin", Buffer.from("payload"));
    const zip = buildRawZip([one, { ...one, shareLocalWith: 0 }]);
    expect(() => listCaseZipEntries(zip)).toThrow(/overlap/);
  });

  it("refuses a local header whose name differs from the central record", () => {
    const zip = buildRawZip([deflatedEntry("case.json", Buffer.from("{}"))]);
    const at = zip.indexOf(Buffer.from("case.json")); // the local copy comes first
    zip.write("CASE.json", at);
    expect(() => listCaseZipEntries(zip)).toThrow(/does not match its central record/);
  });

  it("refuses an encrypted entry, an unknown method and a stored entry with two sizes", () => {
    const enc = buildRawZip([{ ...deflatedEntry("a", Buffer.from("x")), flags: 0x0801 }]);
    expect(() => listCaseZipEntries(enc)).toThrow(/encrypted/);
    const bz = buildRawZip([{ ...deflatedEntry("a", Buffer.from("x")), method: 12 as unknown as 8 }]);
    expect(() => listCaseZipEntries(bz)).toThrow(/unsupported compression method 12/);
    const stored = buildRawZip([{ ...storedEntry("a", Buffer.from("xyz")), size: 1000 }]);
    expect(() => listCaseZipEntries(stored)).toThrow(/two different sizes/);
  });

  it("refuses ZIP64 markers and trailing bytes after the end record", () => {
    const zip = buildRawZip([deflatedEntry("a", Buffer.from("x"))]);
    const zip64 = Buffer.from(zip);
    zip64.writeUInt32LE(0xffffffff, zip64.length - 22 + 16);
    expect(() => listCaseZipEntries(zip64)).toThrow(/ZIP64/);
    expect(() => listCaseZipEntries(Buffer.concat([zip, Buffer.from("junk")]))).toThrow(/not a ZIP archive/);
  });
});

describe("extractCaseZipEntry — streams to disk and never trusts the declared size", () => {
  it("writes a deflated and a stored entry byte for byte, with their SHA-256", async () => {
    const dir = await scratch();
    const text = Buffer.from("line one\nline two\n".repeat(1000));
    const zip = buildRawZip([deflatedEntry("a.txt", text), storedEntry("b.bin", Buffer.from([1, 2, 3]))]);
    const [a, b] = listCaseZipEntries(zip);
    const ra = await extractCaseZipEntry(zip, a, join(dir, "a.txt"));
    const rb = await extractCaseZipEntry(zip, b, join(dir, "b.bin"));
    expect((await readFile(join(dir, "a.txt"))).equals(text)).toBe(true);
    expect(ra).toEqual({ bytes: text.length, sha256: createHash("sha256").update(text).digest("hex") });
    expect(rb.bytes).toBe(3);
    expect(readCaseZipEntry(zip, b).equals(Buffer.from([1, 2, 3]))).toBe(true);
  });

  it("stops a header that lies about its size before the bomb is inflated", async () => {
    const dir = await scratch();
    const { body, crc } = await deflatedZeros(256 * MiB);
    const zip = buildRawZip([{ name: "liar.bin", body, method: 8, crc, size: 1000 }]);
    const [entry] = listCaseZipEntries(zip); // the declared sizes are harmless
    const before = process.memoryUsage().arrayBuffers;
    await expect(extractCaseZipEntry(zip, entry, join(dir, "liar.bin"))).rejects.toThrow(
      /inflates past the size its header declares/,
    );
    expect(process.memoryUsage().arrayBuffers - before).toBeLessThan(32 * MiB);
    // Only the first zlib chunk ever reached the disk.
    expect((await readFile(join(dir, "liar.bin"))).length).toBeLessThan(MiB);
    expect(() => readCaseZipEntry(zip, entry)).toThrow(/could not be inflated/);
  });

  it("refuses a CRC mismatch and leaves the handle closed (the file can be listed and removed)", async () => {
    const dir = await scratch();
    const zip = buildRawZip([{ ...deflatedEntry("a.txt", Buffer.from("hello")), crc: 1234 }]);
    const [entry] = listCaseZipEntries(zip);
    await expect(extractCaseZipEntry(zip, entry, join(dir, "a.txt"))).rejects.toThrow(/CRC mismatch/);
    expect(await readdir(dir)).toEqual(["a.txt"]);
  });
});
