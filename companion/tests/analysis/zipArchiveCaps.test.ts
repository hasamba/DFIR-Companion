import { randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { crc32, createZip, readZip } from "../../src/analysis/zipArchive.js";

// Codex review of #2204: the size caps were only enforced while inflating DEFLATE entries. A STORED
// entry was copied straight through, and an unknown compression method was read as stored.

/** Rewrite every entry's compression method (local + central headers) to `method`. */
function withMethod(archive: Buffer, method: number): Buffer {
  const out = Buffer.from(archive);
  for (let i = 0; i + 4 <= out.length; i++) {
    const sig = out.readUInt32LE(i);
    if (sig === 0x04034b50) out.writeUInt16LE(method, i + 8);
    if (sig === 0x02014b50) out.writeUInt16LE(method, i + 10);
  }
  return out;
}

/** A minimal archive whose entries are genuinely STORED (method 0), with correct CRCs. */
function storedZip(entries: { path: string; data: Buffer }[]): Buffer {
  const locals: Buffer[] = [];
  const centrals: Buffer[] = [];
  let offset = 0;
  for (const e of entries) {
    const name = Buffer.from(e.path);
    const crc = crc32(e.data);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(e.data.length, 18);
    local.writeUInt32LE(e.data.length, 22);
    local.writeUInt16LE(name.length, 26);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(e.data.length, 20);
    central.writeUInt32LE(e.data.length, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt32LE(offset, 42);
    locals.push(local, name, e.data);
    centrals.push(central, name);
    offset += local.length + name.length + e.data.length;
  }
  const cd = Buffer.concat(centrals);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(cd.length, 12);
  eocd.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, cd, eocd]);
}

describe("readZip caps", () => {
  it("reads a genuinely stored entry within the caps", () => {
    const data = randomBytes(64);
    expect(readZip(storedZip([{ path: "a.bin", data }]))[0].data.equals(data)).toBe(true);
  });

  it("counts a stored entry against the per-entry cap", () => {
    const zip = storedZip([{ path: "a.bin", data: randomBytes(4096) }]);
    expect(() => readZip(zip, { maxEntryBytes: 1024 })).toThrow(/cap/);
  });

  it("counts stored entries against the total cap", () => {
    const zip = storedZip([
      { path: "a.bin", data: randomBytes(800) },
      { path: "b.bin", data: randomBytes(800) },
    ]);
    expect(() => readZip(zip, { maxEntryBytes: 1000, maxTotalBytes: 1200 })).toThrow(/cap/);
  });

  it("refuses an unsupported compression method instead of reading it as stored", () => {
    const zip = withMethod(createZip([{ path: "a.txt", data: Buffer.from("hello") }]), 12);
    expect(() => readZip(zip)).toThrow(/compression method 12/);
  });
});
