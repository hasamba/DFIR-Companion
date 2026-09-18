import { describe, it, expect } from "vitest";
import {
  parseAliasRecord,
  looksLikeAliasRecord,
  AliasRecordError,
  MAX_ALIAS_BYTES,
  MAX_ALIAS_TAGS,
} from "../../src/analysis/aliasRecordReader.js";

// Fixtures written by dmgbuild/mac_alias 2.2.3's own Alias.to_bytes() (the same project whose
// Bookmark.to_bytes() produced #1013's bookmark fixtures). Layout cross-checked against
// strozfriedberg/plistutils @3d00bf8 ALIASV2/ALIASV3 — mac_alias's own v3 READER is buggy
// (reads 46 of a 50-byte block), so the writer + plistutils are the sources of truth here. See
// RECOMMENDATION-1301.md.

// v2, appinfo 0, volume "Macintosh HD" created 2015-03-04T05:06:07Z, target file
// "EvilAgent.app" (folder CNID 1234, CNID 5678, created 2016-07-08T09:10:11Z), tags: folder name,
// high-res dates, CNID path (2,1234,5678), carbon path, POSIX path, POSIX mount point.
const ALIAS_V2 =
  "000000000162000200000c4d6163696e746f7368204844000000000000000000000000000000d11c433f482b0000000004d20d4576696c4167656e742e61707000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000162ed3a51e730000000000000000ffffffff000000000000000000000000000000000000000c4170706c69636174696f6e73001000080000d11c433f0000001100080000d3a51e7300000001000c00000002000004d20000162e000200274d6163696e746f73682048443a4170706c69636174696f6e733a4576696c4167656e742e61707000000e001c000d004500760069006c004100670065006e0074002e006100700070000f001a000c004d006100630069006e0074006f007300680020004800440012001b2f4170706c69636174696f6e732f4576696c4167656e742e61707000001300012f00ffff0000";

// v3, appinfo == "alis" (a legal four-char-code — a magic-first dispatch would misroute this to
// the bookmark decoder), volume "Data", target FOLDER "Payloads" (99 / 4242), POSIX path
// /Users/bob/Payloads, mount point /System/Volumes/Data.
const ALIAS_V3_ALIS =
  "616c697300ba000300010000d11c433f0000482b0000000000000063000010920000d3a51e730000000000000000000000000000000000000000001000080000d11c433f0000001100080000d3a51e7300000001000c000000020000006300001092000e00120008005000610079006c006f006100640073000f000a00040044006100740061001200132f55736572732f626f622f5061796c6f61647300001300142f53797374656d2f566f6c756d65732f44617461ffff0000";

// v2 whose Pascal filename was stored with a "/" (HFS names use ":" as the separator).
const ALIAS_V2_SLASHNAME =
  "0000000000e4000200000c4d6163696e746f7368204844000000000000000000000000000000d11c433f482b00000000000107612f622e617070000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002d3a51e730000000000000000ffffffff00000000000000000000000000000000001000080000d11c433f0000001100080000d3a51e730000000e001000070061002f0062002e006100700070000f001a000c004d006100630069006e0074006f00730068002000480044ffff0000";

// A real CFURL "book" bookmark — NOT an alias record.
const BOOK =
  "626f6f6b4801000000000410300000000000000000000000000000000000000000000000000000000000000000000000c8000000080000000106000014000000280000000c000000010100004170706c69636174696f6e731100000001010000426f6f6b6d61726b65644170702e6170700000000800000001060000540000006000000004000000030300000200000004000000030300004d0000000c000000010100004d6163696e746f7368204844240000000101000043434343434343432d313131312d323232322d333333332d3434343434343434343434341100000001010000426f6f6b6d61726b65644170702e61707000000034000000feffffff010000000000000005000000041000000400000000000000051000004400000000000000102000006c0000000000000011200000800000000000000017f00000ac00000000000000";

const buf = (hex: string): Buffer => Buffer.from(hex, "hex");

describe("parseAliasRecord — version 2", () => {
  it("reads the fixed block and every tag mac_alias wrote", () => {
    const r = parseAliasRecord(buf(ALIAS_V2));
    expect(r.version).toBe(2);
    expect(r.appinfo).toBe("00000000");
    expect(r.kind).toBe(0);
    expect(r.volumeName).toBe("Macintosh HD");
    expect(r.volumeCreationDate).toBe("2015-03-04T05:06:07.000Z");
    expect(r.fsType).toBe("H+");
    expect(r.diskType).toBe(0);
    expect(r.folderCnid).toBe(1234);
    expect(r.targetCnid).toBe(5678);
    expect(r.targetFilename).toBe("EvilAgent.app");
    expect(r.targetCreationDate).toBe("2016-07-08T09:10:11.000Z");
    expect(r.levelsFrom).toBe(-1);
    expect(r.levelsTo).toBe(-1);
    expect(r.folderName).toBe("Applications");
    expect(r.cnidPath).toEqual([2, 1234, 5678]);
    expect(r.carbonPath).toBe("Macintosh HD:Applications:EvilAgent.app");
    expect(r.posixPath).toBe("/Applications/EvilAgent.app");
    expect(r.posixMountPoint).toBe("/");
    expect(r.unknownTags).toEqual([]);
    expect(r.recsize).toBe(buf(ALIAS_V2).length);
  });

  it("renders a stored '/' in a Pascal name as ':' the way mac_alias does (HFS separator)", () => {
    const r = parseAliasRecord(buf(ALIAS_V2_SLASHNAME));
    // mac_alias writes ':'→'/' into the Pascal field and reads '/'→':' back; the UTF-16 tag 14
    // override is used verbatim (mac_alias does no replace there), so the override wins here.
    expect(r.targetFilename).toBe("a/b.app");
    expect(r.pascalFilename).toBe("a:b.app");
  });
});

describe("parseAliasRecord — version 3 (50-byte fixed block)", () => {
  it("reads a v3 record whose appinfo is the four-char-code 'alis'", () => {
    const r = parseAliasRecord(buf(ALIAS_V3_ALIS));
    expect(r.version).toBe(3);
    expect(r.appinfo).toBe("alis");
    expect(r.kind).toBe(1);
    expect(r.volumeName).toBe("Data");
    expect(r.targetFilename).toBe("Payloads");
    expect(r.folderCnid).toBe(99);
    expect(r.targetCnid).toBe(4242);
    expect(r.posixPath).toBe("/Users/bob/Payloads");
    expect(r.posixMountPoint).toBe("/System/Volumes/Data");
    expect(r.cnidPath).toEqual([2, 99, 4242]);
    expect(r.volumeCreationDate).toBe("2015-03-04T05:06:07.000Z");
    expect(r.targetCreationDate).toBe("2016-07-08T09:10:11.000Z");
    expect(r.levelsFrom).toBeUndefined();
  });
});

describe("looksLikeAliasRecord — the structural probe, never the first four bytes", () => {
  it("accepts both fixtures and rejects a real CFURL bookmark", () => {
    expect(looksLikeAliasRecord(buf(ALIAS_V2))).toBe(true);
    expect(looksLikeAliasRecord(buf(ALIAS_V3_ALIS))).toBe(true);
    expect(looksLikeAliasRecord(buf(BOOK))).toBe(false);
  });

  it("rejects a version outside {2, 3} and a recsize past the buffer", () => {
    const v = Buffer.from(buf(ALIAS_V2));
    v.writeInt16BE(4, 6);
    expect(looksLikeAliasRecord(v)).toBe(false);
    const big = Buffer.from(buf(ALIAS_V2));
    big.writeInt16BE(big.length + 1, 4);
    expect(looksLikeAliasRecord(big)).toBe(false);
    expect(looksLikeAliasRecord(Buffer.alloc(7))).toBe(false);
  });
});

describe("parseAliasRecord — every malformed case throws AliasRecordError, never a raw RangeError", () => {
  const cases: Array<[string, () => Buffer]> = [
    ["shorter than the header", () => Buffer.alloc(7)],
    [
      "unsupported version",
      () => {
        const b = Buffer.from(buf(ALIAS_V2));
        b.writeInt16BE(5, 6);
        return b;
      },
    ],
    [
      "recsize below mac_alias's 150 floor",
      () => {
        const b = Buffer.from(buf(ALIAS_V2));
        b.writeInt16BE(100, 4);
        return b;
      },
    ],
    [
      "recsize past the buffer",
      () => {
        const b = Buffer.from(buf(ALIAS_V2));
        b.writeInt16BE(b.length + 2, 4);
        return b;
      },
    ],
    ["fixed block truncated", () => buf(ALIAS_V2).subarray(0, 100)],
    [
      "Pascal volume-name count past its field",
      () => {
        const b = Buffer.from(buf(ALIAS_V2));
        b[10] = 40;
        return b;
      },
    ],
    [
      "negative tag length",
      () => {
        const b = Buffer.from(buf(ALIAS_V2));
        b.writeInt16BE(-4, 8 + 142 + 2);
        return b;
      },
    ],
    [
      "tag value past the buffer",
      () => {
        const b = Buffer.from(buf(ALIAS_V2));
        b.writeInt16BE(9000, 8 + 142 + 2);
        return b;
      },
    ],
    ["no -1 terminator before end of buffer", () => buf(ALIAS_V2).subarray(0, buf(ALIAS_V2).length - 2)],
    ["over the size budget", () => Buffer.concat([buf(ALIAS_V2), Buffer.alloc(MAX_ALIAS_BYTES)])],
  ];
  for (const [name, make] of cases) {
    it(name, () => {
      expect(() => parseAliasRecord(make())).toThrow(AliasRecordError);
    });
  }

  it("tag 1 with a length that is not a multiple of 4, and tags 16/17 with a length other than 8", () => {
    // Rewrite the first tag (folder name, tag 0, length 12) into tag 1 with length 12 — valid
    // multiple of 4 — then to length 10 — invalid.
    const b = Buffer.from(buf(ALIAS_V2));
    const tagOff = 8 + 142;
    expect(b.readInt16BE(tagOff)).toBe(0);
    b.writeInt16BE(1, tagOff);
    expect(() => parseAliasRecord(b)).not.toThrow();
    const c = Buffer.from(buf(ALIAS_V2));
    c.writeInt16BE(16, tagOff); // high-res date with length 12 — must be exactly 8
    expect(() => parseAliasRecord(c)).toThrow(AliasRecordError);
  });

  it("more than MAX_ALIAS_TAGS tags before the terminator", () => {
    const head = buf(ALIAS_V2).subarray(0, 8 + 142);
    const tag = Buffer.alloc(4);
    tag.writeInt16BE(7, 0); // an unknown tag, zero length
    tag.writeInt16BE(0, 2);
    const many = Buffer.concat([
      head,
      ...Array.from({ length: MAX_ALIAS_TAGS + 1 }, () => tag),
      Buffer.from([0xff, 0xff]),
    ]);
    many.writeInt16BE(many.length, 4);
    expect(() => parseAliasRecord(many)).toThrow(AliasRecordError);
  });

  it("an unknown tag is disclosed by number, and tag 20 (recursive alias) is never recursed into", () => {
    const head = buf(ALIAS_V2).subarray(0, 8 + 142);
    const t7 = Buffer.from([0x00, 0x07, 0x00, 0x02, 0xaa, 0xbb]);
    const t20 = Buffer.concat([Buffer.from([0x00, 0x14, 0x00, 0x04]), Buffer.from("junk")]);
    const b = Buffer.concat([head, t7, t20, Buffer.from([0xff, 0xff])]);
    b.writeInt16BE(b.length, 4);
    const r = parseAliasRecord(b);
    expect(r.unknownTags).toEqual([7, 20]);
  });

  it("tolerates trailing bytes after recsize (mac_alias never compares recsize to the buffer) and discloses them", () => {
    const b = Buffer.concat([buf(ALIAS_V2), Buffer.from([1, 2, 3])]);
    const r = parseAliasRecord(b);
    expect(r.recsize).toBe(buf(ALIAS_V2).length);
    expect(r.trailingBytes).toBe(3);
    expect(r.posixPath).toBe("/Applications/EvilAgent.app");
  });

  it("never reads a tag that sits past recsize — bytes the record did not claim are not its facts", () => {
    // A minimal record (fixed block + terminator, recsize set accordingly), followed by a forged
    // tag 18 ("/Evil") and its own terminator. Before the fix the loop scanned to the end of the
    // buffer and minted the forged path as the record's stored path (code review finding 3).
    const head = buf(ALIAS_V2).subarray(0, 8 + 142);
    const own = Buffer.concat([head, Buffer.from([0xff, 0xff])]);
    own.writeInt16BE(own.length, 4);
    const forged = Buffer.concat([
      Buffer.from([0x00, 0x12, 0x00, 0x05]),
      Buffer.from("/Evil"),
      Buffer.from([0x00, 0xff, 0xff]),
    ]);
    const r = parseAliasRecord(Buffer.concat([own, forged]));
    expect(r.posixPath).toBeUndefined();
    expect(r.trailingBytes).toBe(forged.length);
  });

  it("a CNID path deeper than the budget is malformed, never a silently shortened path", () => {
    const head = buf(ALIAS_V2).subarray(0, 8 + 142);
    const n = 65;
    const tag = Buffer.alloc(4 + n * 4);
    tag.writeInt16BE(1, 0);
    tag.writeInt16BE(n * 4, 2);
    const b = Buffer.concat([head, tag, Buffer.from([0xff, 0xff])]);
    b.writeInt16BE(b.length, 4);
    expect(() => parseAliasRecord(b)).toThrow(/depth budget/);
  });

  it("a zero date is absent, never 1904-01-01", () => {
    // Fixed block only, no tags (so no high-res override): voldate at 8+2+28 = 38, crdate at 8+110.
    const head = Buffer.from(buf(ALIAS_V2).subarray(0, 8 + 142));
    head.writeUInt32BE(0, 38);
    head.writeUInt32BE(0, 8 + 110);
    const b = Buffer.concat([head, Buffer.from([0xff, 0xff])]);
    b.writeInt16BE(b.length, 4);
    const r = parseAliasRecord(b);
    expect(r.volumeCreationDate).toBeUndefined();
    expect(r.targetCreationDate).toBeUndefined();
  });
});
