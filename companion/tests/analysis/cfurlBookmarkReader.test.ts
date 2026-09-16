import { describe, it, expect } from "vitest";
import {
  parseBookmark,
  bookmarkGet,
  CfurlBookmarkError,
  kBookmarkPath,
  kBookmarkCNIDPath,
  kBookmarkVolumeName,
  kBookmarkVolumeUUID,
  kBookmarkVolumeIsRoot,
  kBookmarkWasFileReference,
  kBookmarkDisplayName,
} from "../../src/analysis/cfurlBookmarkReader.js";

// Real bytes produced by michaeldiazlutz/mac_alias's own bidirectional `Bookmark.to_bytes()`
// (fetched live from PyPI, actively maintained, used by dmgbuild) — cross-validated by round-
// tripping through `Bookmark.from_bytes()` before capture. See RECOMMENDATION-12.md.
const REAL_BOOKMARK_HEX =
  "626f6f6ba4010000000004103000000000000000000000000000000000000000000000000000000000000000000000000c01000010000000010600001c0000002c0000003c0000004c000000050000000101000055736572730000000700000001010000616e616c7973740007000000010100004465736b746f70000b000000010100007061796c6f61642e6578650010000000010600007800000084000000900000009c0000000400000003030000020000000400000003030000640000000400000003030000c800000004000000030300002c0100000c000000010100004d6163696e746f7368204844240000000101000031323334353637382d313233342d313233342d313233342d31323334353637383941424300000000010500000b000000010100007061796c6f61642e6578650000000000010500004c000000feffffff01000000000000000700000004100000040000000000000005100000600000000000000010200000a80000000000000011200000bc0000000000000030200000e80000000000000001d00000040100000000000017f00000f000000000000000";

function buf(hex: string): Buffer {
  return Buffer.from(hex, "hex");
}

describe("parseBookmark — real mac_alias-encoded fixture", () => {
  const data = buf(REAL_BOOKMARK_HEX);

  it("recognizes the real 'book' magic", () => {
    const bm = parseBookmark(data);
    expect(bm.resolvedFromFormat).toBe("book");
  });

  it("decodes the path-components array exactly as encoded", () => {
    const bm = parseBookmark(data);
    expect(bookmarkGet(bm, kBookmarkPath)).toEqual(["Users", "analyst", "Desktop", "payload.exe"]);
  });

  it("decodes the CNID path as real inode numbers", () => {
    const bm = parseBookmark(data);
    expect(bookmarkGet(bm, kBookmarkCNIDPath)).toEqual([2, 100, 200, 300]);
  });

  it("decodes volume name, UUID (a plain string) and root flag", () => {
    const bm = parseBookmark(data);
    expect(bookmarkGet(bm, kBookmarkVolumeName)).toBe("Macintosh HD");
    expect(bookmarkGet(bm, kBookmarkVolumeUUID)).toBe("12345678-1234-1234-1234-123456789ABC");
    expect(bookmarkGet(bm, kBookmarkVolumeIsRoot)).toBe(true);
  });

  it("decodes displayName and wasFileReference", () => {
    const bm = parseBookmark(data);
    expect(bookmarkGet(bm, kBookmarkDisplayName)).toBe("payload.exe");
    expect(bookmarkGet(bm, kBookmarkWasFileReference)).toBe(true);
  });

  it("returns undefined for a key that was never in the TOC", () => {
    const bm = parseBookmark(data);
    expect(bookmarkGet(bm, 0xdead)).toBeUndefined();
  });
});

describe("parseBookmark — malformed/hostile input", () => {
  it("rejects a buffer with neither 'book' nor 'alis' magic", () => {
    const bad = Buffer.concat([Buffer.from("XXXX"), Buffer.alloc(20)]);
    expect(() => parseBookmark(bad)).toThrow(CfurlBookmarkError);
  });

  it("rejects a buffer too short to hold a header", () => {
    expect(() => parseBookmark(Buffer.from("book"))).toThrow(CfurlBookmarkError);
  });

  it("rejects a header whose declared size disagrees with the actual buffer length", () => {
    const data = buf(REAL_BOOKMARK_HEX);
    const crafted = Buffer.from(data);
    crafted.writeUInt32LE(999999, 4); // size field, byte offset 4
    expect(() => parseBookmark(crafted)).toThrow(CfurlBookmarkError);
  });

  it("rejects an hdrsize larger than the declared total size", () => {
    const data = buf(REAL_BOOKMARK_HEX);
    const crafted = Buffer.from(data);
    crafted.writeUInt32LE(crafted.length + 100, 12); // hdrsize field, byte offset 12
    expect(() => parseBookmark(crafted)).toThrow(CfurlBookmarkError);
  });

  it("detects a TOC-chain cycle rather than looping forever", () => {
    const data = buf(REAL_BOOKMARK_HEX);
    const crafted = Buffer.from(data);
    // The first TOC's own header lives at hdrsize + firstTocOffset. Its "next TOC offset" field is
    // the 4th uint32 in the 20-byte TOC header (offset +12 from the TOC base). Point it back at
    // itself to force a revisit.
    const hdrsize = crafted.readUInt32LE(12);
    const firstTocOffset = crafted.readUInt32LE(hdrsize);
    const tocBase = hdrsize + firstTocOffset;
    crafted.writeUInt32LE(firstTocOffset, tocBase + 12);
    expect(() => parseBookmark(crafted)).toThrow(CfurlBookmarkError);
  });
});
