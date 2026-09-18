import { describe, it, expect } from "vitest";
import { parseBplist, BplistUid, BplistError, MAX_OBJECTS } from "../../src/analysis/bplistReader.js";

// Fixtures generated live via Python's own stdlib `plistlib.dumps(data, fmt=plistlib.FMT_BINARY)`
// — real bplist00 bytes, not hand-crafted, cross-validated by round-tripping through
// `plistlib.loads()` before capture. See RECOMMENDATION-12.md for the full research trail.

// { "$archiver": "NSKeyedArchiver", "flag": True, "hello": b"world", "num": 42 }
const SIMPLE_HEX =
  "62706c6973743030d401020304050607085924617263686976657254666c61675568656c6c6f536e756d5f100f4e534b6579656441726368697665720945776f726c64102a08111b20262a3c3d430000000000000101000000000000000900000000000000000000000000000045";

// Nested arrays/dicts/dates/unicode/large ints:
// {"arr": ["a","b","c", 12345678901234], "nested": {"x": [1,2,3], "y": datetime(2024,3,15,10,30,0)},
//  "unicode": "héllo wörld 中文", "bignum": 9007199254740993, "neg": -5}
const COMPLEX_HEX =
  "62706c6973743030d50102030405060b0c0d1553617272566269676e756d536e6567566e657374656457756e69636f6465a40708090a5161516251631300000b3a73ce2ff213002000000000000113fffffffffffffffbd20e0f101451785179a31112131001100210033341c5d22d540000006e006800e9006c006c006f0020007700f60072006c006400204e2d65870813171e22293136383a3c454e575c5e606466686a730000000000000101000000000000001600000000000000000000000000000090";

function buf(hex: string): Buffer {
  return Buffer.from(hex, "hex");
}

describe("parseBplist — real Python-generated fixtures", () => {
  it("decodes primitives, a Buffer for bytes, and bigint for an int", () => {
    const root = parseBplist(buf(SIMPLE_HEX));
    expect(root).toBeInstanceOf(Map);
    const m = root as Map<unknown, unknown>;
    expect(m.get("$archiver")).toBe("NSKeyedArchiver");
    expect(m.get("flag")).toBe(true);
    expect(m.get("num")).toBe(42n);
    const hello = m.get("hello");
    expect(Buffer.isBuffer(hello)).toBe(true);
    expect((hello as Buffer).toString("utf8")).toBe("world");
  });

  it("decodes nested arrays/dicts, a real Date, unicode UTF-16 strings, and large bigints without precision loss", () => {
    const root = parseBplist(buf(COMPLEX_HEX)) as Map<string, unknown>;
    const arr = root.get("arr") as unknown[];
    expect(arr[0]).toBe("a");
    expect(arr[3]).toBe(12345678901234n);
    expect(root.get("unicode")).toBe("héllo wörld 中文");
    expect(root.get("bignum")).toBe(9007199254740993n); // 2^53 + 1 — would round if passed through Number()
    expect(root.get("neg")).toBe(-5n);
    const nested = root.get("nested") as Map<string, unknown>;
    const y = nested.get("y");
    expect(y).toBeInstanceOf(Date);
    expect((y as Date).toISOString()).toBe("2024-03-15T10:30:00.000Z");
  });
});

describe("parseBplist — malformed/hostile input", () => {
  it("rejects a buffer with the wrong magic", () => {
    const bad = Buffer.concat([Buffer.from("not-a-plist"), Buffer.alloc(40)]);
    expect(() => parseBplist(bad)).toThrow(BplistError);
  });

  it("rejects a buffer too short to hold a trailer", () => {
    expect(() => parseBplist(Buffer.from("bplist00"))).toThrow(BplistError);
  });

  it("rejects a truncated file (real header, corrupted/short trailer)", () => {
    const real = buf(SIMPLE_HEX);
    const truncated = real.subarray(0, real.length - 20);
    expect(() => parseBplist(truncated)).toThrow(BplistError);
  });

  it("enforces the object-count budget rather than allocating an unbounded offset table", () => {
    const real = buf(SIMPLE_HEX);
    const trailer = Buffer.from(real.subarray(real.length - 32));
    // Overwrite numObjects (trailer bytes 8-15, big-endian uint64) with a value past the budget.
    trailer.writeBigUInt64BE(BigInt(MAX_OBJECTS + 1), 8);
    const crafted = Buffer.concat([real.subarray(0, real.length - 32), trailer]);
    expect(() => parseBplist(crafted)).toThrow(BplistError);
  });

  it("rejects a float type byte whose nibble is not exactly 2 or 3, never reads an arbitrary-length region", () => {
    // Hand-crafted: a single object at offset 8, type byte 0x25 (float, nibble 5 -- invalid; only
    // 2 and 3 are real). Ollama code review finding: the un-fixed code computed len = 2**5 = 32 and
    // happily read 32 bytes as if it were a valid float record.
    const crafted = buf(
      "62706c6973743030250000000000000000000000000000000000000000000000000000000000000000080000000000000101000000000000000100000000000000000000000000000029",
    );
    expect(() => parseBplist(crafted)).toThrow(/invalid float nibble/);
  });

  it("rejects a UID pointing past the real object table (validated at the bplist layer itself)", () => {
    // Hand-crafted: a single object at offset 8, a UID (type 0x81) whose value is 99, but the file
    // declares only 1 real object.
    const crafted = buf(
      "62706c697374303081006308000000000000010100000000000000010000000000000000000000000000000b",
    );
    expect(() => parseBplist(crafted)).toThrow(/uid.*out of range/i);
  });

  it("rejects a finite-but-out-of-range date (huge secs -> Invalid Date), never returns it (#1190)", () => {
    // Hand-crafted: a single date object (type 0x33) at offset 8, secs = 1e300 -- finite, but the
    // resulting Date is out of JS's representable range (Invalid Date).
    const crafted = buf(
      "62706c6973743030337e37e43c8800759c080000000000000101000000000000000100000000000000000000000000000011",
    );
    expect(() => parseBplist(crafted)).toThrow(/out of representable range/);
  });

  it("rejects an offset-table entry that points at the offset table itself rather than real object data", () => {
    // Hand-crafted: a single valid null object at offset 8, but the offset-table entry is crafted
    // to point at the table's own offset (9) instead of the real object (8).
    const crafted = buf(
      "62706c697374303000090000000000000101000000000000000100000000000000000000000000000009",
    );
    expect(() => parseBplist(crafted)).toThrow(/offset table entry points outside/);
  });
});

describe("BplistUid", () => {
  it("is a distinct tagged type, never conflated with a plain number", () => {
    const uid = new BplistUid(5);
    expect(uid).toBeInstanceOf(BplistUid);
    expect(uid.value).toBe(5);
    expect(typeof uid).not.toBe("number");
  });
});
