import { describe, it, expect } from "vitest";
import { normalizeHash, parseNsrlText, nsrlMatchIocs, nsrlMatchEvents } from "../../src/analysis/nsrl.js";
import type { ForensicEvent, IOC } from "../../src/analysis/stateTypes.js";

const MD5 = "d41d8cd98f00b204e9800998ecf8427e";   // empty-file MD5
const SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"; // empty-file SHA-1
const SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"; // empty-file SHA-256

describe("normalizeHash", () => {
  it("accepts MD5 / SHA-1 / SHA-256, lowercasing and stripping 0x + whitespace", () => {
    expect(normalizeHash("  D41D8CD98F00B204E9800998ECF8427E ")).toBe(MD5);
    expect(normalizeHash("0x" + SHA1.toUpperCase())).toBe(SHA1);
    expect(normalizeHash(SHA256)).toBe(SHA256);
  });
  it("rejects non-hashes (CRC32, sizes, names, wrong length, non-hex)", () => {
    expect(normalizeHash("ffffffff")).toBeNull();         // 8 hex (CRC32) — wrong length
    expect(normalizeHash("12345")).toBeNull();
    expect(normalizeHash("kernel32.dll")).toBeNull();
    expect(normalizeHash("g".repeat(32))).toBeNull();     // right length, not hex
    expect(normalizeHash("")).toBeNull();
  });
});

describe("parseNsrlText", () => {
  it("parses an NSRLFile.txt-style RDS CSV, pulling SHA-1 + MD5 columns (not CRC32/size)", () => {
    const csv =
      '"SHA-1","MD5","CRC32","FileName","FileSize","ProductCode","OpSystemCode","SpecialCode"\n' +
      `"${SHA1.toUpperCase()}","${MD5.toUpperCase()}","00000000","empty.txt","0","1","2",""\n`;
    const hashes = parseNsrlText(csv);
    expect(hashes.sort()).toEqual([MD5, SHA1].sort());
    expect(hashes).not.toContain("00000000");
  });

  it("parses a plain hash-per-line list and a comma-separated list, deduping", () => {
    expect(parseNsrlText(`${MD5}\n${SHA256}\n${MD5}\n`).sort()).toEqual([MD5, SHA256].sort());
    expect(parseNsrlText(`${MD5}, ${SHA1} , ${MD5}`).sort()).toEqual([MD5, SHA1].sort());
  });

  it("scans tokens out of a JSON-ish dump and ignores junk", () => {
    const hashes = parseNsrlText(`{ "sha256": "${SHA256}", "name": "thing.exe", "size": 1024 }`);
    expect(hashes).toEqual([SHA256]);
  });

  it("returns [] for empty / hash-free input", () => {
    expect(parseNsrlText("")).toEqual([]);
    expect(parseNsrlText("no hashes here, just words")).toEqual([]);
  });
});

describe("nsrlMatchIocs", () => {
  const iocs: IOC[] = [
    { id: "i1", type: "hash", value: MD5.toUpperCase(), firstSeen: "2026-01-01T00:00:00Z" }, // known-good (case-insensitive)
    { id: "i2", type: "hash", value: "abc123", firstSeen: "2026-01-01T00:00:00Z" },           // not a valid hash → skip
    { id: "i3", type: "ip", value: MD5, firstSeen: "2026-01-01T00:00:00Z" },                  // not a hash IOC → skip
    { id: "i4", type: "hash", value: SHA256, firstSeen: "2026-01-01T00:00:00Z" },             // not in set
  ];
  it("matches only hash IOCs whose value is in the set", () => {
    const out = nsrlMatchIocs(iocs, new Set([MD5]));
    expect(out.map((m) => m.ioc.id)).toEqual(["i1"]);
    expect(out[0].hash).toBe(MD5);
  });
  it("returns [] for an empty set", () => {
    expect(nsrlMatchIocs(iocs, new Set())).toEqual([]);
  });
});

describe("nsrlMatchEvents", () => {
  const base = { description: "f", severity: "High" as const, mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [] };
  const events: ForensicEvent[] = [
    { id: "e1", timestamp: "t", ...base, sha256: SHA256.toUpperCase() },  // known-good by sha256
    { id: "e2", timestamp: "t", ...base, md5: MD5 },                      // known-good by md5
    { id: "e3", timestamp: "t", ...base, sha256: "f".repeat(64) },        // unknown
    { id: "e4", timestamp: "t", ...base },                                // no hash
  ];
  it("matches events whose sha256 or md5 is known-good", () => {
    const out = nsrlMatchEvents(events, new Set([SHA256, MD5]));
    expect(out.map((m) => m.event.id).sort()).toEqual(["e1", "e2"]);
  });
  it("prefers the sha256 match and falls back to md5", () => {
    const out = nsrlMatchEvents([{ id: "e5", timestamp: "t", ...base, sha256: SHA256, md5: MD5 }], new Set([MD5]));
    expect(out).toHaveLength(1);
    expect(out[0].hash).toBe(MD5); // sha256 not in set, md5 is
  });
  it("also accepts a lookup predicate (the SQLite-RDS / union backend form)", () => {
    const lookup = (h: string): boolean => h === SHA256;     // pretend-DB: only this sha256 is known-good
    const out = nsrlMatchEvents(events, lookup);
    expect(out.map((m) => m.event.id)).toEqual(["e1"]);
    expect(nsrlMatchIocs([{ id: "i", type: "hash", value: SHA256, firstSeen: "t" }], lookup)).toHaveLength(1);
  });
});
