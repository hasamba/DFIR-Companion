import { describe, it, expect } from "vitest";
import { computeContentHash } from "../../src/dedup/contentHash.js";

describe("computeContentHash", () => {
  it("returns a 64-char hex SHA-256 string", () => {
    expect(computeContentHash(Buffer.from("hello"))).toMatch(/^[0-9a-f]{64}$/);
  });

  it("is identical for byte-identical input", () => {
    const a = computeContentHash(Buffer.from([1, 2, 3, 4, 5]));
    const b = computeContentHash(Buffer.from([1, 2, 3, 4, 5]));
    expect(a).toBe(b);
  });

  it("differs for a single-byte change (exact match — any difference is not a duplicate)", () => {
    const a = computeContentHash(Buffer.from([1, 2, 3, 4, 5]));
    const b = computeContentHash(Buffer.from([1, 2, 3, 4, 6]));
    expect(a).not.toBe(b);
  });
});
