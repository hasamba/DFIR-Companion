import { describe, it, expect } from "vitest";
import { encryptBuffer, decryptBuffer, DecryptionError } from "../../src/analysis/caseEncryption.js";

describe("encryptBuffer / decryptBuffer", () => {
  it("round-trips arbitrary bytes", () => {
    const data = Buffer.from("the quick brown fox jumps over the lazy dog", "utf8");
    const container = encryptBuffer(data, "correct horse battery staple");
    const back = decryptBuffer(container, "correct horse battery staple");
    expect(back.equals(data)).toBe(true);
  });

  it("produces different ciphertext for the same input on each call (random salt/IV)", () => {
    const data = Buffer.from("same input", "utf8");
    const a = encryptBuffer(data, "pw12345678");
    const b = encryptBuffer(data, "pw12345678");
    expect(a.equals(b)).toBe(false);
  });

  it("throws DecryptionError on the wrong password", () => {
    const container = encryptBuffer(Buffer.from("secret data"), "correct-password");
    expect(() => decryptBuffer(container, "wrong-password")).toThrow(DecryptionError);
  });

  it("throws DecryptionError on a tampered ciphertext", () => {
    const container = encryptBuffer(Buffer.from("secret data"), "correct-password");
    const tampered = Buffer.from(container);
    tampered[tampered.length - 1] ^= 0xff; // flip a byte at the end of the ciphertext
    expect(() => decryptBuffer(tampered, "correct-password")).toThrow(DecryptionError);
  });

  it("throws DecryptionError on a buffer that isn't a .dfircase container", () => {
    expect(() => decryptBuffer(Buffer.from("not a dfircase file"), "any-password")).toThrow(DecryptionError);
  });

  it("throws DecryptionError on a truncated container", () => {
    const container = encryptBuffer(Buffer.from("secret data"), "correct-password");
    expect(() => decryptBuffer(container.subarray(0, 10), "correct-password")).toThrow(DecryptionError);
  });

  it("handles empty input", () => {
    const container = encryptBuffer(Buffer.alloc(0), "pw12345678");
    expect(decryptBuffer(container, "pw12345678").length).toBe(0);
  });
});
