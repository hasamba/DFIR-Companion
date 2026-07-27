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

describe("container versioning", () => {
  // A real v1 container, frozen as hex: magic DFIRCZ01, fixed salt/IV, key derived with the
  // scrypt parameters the 0.31.0 writer used (Node's defaults). Generated OUTSIDE this module so
  // it stays a genuine regression vector — if the v1 parameters are ever changed, or v1 dropped
  // from the read path, this test fails instead of the archives in an analyst's evidence store.
  // The delete-with-encrypted-archive flow deletes the case folder after writing the archive, so
  // for some cases a v1 .dfircase is the only copy that exists.
  const V1_PASSWORD = "correct horse battery staple";
  const V1_PLAINTEXT = "v1 archive written before #268";
  const V1_CONTAINER_HEX =
    "44464952435a30310123456789abcdef0123456789abcdeffedcba9876543210fedcba98" +
    "8d43145e792b5fe7931961f60a9c76f3fae0a2d211d264e4b5978fc8fdb983adfb852092e70093b5619619c2525d";

  it("still opens a v1 archive written before the scrypt bump", () => {
    const back = decryptBuffer(Buffer.from(V1_CONTAINER_HEX, "hex"), V1_PASSWORD);
    expect(back.toString("utf8")).toBe(V1_PLAINTEXT);
  });

  it("rejects a wrong password against a v1 archive", () => {
    expect(() => decryptBuffer(Buffer.from(V1_CONTAINER_HEX, "hex"), "wrong-password")).toThrow(DecryptionError);
  });

  it("writes new archives in v2", () => {
    const container = encryptBuffer(Buffer.from("fresh export"), "pw12345678");
    expect(container.subarray(0, 8).toString("utf8")).toBe("DFIRCZ02");
  });

  it("reports an unknown (newer) container version as not a valid archive, not a wrong password", () => {
    const fromTheFuture = encryptBuffer(Buffer.from("written by a later build"), "pw12345678");
    Buffer.from("DFIRCZ99", "utf8").copy(fromTheFuture, 0);
    expect(() => decryptBuffer(fromTheFuture, "pw12345678")).toThrow(/not a valid \.dfircase archive/);
  });
});
