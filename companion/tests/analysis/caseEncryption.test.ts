import { describe, it, expect } from "vitest";
import {
  encryptBuffer,
  decryptBuffer,
  readFormatVersion,
  CURRENT_FORMAT_VERSION,
  DecryptionError,
} from "../../src/analysis/caseEncryption.js";

describe("encryptBuffer / decryptBuffer", () => {
  it("round-trips arbitrary bytes", async () => {
    const data = Buffer.from("the quick brown fox jumps over the lazy dog", "utf8");
    const container = await encryptBuffer(data, "correct horse battery staple");
    const back = await decryptBuffer(container, "correct horse battery staple");
    expect(back.equals(data)).toBe(true);
  });

  it("produces different ciphertext for the same input on each call (random salt/IV)", async () => {
    const data = Buffer.from("same input", "utf8");
    const a = await encryptBuffer(data, "pw12345678");
    const b = await encryptBuffer(data, "pw12345678");
    expect(a.equals(b)).toBe(false);
  });

  it("throws DecryptionError on the wrong password", async () => {
    const container = await encryptBuffer(Buffer.from("secret data"), "correct-password");
    await expect(decryptBuffer(container, "wrong-password")).rejects.toThrow(DecryptionError);
  });

  it("throws DecryptionError on a tampered ciphertext", async () => {
    const container = await encryptBuffer(Buffer.from("secret data"), "correct-password");
    const tampered = Buffer.from(container);
    tampered[tampered.length - 1] ^= 0xff; // flip a byte at the end of the ciphertext
    await expect(decryptBuffer(tampered, "correct-password")).rejects.toThrow(DecryptionError);
  });

  it("throws DecryptionError on a buffer that isn't a .dfircase container", async () => {
    await expect(decryptBuffer(Buffer.from("not a dfircase file"), "any-password")).rejects.toThrow(
      DecryptionError,
    );
  });

  it("throws DecryptionError on a truncated container", async () => {
    const container = await encryptBuffer(Buffer.from("secret data"), "correct-password");
    await expect(decryptBuffer(container.subarray(0, 10), "correct-password")).rejects.toThrow(
      DecryptionError,
    );
  });

  it("handles empty input", async () => {
    const container = await encryptBuffer(Buffer.alloc(0), "pw12345678");
    expect((await decryptBuffer(container, "pw12345678")).length).toBe(0);
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

  it("still opens a v1 archive written before the scrypt bump", async () => {
    const back = await decryptBuffer(Buffer.from(V1_CONTAINER_HEX, "hex"), V1_PASSWORD);
    expect(back.toString("utf8")).toBe(V1_PLAINTEXT);
  });

  it("rejects a wrong password against a v1 archive", async () => {
    await expect(decryptBuffer(Buffer.from(V1_CONTAINER_HEX, "hex"), "wrong-password")).rejects.toThrow(
      DecryptionError,
    );
  });

  it("writes new archives in v2", async () => {
    const container = await encryptBuffer(Buffer.from("fresh export"), "pw12345678");
    expect(container.subarray(0, 8).toString("utf8")).toBe("DFIRCZ02");
  });

  it("reports an unknown (newer) container version as not a valid archive, not a wrong password", async () => {
    const fromTheFuture = await encryptBuffer(Buffer.from("written by a later build"), "pw12345678");
    Buffer.from("DFIRCZ99", "utf8").copy(fromTheFuture, 0);
    await expect(decryptBuffer(fromTheFuture, "pw12345678")).rejects.toThrow(
      /not a valid \.dfircase archive/,
    );
  });
  // readFormatVersion is what lets the import flow TELL the analyst the archive was written under
  // the weaker v1 derivation (#672). It reads the magic only — no password, no derivation — so it
  // must stay on the post-decryption path in the route; an endpoint that reported the version
  // before decrypting would let an unauthenticated caller sort a pile of archives by which ones
  // are cheapest to crack.
  it("reports version 1 for a v1 archive", () => {
    expect(readFormatVersion(Buffer.from(V1_CONTAINER_HEX, "hex"))).toBe(1);
  });

  it("reports version 2 for a freshly written archive", async () => {
    expect(readFormatVersion(await encryptBuffer(Buffer.from("fresh export"), "pw12345678"))).toBe(2);
  });

  it("CURRENT_FORMAT_VERSION is the version encryptBuffer actually writes", async () => {
    const container = await encryptBuffer(Buffer.from("fresh export"), "pw12345678");
    expect(readFormatVersion(container)).toBe(CURRENT_FORMAT_VERSION);
  });

  // A version older than the current one is always the weaker one: the module's rule is that an
  // existing version's parameters never change, so the ONLY way the cost is ever raised is by
  // adding a version. That makes "version < CURRENT_FORMAT_VERSION" a sound weakness test, and it
  // keeps working when a v3 arrives without anyone remembering to update the caller.
  it("orders versions so an older one is the weaker one", () => {
    expect(readFormatVersion(Buffer.from(V1_CONTAINER_HEX, "hex"))!).toBeLessThan(CURRENT_FORMAT_VERSION);
  });

  it("returns undefined for a buffer that isn't a .dfircase container", () => {
    expect(readFormatVersion(Buffer.from("not a dfircase file"))).toBeUndefined();
  });

  it("returns undefined for a container written by a newer build", async () => {
    const fromTheFuture = await encryptBuffer(Buffer.from("written by a later build"), "pw12345678");
    Buffer.from("DFIRCZ99", "utf8").copy(fromTheFuture, 0);
    expect(readFormatVersion(fromTheFuture)).toBeUndefined();
  });

  it("returns undefined for a truncated container", async () => {
    const container = await encryptBuffer(Buffer.from("secret data"), "correct-password");
    expect(readFormatVersion(container.subarray(0, 10))).toBeUndefined();
  });
});
