import { describe, it, expect } from "vitest";
import { createZip } from "../../src/analysis/zipArchive.js";
import { candidatePasswords, extractZipEntries, MAX_ZIP_ENTRIES } from "../../src/analysis/zipExtract.js";
import { ZipAuthenticationError } from "../../src/analysis/zipCrypto.js";

const ZC_ZIP_B64 =
  "UEsDBAoACQAAAGWB/VzrJ0KsIwAAABcAAAAKABwAc2FtcGxlLmJpblVUCQAD7vtpau77aWp1eAsAAQToAwAABOgDAACSY93uO3OX" +
  "/aoYARCx5Jfbd3EGx/7tlqbVxQgzvT21C/Kx6FBLBwjrJ0KsIwAAABcAAABQSwECHgMKAAkAAABlgf1c6ydCrCMAAAAXAAAACgAY" +
  "AAAAAAABAAAAtIEAAAAAc2FtcGxlLmJpblVUBQAD7vtpanV4CwABBOgDAAAE6AMAAFBLBQYAAAAAAQABAFAAAAB3AAAAAAA=";

// `zip -P s3cret custom.zip secret.bin` — a password NOT in the default ladder, holding the
// 24-byte file "custom password payload\n". This is the fixture that proves custom passwords work,
// which is the one thing the SO-CRATES API can never do.
const CUSTOM_ZIP_B64 =
  "UEsDBAoACQAAAO2C/Vx7BJ0tJAAAABgAAAAKABwAc2VjcmV0LmJpblVUCQADzf5pas3+aWp1eAsAAQToAwAABOgDAACQ7YfTxb3j" +
  "gnkcB9RnjbnCiwID4RlVYqmQgwa8AzOEfM/SLxRQSwcIewSdLSQAAAAYAAAAUEsBAh4DCgAJAAAA7YL9XHsEnS0kAAAAGAAAAAoA" +
  "GAAAAAAAAQAAALSBAAAAAHNlY3JldC5iaW5VVAUAA83+aWp1eAsAAQToAwAABOgDAABQSwUGAAAAAAEAAQBQAAAAeAAAAAAA";

// 7-Zip: `7z a -tzip -pinfected -mem=AES256 aes.zip sample.bin` — AE-2, STORED, 23 bytes.
const AES_ZIP_B64 =
  "UEsDBDMAAQBjAGaB/VwAAAAAMwAAABcAAAAKAAsAc2FtcGxlLmJpbgGZBwACAEFFAwAAjSVbocfmvx3PE5161dsvWZeAGwRMGhH+" +
  "U3dNZiO2mA/QMCMLIAwEGRmcHEdlOo1WBP7zUEsBAj8DMwABAGMAZoH9XAAAAAAzAAAAFwAAAAoALwAAAAAAAAAggLSBAAAAAHNh" +
  "bXBsZS5iaW4KACAAAAAAAAEAGAC4I7e5Wx/dAQAAAAAAAAAAAAAAAAAAAAABmQcAAgBBRQMAAFBLBQYAAAAAAQABAGcAAABmAAAA" +
  "AAA=";

describe("candidatePasswords", () => {
  it("defaults to infected when nothing is supplied", () => {
    expect(candidatePasswords("sample.zip")).toEqual(["infected"]);
  });

  it("puts the supplied password first, keeping infected as a fallback", () => {
    expect(candidatePasswords("sample.zip", "hunter2")).toEqual(["hunter2", "infected"]);
  });

  it("derives the dated MTA-style password from a date in the filename", () => {
    // malware-traffic-analysis.net convention, which SO-CRATES also follows.
    expect(candidatePasswords("2026-02-03-traffic.zip")).toEqual(["infected", "infected_20260203"]);
  });

  it("does not duplicate infected when it is also the supplied password", () => {
    expect(candidatePasswords("sample.zip", "infected")).toEqual(["infected"]);
  });
});

describe("extractZipEntries", () => {
  it("opens a ZipCrypto archive with the default password", () => {
    const res = extractZipEntries(Buffer.from(ZC_ZIP_B64, "base64"), "zc.zip");
    expect(res.passwordUsed).toBe("infected");
    expect(res.entries.map((e) => e.path)).toEqual(["sample.bin"]);
  });

  it("keeps every file entry rather than only the first", () => {
    const archive = createZip([
      { path: "a.bin", data: Buffer.from("aaa") },
      { path: "b.bin", data: Buffer.from("bbb") },
      { path: "c.bin", data: Buffer.from("ccc") },
    ]);
    const res = extractZipEntries(archive, "bundle.zip");
    expect(res.entries.map((e) => e.path)).toEqual(["a.bin", "b.bin", "c.bin"]);
    expect(res.passwordUsed).toBeNull();
  });

  it("drops directory entries, dotfiles, and __MACOSX metadata", () => {
    const archive = createZip([
      { path: "payload/", data: Buffer.alloc(0) },
      { path: "payload/evil.exe", data: Buffer.from("MZ") },
      { path: ".DS_Store", data: Buffer.from("junk") },
      { path: "__MACOSX/._evil.exe", data: Buffer.from("junk") },
    ]);
    expect(extractZipEntries(archive, "b.zip").entries.map((e) => e.path)).toEqual(["payload/evil.exe"]);
  });

  it("rejects zip-slip paths", () => {
    const archive = createZip([{ path: "../../etc/passwd", data: Buffer.from("x") }]);
    expect(() => extractZipEntries(archive, "evil.zip")).toThrow(/outside the archive/i);
  });

  it("reports nested zips instead of recursing into them", () => {
    const inner = createZip([{ path: "deep.bin", data: Buffer.from("d") }]);
    const archive = createZip([
      { path: "outer.bin", data: Buffer.from("o") },
      { path: "inner.zip", data: inner },
    ]);
    const res = extractZipEntries(archive, "nest.zip");
    expect(res.entries.map((e) => e.path)).toEqual(["outer.bin"]);
    expect(res.skippedNested).toEqual(["inner.zip"]);
  });

  it("caps the entry count and flags truncation", () => {
    const many = Array.from({ length: MAX_ZIP_ENTRIES + 5 }, (_, i) => ({
      path: `f${i}.bin`, data: Buffer.from(String(i)),
    }));
    const res = extractZipEntries(createZip(many), "many.zip");
    expect(res.entries).toHaveLength(MAX_ZIP_ENTRIES);
    expect(res.truncated).toBe(true);
  });

  it("opens an archive whose password is NOT in the default ladder", () => {
    // The whole point of the feature: SO-CRATES can only ever try `infected`.
    const res = extractZipEntries(Buffer.from(CUSTOM_ZIP_B64, "base64"), "custom.zip", "s3cret");
    expect(res.passwordUsed).toBe("s3cret");
    expect(res.entries[0].data.toString("utf8")).toBe("custom password payload\n");
  });

  it("falls back to infected when the supplied password is wrong", () => {
    // Deliberate: a typo in the password box should not fail an archive that infected opens.
    const res = extractZipEntries(Buffer.from(ZC_ZIP_B64, "base64"), "zc.zip", "typo");
    expect(res.passwordUsed).toBe("infected");
  });

  it("reports a wrong password once every candidate fails", () => {
    // Nothing in the ladder opens this one, so the analyst gets an actionable error.
    expect(() => extractZipEntries(Buffer.from(CUSTOM_ZIP_B64, "base64"), "custom.zip"))
      .toThrow(/password/i);
  });

  // #428: this is the evidence-ingestion entry point, and the password ladder is where a tamper
  // signal would go missing. ZipAuthenticationError is deliberately not a ZipPasswordError, so the
  // loop stops on the first candidate and reports the modification instead of walking the rest of
  // the ladder and blaming the password.
  it("surfaces AES tampering as tampering, not as 'wrong password (tried N passwords)'", () => {
    const archive = Buffer.from(AES_ZIP_B64, "base64");
    let eocd = -1;
    for (let i = archive.length - 22; i >= 0; i--) {
      if (archive.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
    }
    const central = archive.readUInt32LE(eocd + 16);
    const localOffset = archive.readUInt32LE(central + 42);
    const dataStart = localOffset + 30 + archive.readUInt16LE(localOffset + 26) + archive.readUInt16LE(localOffset + 28);
    archive[dataStart + 16 + 2 + 5] ^= 0x20;   // past salt + verifier, into the ciphertext

    expect(() => extractZipEntries(archive, "aes.zip")).toThrow(ZipAuthenticationError);
    expect(() => extractZipEntries(archive, "aes.zip")).toThrow(/modified/i);
  });
});
