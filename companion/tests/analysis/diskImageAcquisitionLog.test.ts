// #1102: full-disk-image acquisition/verification logs (FTK Imager, dc3dd), read as disclosure-
// only facts — never wired into refutationGate.ts (see canonicalDiskImage.ts's own header).
import { describe, it, expect } from "vitest";
import {
  isFtkImagerLog,
  isDc3ddLog,
  isDiskImageLog,
  parseFtkImagerLog,
  parseDc3ddLog,
  parseDiskImageLog,
} from "../../src/analysis/diskImageAcquisitionLog.js";
import { canonicalEventEnvelopeSchema } from "../../src/analysis/canonicalEvent.js";

const env = (e: { canonical?: unknown }) => canonicalEventEnvelopeSchema.parse(e.canonical);

const MD5_A = "aabbccddeeff00112233445566778899";
const SHA1_A = "aabbccddeeff00112233445566778899aabbccdd";

function ftkLog(
  opts: {
    verifiedMd5?: boolean;
    verifiedSha1?: boolean;
    md5Verify?: string;
    sha1Verify?: string;
    readError?: boolean;
  } = {},
): string {
  const {
    verifiedMd5 = true,
    verifiedSha1 = true,
    md5Verify = MD5_A,
    sha1Verify = SHA1_A,
    readError = false,
  } = opts;
  return `Created By AccessData(r) FTK(r) Imager 4.7.1.2

Case Information:
Case Number:
Evidence Number:
Examiner: J. Analyst

--------------------------------------------------------------------

Drive Geometry:
Cylinders: 4177
Tracks per Cylinder: 255
Sectors per Track: 63
Bytes per Sector: 512
Sector Count: 67108864

Image Information:
Acquisition started: Mon Jan 12 10:00:00 2026
Acquisition finished: Mon Jan 12 11:30:00 2026

Computed Hashes:
MD5 checksum: ${MD5_A}
SHA1 checksum: ${SHA1_A}
${readError ? "\nATTENTION: This image is incomplete!\nThe following sector(s) on the source drive could not be read: 0 through 10790911\n" : ""}
Image Verification Results:
Verification started: Mon Jan 12 11:30:05 2026
Verification finished: Mon Jan 12 11:45:00 2026
MD5 checksum: ${md5Verify} : ${verifiedMd5 ? "verified" : "does not match"}
SHA1 checksum: ${sha1Verify} : ${verifiedSha1 ? "verified" : "does not match"}
`;
}

const SHA256_A = "3b1e196c000000000000000000000000000000000000000000000000000000a1";

function dc3ddLog(opts: { outputHash?: string } = {}): string {
  const outputHashLine = opts.outputHash ? `\n   ${opts.outputHash} (sha256)` : "";
  return `dc3dd 7.2.646 started at 2026-01-12 10:00:00 -0500
compiled options:
command line: dc3dd if=/dev/sda hash=sha256 of=/images/disk.img log=disk.log

input results for file \`/dev/sda':
   1953525168 sectors + 512 bytes in
   ${SHA256_A} (sha256)

output results for file \`/images/disk.img':
   1953525168 sectors + 512 bytes out${outputHashLine}

dc3dd completed at 2026-01-12 12:00:00 -0500
`;
}

const MD5_DEVICE = "248c65b1d5d0fb63c8b35dd411cc3ed8";
const SHA256_DEVICE = "3a015e8c91a982c2629d037431953521b9daad811916436b807e2efd0aaef0fd";

// A real captured physical-device run (securitynik.com, /dev/sdb) — "device", not "file", no "+ M
// bytes" remainder clause, two hash algorithms, and dc3dd's own "[ok]"/bad-sectors disclosure.
function dc3ddDeviceLog(opts: { badSectors?: number; secondOutputHash?: string } = {}): string {
  const { badSectors = 0, secondOutputHash } = opts;
  const secondOutput = secondOutputHash
    ? `\n\noutput results for file \`/cases/second-copy.img':\n   62914560 sectors out\n   [${secondOutputHash === MD5_DEVICE ? "ok" : "??"}] ${secondOutputHash} (md5)`
    : "";
  return `dc3dd 7.2.646 started at 2026-01-12 10:00:00 -0500

input results for device \`/dev/sdb':
   62914560 sectors in
   ${badSectors} bad sectors replaced by zeros
   ${MD5_DEVICE} (md5)
   ${SHA256_DEVICE} (sha256)

output results for file \`/cases/nik-usb-sdb.img':
   62914560 sectors out
   [ok] ${MD5_DEVICE} (md5)
   [ok] ${SHA256_DEVICE} (sha256)${secondOutput}

dc3dd completed at 2026-01-12 12:00:00 -0500
`;
}

describe("isFtkImagerLog / isDc3ddLog — full-signature detection", () => {
  it("requires both FTK section labels", () => {
    expect(isFtkImagerLog(ftkLog())).toBe(true);
    expect(isFtkImagerLog("Case Information:\nsomething else")).toBe(false);
    expect(isFtkImagerLog("random text")).toBe(false);
  });

  it("requires both dc3dd result-block labels", () => {
    expect(isDc3ddLog(dc3ddLog())).toBe(true);
    expect(isDc3ddLog("input results for file `x': 1 sectors")).toBe(false);
  });

  it("isDiskImageLog matches either", () => {
    expect(isDiskImageLog(ftkLog())).toBe(true);
    expect(isDiskImageLog(dc3ddLog())).toBe(true);
    expect(isDiskImageLog("plain syslog line")).toBe(false);
  });
});

describe("parseFtkImagerLog", () => {
  it("verified: exact 'verified' text AND matching digests for both algorithms", () => {
    const result = parseFtkImagerLog(ftkLog());
    expect(result).not.toBeNull();
    const block = env(result!.events[0]).diskImageAcquisition!;
    expect(block.tool).toBe("ftk-imager");
    expect(block.verificationStatus).toBe("verified");
    expect(block.sectorCount).toBe(67108864);
    expect(block.readErrorsDetected).toBe(false);
    expect(result!.events[0].severity).toBe("Info");
    expect(block.hashes).toEqual(
      expect.arrayContaining([
        { algorithm: "md5", digest: MD5_A, phase: "acquisition" },
        { algorithm: "md5", digest: MD5_A, phase: "verification" },
      ]),
    );
  });

  it("unrecognized: verification text is not the exact word 'verified'", () => {
    const result = parseFtkImagerLog(ftkLog({ verifiedMd5: false }));
    const block = env(result!.events[0]).diskImageAcquisition!;
    expect(block.verificationStatus).toBe("unrecognized");
    expect(block.unrecognizedVerificationText).toMatch(/does not match/);
    expect(result!.events[0].severity).toBe("Medium");
  });

  it("unrecognized: text says verified but the digest itself differs — never trusted on the word alone", () => {
    const result = parseFtkImagerLog(ftkLog({ md5Verify: "00000000000000000000000000000000" }));
    const block = env(result!.events[0]).diskImageAcquisition!;
    expect(block.verificationStatus).toBe("unrecognized");
  });

  it("read errors detected: forces High severity regardless of a verified hash", () => {
    const result = parseFtkImagerLog(ftkLog({ readError: true }));
    const block = env(result!.events[0]).diskImageAcquisition!;
    expect(block.verificationStatus).toBe("verified");
    expect(block.readErrorsDetected).toBe(true);
    expect(block.readErrorRange).toBe("0 through 10790911");
    expect(result!.events[0].severity).toBe("High");
  });

  it("returns null for text that doesn't match the FTK signature", () => {
    expect(parseFtkImagerLog("not an ftk log")).toBeNull();
  });

  it("unrecognized: a verification section present but missing a result for one of the two acquired algorithms", () => {
    const withoutSha1Verification = ftkLog().replace(`SHA1 checksum: ${SHA1_A} : verified`, "");
    const result = parseFtkImagerLog(withoutSha1Verification);
    const block = env(result!.events[0]).diskImageAcquisition!;
    expect(block.verificationStatus).toBe("unrecognized");
    expect(block.unrecognizedVerificationText).toMatch(/no matching verification result/);
    expect(result!.events[0].severity).toBe("Medium");
  });

  it("unrecognized: an invalid-length digest is never accepted, even if the line says 'verified'", () => {
    const shortDigest = MD5_A.slice(0, 20);
    const result = parseFtkImagerLog(
      ftkLog({ md5Verify: shortDigest }).replace(
        `MD5 checksum: ${MD5_A}\n`,
        `MD5 checksum: ${shortDigest}\n`,
      ),
    );
    const block = env(result!.events[0]).diskImageAcquisition!;
    expect(block.verificationStatus).toBe("unrecognized");
  });

  it("basis sentence is the fixed, never-comparable-to-per-file-hash disclosure", () => {
    const result = parseFtkImagerLog(ftkLog());
    const block = env(result!.events[0]).diskImageAcquisition!;
    expect(block.basis).toMatch(/whole acquired evidence stream/);
    expect(block.basis).toMatch(/never a per-file content hash/);
  });
});

describe("parseDc3ddLog", () => {
  it("not-performed: plain of= run, only an input hash, no output hash to compare", () => {
    const result = parseDc3ddLog(dc3ddLog());
    expect(result).not.toBeNull();
    const block = env(result!.events[0]).diskImageAcquisition!;
    expect(block.tool).toBe("dc3dd");
    expect(block.verificationStatus).toBe("not-performed");
    expect(block.sectorCount).toBe(1953525168);
    expect(block.remainderBytes).toBe(512);
    expect(block.sourcePath).toBe("/dev/sda");
    expect(block.outputPath).toBe("/images/disk.img");
    expect(result!.events[0].severity).toBe("Info");
  });

  it("verified: an output hash (hof=/hofs=/fhod= run) equal to the input hash", () => {
    const result = parseDc3ddLog(dc3ddLog({ outputHash: SHA256_A }));
    const block = env(result!.events[0]).diskImageAcquisition!;
    expect(block.verificationStatus).toBe("verified");
    expect(result!.events[0].severity).toBe("Info");
  });

  it("unrecognized: a present but different output hash — never inferred as a match or a real mismatch", () => {
    const differentHash = "0000000000000000000000000000000000000000000000000000000000000f00";
    const result = parseDc3ddLog(dc3ddLog({ outputHash: differentHash }));
    const block = env(result!.events[0]).diskImageAcquisition!;
    expect(block.verificationStatus).toBe("unrecognized");
    expect(block.unrecognizedVerificationText).toMatch(new RegExp(differentHash));
    expect(result!.events[0].severity).toBe("Medium");
  });

  it("returns null for text that doesn't match the dc3dd signature", () => {
    expect(parseDc3ddLog("not a dc3dd log")).toBeNull();
  });

  it("a real physical-device run ('device', not 'file') is detected and verified across two hash algorithms", () => {
    expect(isDc3ddLog(dc3ddDeviceLog())).toBe(true);
    const result = parseDc3ddLog(dc3ddDeviceLog());
    expect(result).not.toBeNull();
    const block = env(result!.events[0]).diskImageAcquisition!;
    expect(block.verificationStatus).toBe("verified");
    expect(block.sourcePath).toBe("/dev/sdb");
    expect(block.sectorCount).toBe(62914560);
    expect(block.remainderBytes).toBeUndefined();
    expect(block.readErrorsDetected).toBe(false);
    expect(result!.events[0].severity).toBe("Info");
  });

  it("bad sectors replaced by zeros forces readErrorsDetected + High severity even though hashes still match", () => {
    const result = parseDc3ddLog(dc3ddDeviceLog({ badSectors: 42 }));
    const block = env(result!.events[0]).diskImageAcquisition!;
    expect(block.verificationStatus).toBe("verified");
    expect(block.readErrorsDetected).toBe(true);
    expect(result!.events[0].severity).toBe("High");
  });

  it("multiple outputs: one verified output cannot hide a second, mismatched one", () => {
    const differentHash = "0000000000000000000000000000000000000000000000000000000000000f00".slice(0, 64);
    const result = parseDc3ddLog(dc3ddDeviceLog({ secondOutputHash: differentHash }));
    const block = env(result!.events[0]).diskImageAcquisition!;
    expect(block.verificationStatus).toBe("unrecognized");
    expect(result!.events[0].severity).toBe("Medium");
  });

  it("a truncated/invalid-length digest is never accepted as a valid match, even if present", () => {
    const result = parseDc3ddLog(dc3ddLog({ outputHash: SHA256_A.slice(0, 40) }));
    const block = env(result!.events[0]).diskImageAcquisition!;
    // A present-but-wrong-length "sha256" digest is a malformed line, not "nothing to compare" —
    // it must never silently downgrade to the unalarming "not-performed" status.
    expect(block.verificationStatus).toBe("unrecognized");
  });
});

describe("parseDiskImageLog — dispatches to whichever tool's signature matches", () => {
  it("routes an FTK Imager log", () => {
    const result = parseDiskImageLog(ftkLog());
    expect(env(result!.events[0]).diskImageAcquisition!.tool).toBe("ftk-imager");
  });

  it("routes a dc3dd log", () => {
    const result = parseDiskImageLog(dc3ddLog());
    expect(env(result!.events[0]).diskImageAcquisition!.tool).toBe("dc3dd");
  });

  it("returns null for neither", () => {
    expect(parseDiskImageLog("plain text, no signature")).toBeNull();
  });
});
