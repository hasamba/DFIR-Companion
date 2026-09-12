// #932 item 3 — NTFS alternate data streams: a download mark is not a hidden payload.
import { describe, expect, it } from "vitest";
import {
  APPLICATION_STREAMS,
  CONTENT_NOTE,
  parseZoneMark,
  PROVENANCE_NOTE,
  readHost,
  readStream,
  splitStream,
  streamFlag,
  validHash,
} from "../../src/analysis/ntfsStreams.js";
import { gradeMotwDownload } from "../../src/analysis/motwDownload.js";

const HOST = "C:\\Users\\bob\\Documents\\notes.txt";
const MARK =
  "[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://files.example.invalid/a.exe\r\nReferrerUrl=https://example.invalid/\r\n\u0000";

describe("splitStream — the grammar", () => {
  it("a drive letter's colon is never a stream; the stream follows the first colon after the last separator", () => {
    expect(splitStream("C:\\Users\\bob\\notes.txt")).toEqual({
      hostPath: "C:\\Users\\bob\\notes.txt",
      stream: "",
    });
    expect(splitStream("C:")).toEqual({ hostPath: "C:", stream: "" });
    expect(splitStream(`${HOST}:payload.dll`)).toEqual({ hostPath: HOST, stream: "payload.dll" });
    expect(splitStream(`${HOST}:Zone.Identifier:$DATA`)).toEqual({
      hostPath: HOST,
      stream: "Zone.Identifier",
    });
    expect(splitStream("notes.txt:data")).toEqual({ hostPath: "notes.txt", stream: "data" });
    expect(splitStream("/mnt/c/dir:with:colons/file.txt")).toEqual({
      hostPath: "/mnt/c/dir:with:colons/file.txt",
      stream: "",
    });
    expect(splitStream(`${HOST}:`)).toEqual({ hostPath: HOST, stream: "" });
  });
});

describe("parseZoneMark — the [ZoneTransfer] text", () => {
  it("reads ZoneId, HostUrl and ReferrerUrl through CRLF, NUL and a flattened line", () => {
    expect(parseZoneMark(MARK)).toEqual({
      zone: "3",
      url: "https://files.example.invalid/a.exe",
      referrer: "https://example.invalid/",
    });
    expect(parseZoneMark("[ZoneTransfer]  ZoneId=3  HostUrl=https://x.example.invalid/f")).toEqual({
      zone: "3",
      url: "https://x.example.invalid/f",
      referrer: "",
    });
    expect(parseZoneMark("[ZoneTransfer]\nZoneId=3\n")).toEqual({ zone: "3", url: "", referrer: "" });
  });
  it("is null without the structure or a numeric zone; a non-http url is dropped", () => {
    expect(parseZoneMark(undefined)).toBeNull();
    expect(parseZoneMark("MZ\u0090\u0000\u0003")).toBeNull();
    expect(parseZoneMark("ZoneId=3")).toBeNull();
    expect(parseZoneMark("[ZoneTransfer]\r\nZoneId=three")).toBeNull();
    expect(parseZoneMark("[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=javascript:alert(1)")?.url).toBe("");
  });
});

describe("readStream — evidence before the name", () => {
  it("code content decides whatever the name says: MZ in a SmartScreen stream is a payload", () => {
    const r = readStream({ path: `${HOST}:SmartScreen`, contents: "MZ\u0090\u0000\u0003", size: "40960" })!;
    expect(r.kind).toBe("code");
    expect(r.severity).toBe("Medium");
    expect(r.mitre).toEqual(["T1564.004"]);
    expect(r.words).toBe(
      'alternate data stream "SmartScreen" on notes.txt (40960 bytes) — executable content (starts with MZ)',
    );
    const zone = readStream({ path: `${HOST}:Zone.Identifier`, contents: "MZ\u0090" })!;
    expect(zone.kind).toBe("code");
    const magic = readStream({ path: `${HOST}:data`, magic: "PE32 executable (GUI) Intel 80386" })!;
    expect(magic.kind).toBe("code");
    expect(magic.words).toContain("executable content (magic PE32 executable (GUI) Intel 80386)");
    const mime = readStream({ path: `${HOST}:data`, mime: "application/x-msdownload" })!;
    expect(mime.kind).toBe("code");
    const elf = readStream({ path: `${HOST}:data`, contents: "\u007fELF\u0002" })!;
    expect(elf.kind).toBe("code");
  });
  it("a Zone.Identifier with the mark's structure is a download mark, graded like EvidenceOfDownload, no technique", () => {
    const doc = readStream({ path: `${HOST}:Zone.Identifier`, contents: MARK, size: "120" })!;
    expect(doc.kind).toBe("download-mark");
    expect(doc.severity).toBe("Info");
    expect(doc.mitre).toEqual([]);
    expect(doc.words).toBe(
      'alternate data stream "Zone.Identifier" on notes.txt (120 bytes) — downloaded from the Internet zone (https://files.example.invalid/a.exe, referrer https://example.invalid/)',
    );
    expect(doc.qualifiers).toEqual([PROVENANCE_NOTE]);
    expect(doc).toMatchObject({
      zone: "3",
      url: "https://files.example.invalid/a.exe",
      referrer: "https://example.invalid/",
    });
    expect(doc.keySegment).toBe("|ads:download-mark|3");
    const exe = readStream({ path: "C:\\Users\\bob\\Downloads\\tool.exe:Zone.Identifier", contents: MARK })!;
    expect(exe.severity).toBe("Medium");
    expect(exe.mitre).toEqual([]);
    expect(exe.severity).toBe(gradeMotwDownload("3", "tool.exe").severity);
    const intranet = readStream({
      path: "C:\\Users\\bob\\Downloads\\tool.exe:Zone.Identifier",
      contents: "[ZoneTransfer]\r\nZoneId=1",
    })!;
    expect(intranet.severity).toBe("Info");
    expect(intranet.words).toContain("downloaded from the Local intranet zone");
  });
  it("a Zone.Identifier with no contents is a mark only at a mark's size; otherwise it is a named stream", () => {
    const small = readStream({ path: `${HOST}:Zone.Identifier`, size: "26" })!;
    expect(small.kind).toBe("download-mark");
    expect(small.words).toContain("download mark (Zone.Identifier)");
    expect(small.severity).toBe("Info");
    const unknownSize = readStream({ path: `${HOST}:Zone.Identifier` })!;
    expect(unknownSize.kind).toBe("download-mark");
    const big = readStream({ path: `${HOST}:Zone.Identifier`, size: "204800" })!;
    expect(big.kind).toBe("named");
    expect(big.severity).toBe("Low");
    expect(big.words).toContain("large named stream");
    // contents that are not a mark, on a mark-sized stream: named, not a mark
    const text = readStream({ path: `${HOST}:Zone.Identifier`, contents: "hello", size: "5" })!;
    expect(text.kind).toBe("named");
  });
  it("each application stream literal is Info by name, on an MFTECmd row and a Velociraptor path alike", () => {
    for (const name of APPLICATION_STREAMS) {
      const kape = readStream({ path: `notes.txt:${name}`, isAds: true, size: "64" })!;
      const velo = readStream({ path: `${HOST}:${name}:$DATA` })!;
      for (const r of [kape, velo]) {
        expect(r.kind, name).toBe("application");
        expect(r.severity, name).toBe("Info");
        expect(r.stream, name).toBe(name);
      }
      expect(readStream({ path: `${HOST}:${name.toUpperCase()}` })!.kind, name).toBe("application");
    }
  });
  it("a named stream needs a positive signal: a code-like name is Medium, a large one Low, else Info; no $ exemption", () => {
    const dll = readStream({ path: `${HOST}:payload.dll`, size: "1234567" })!;
    expect(dll.kind).toBe("named");
    expect(dll.severity).toBe("Medium");
    expect(dll.mitre).toEqual(["T1564.004"]);
    expect(dll.words).toBe(
      'alternate data stream "payload.dll" on notes.txt (1234567 bytes) — named stream with a code-like name',
    );
    expect(dll.qualifiers).toEqual([CONTENT_NOTE]);
    expect(readStream({ path: `${HOST}:$payload.dll` })!.severity).toBe("Medium");
    expect(readStream({ path: `${HOST}:run.PS1` })!.severity).toBe("Medium");
    const large = readStream({ path: `${HOST}:data`, size: "100000" })!;
    expect(large.severity).toBe("Low");
    expect(large.words).toContain("large named stream");
    expect(large.qualifiers).toEqual([CONTENT_NOTE]);
    const small = readStream({ path: `${HOST}:data`, size: "512" })!;
    expect(small.severity).toBe("Info");
    expect(small.words).toContain("— named stream");
    expect(readStream({ path: `${HOST}:data` })!.severity).toBe("Info");
    const empty = readStream({ path: `${HOST}:data`, size: "0" })!;
    expect(empty.severity).toBe("Info");
    expect(empty.words).toContain("empty named stream");
    expect(readStream({ path: `${HOST}:$TXF_DATA` })!.kind).toBe("application");
  });
  it("names no stream → null; IsAds with no name in the path is still a stream row", () => {
    expect(readStream({ path: HOST })).toBeNull();
    const r = readStream({ path: HOST, isAds: true, size: "10" })!;
    expect(r.words).toContain('alternate data stream "(unnamed)" on notes.txt');
    expect(r.stream).toBe("");
  });
  it("bounds attacker-shaped names and keeps hashes only when they are hashes", () => {
    const long = readStream({ path: `${HOST}:${"s".repeat(300)}\n\u0000x` })!;
    expect(long.words.length).toBeLessThan(260);
    expect(long.words).not.toContain("\n");
    expect(long.stream.length).toBe(303); // the identity stays whole; only the words are bounded
    const hashed = readStream({
      path: `${HOST}:data`,
      sha256: "A".repeat(64),
      md5: "not-a-hash",
    })!;
    expect(hashed.sha256).toBe("a".repeat(64));
    expect(hashed.md5).toBeUndefined();
    expect(validHash("deadbeef", 32)).toBe("");
  });
});

describe("readHost — the host file's own row", () => {
  it("says the file has streams, and reads a download mark from ZoneIdContents with no technique", () => {
    const plain = readHost({ path: HOST });
    expect(plain.words).toBe("");
    expect(plain.severity).toBe("Info");
    const has = readHost({ path: HOST, hasAds: true });
    expect(has.words).toBe("has alternate data streams");
    const doc = readHost({ path: HOST, hasAds: true, contents: MARK });
    expect(doc.words).toBe(
      "has alternate data streams; downloaded from the Internet zone (https://files.example.invalid/a.exe, referrer https://example.invalid/)",
    );
    expect(doc.severity).toBe("Info");
    expect(doc.qualifiers).toEqual([PROVENANCE_NOTE]);
    const exe = readHost({ path: "C:\\Users\\bob\\Downloads\\tool.exe", contents: MARK });
    expect(exe.severity).toBe("Medium");
    expect(exe.mitre).toEqual([]);
    expect(exe.url).toBe("https://files.example.invalid/a.exe");
  });
  it("reads the MFTECmd boolean forms", () => {
    for (const v of ["True", "true", "1", 1, true, "yes"]) expect(streamFlag(v), String(v)).toBe(true);
    for (const v of ["False", "", "0", 0, false, null, undefined])
      expect(streamFlag(v), String(v)).toBe(false);
  });
});

describe("gradeMotwDownload — a mark carries no technique", () => {
  it("grades a runnable from an untrusted zone Medium and attaches no technique on any grade", () => {
    expect(gradeMotwDownload("3", "installer.msi")).toMatchObject({ severity: "Medium", mitre: [] });
    expect(gradeMotwDownload("4", "tool.exe")).toMatchObject({ severity: "Medium", mitre: [] });
    expect(gradeMotwDownload("3", "notes.txt")).toMatchObject({ severity: "Info", mitre: [] });
    expect(gradeMotwDownload("1", "installer.msi")).toMatchObject({ severity: "Info", mitre: [] });
  });
});
