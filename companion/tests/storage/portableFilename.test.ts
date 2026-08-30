import { describe, it, expect } from "vitest";
import { portableZipSegment, portableZipEntryPath } from "../../src/storage/portableFilename.js";

describe("portableZipSegment", () => {
  it("leaves an ordinary name alone, non-ASCII included", () => {
    expect(portableZipSegment("evidence.bin")).toBe("evidence.bin");
    expect(portableZipSegment(".gitignore")).toBe(".gitignore");
    expect(portableZipSegment("rapport été.pdf")).toBe("rapport été.pdf");
  });

  it("replaces the characters Windows refuses", () => {
    expect(portableZipSegment('host:C<>"|?*.evtx')).toBe("host_C______.evtx");
    expect(portableZipSegment("a\u0001b")).toBe("a_b");
  });

  it("pads a trailing dot or space instead of trimming it", () => {
    // Windows strips both, so "notes." and "notes" would resolve to one file. Padding keeps the
    // two names distinct so the caller's collision check still sees two entries.
    expect(portableZipSegment("notes.")).toBe("notes_");
    expect(portableZipSegment("notes ")).toBe("notes_");
    expect(portableZipSegment("notes")).toBe("notes");
  });

  it("never returns an empty segment, which names no file", () => {
    for (const input of ["", ":", "?"]) expect(portableZipSegment(input).length).toBeGreaterThan(0);
  });

  it("escapes a reserved device name, with or without an extension", () => {
    expect(portableZipSegment("NUL")).toBe("_NUL");
    expect(portableZipSegment("con.txt")).toBe("_con.txt");
    expect(portableZipSegment("LPT1.log")).toBe("_LPT1.log");
    expect(portableZipSegment("CONSOLE.txt")).toBe("CONSOLE.txt");
  });
});

describe("portableZipEntryPath", () => {
  it("rewrites every segment and keeps the separators", () => {
    expect(portableZipEntryPath("drop/_processed/host:C.evtx")).toBe("drop/_processed/host_C.evtx");
  });

  // This asserted the opposite when it landed (#732): a backslash folded to a separator. Every
  // caller walks the case directory joining with "/" on EVERY platform, so a backslash arriving
  // here is part of a filename — "back\slash.bin" is a legal file on Linux — and folding it split
  // one file into a directory and a child the case never had. caseExportArchive had the same fold
  // in its READ path, where it was worse still: the read looked inside a directory that does not
  // exist and the export died claiming the file had vanished mid-package (#675).
  it("treats a backslash as filename content, not a separator", () => {
    expect(portableZipEntryPath("drop/back\\slash.bin")).toBe("drop/back_slash.bin");
    expect(portableZipEntryPath("state\\db.sqlite")).toBe("state_db.sqlite");
  });

  it("drops empty segments so a doubled slash does not invent a directory", () => {
    expect(portableZipEntryPath("state//db/case.sqlite")).toBe("state/db/case.sqlite");
  });

  it("leaves the paths a real export produces untouched", () => {
    for (const path of [
      "case.json",
      "state/investigation.sqlite",
      "metadata/captures.jsonl",
      "screenshots/shot-001.webp",
      "archive-manifest.json",
    ]) {
      expect(portableZipEntryPath(path)).toBe(path);
    }
  });

  it("rewrites a hostile DIRECTORY name too, not only the filename", () => {
    expect(portableZipEntryPath("host:1/con/notes.")).toBe("host_1/_con/notes_");
  });

  it("neutralizes a traversal segment", () => {
    expect(portableZipEntryPath("state/../../etc/passwd")).toBe("state/__/__/etc/passwd");
  });
});
