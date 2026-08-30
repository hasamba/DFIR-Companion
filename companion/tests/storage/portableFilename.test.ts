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

  it("folds backslashes to forward slashes and drops empty segments", () => {
    expect(portableZipEntryPath("state\\db\\case.sqlite")).toBe("state/db/case.sqlite");
    expect(portableZipEntryPath("state//db/case.sqlite")).toBe("state/db/case.sqlite");
  });

  it("neutralizes a traversal segment", () => {
    expect(portableZipEntryPath("state/../../etc/passwd")).toBe("state/__/__/etc/passwd");
  });
});
