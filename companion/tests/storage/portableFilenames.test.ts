import { describe, it, expect } from "vitest";
import { portableFilename, portableFilePath } from "../../src/storage/portableFilenames.js";

describe("portableFilename (#675)", () => {
  // Each rule below exists because some platform refuses, or silently rewrites, the name it
  // covers. The archive is written on one machine and opened on another, so a name only the
  // writer's filesystem accepts is a file the reader never sees.
  it.each([
    ["evidence:2026.evtx", "evidence_2026.evtx", "colon — an NTFS alternate data stream"],
    ["back\\slash.bin", "back_slash.bin", "backslash — a path separator on Windows"],
    ["a/b.bin", "a_b.bin", "forward slash — a separator this function is not given"],
    ["pipe|star*.bin", "pipe_star_.bin", "pipe and star"],
    ['quote".bin', "quote_.bin", "double quote"],
    ["less<greater>.bin", "less_greater_.bin", "angle brackets"],
    ["question?.bin", "question_.bin", "question mark"],
    ["\x01ctrl.bin", "_ctrl.bin", "control character"],
    ["notes.", "notes", "Windows strips a trailing dot"],
    ["notes  ", "notes", "Windows strips trailing spaces"],
    ["NUL.txt", "_NUL.txt", "reserved device name with an extension"],
    ["con", "_con", "reserved device name on its own"],
    ["LPT9", "_LPT9", "reserved device name, any case"],
  ])("rewrites %j to %j (%s)", (input, expected) => {
    expect(portableFilename(input)).toBe(expected);
  });

  it.each(["report.md", "shot-001.webp", "investigation.sqlite", "an ordinary name.txt", "café.png"])(
    "leaves %j alone",
    (name) => {
      expect(portableFilename(name)).toBe(name);
    },
  );

  it("never returns an empty or dot-only segment, which names no file", () => {
    for (const input of ["", ".", "..", "...", ":", "   ", "\x01"]) {
      const out = portableFilename(input);
      expect(out.length).toBeGreaterThan(0);
      expect(out).not.toBe(".");
      expect(out).not.toBe("..");
    }
  });
});

describe("portableFilePath (#675)", () => {
  it("rewrites each segment and keeps the separators between them", () => {
    expect(portableFilePath("drop/_processed/evidence:2026.evtx")).toBe("drop/_processed/evidence_2026.evtx");
  });

  it("rewrites a hostile DIRECTORY name too, not only the filename", () => {
    expect(portableFilePath("host:1/con/notes.")).toBe("host_1/_con/notes");
  });

  it("leaves the paths a real export produces untouched", () => {
    for (const path of [
      "case.json",
      "state/investigation.sqlite",
      "metadata/captures.jsonl",
      "screenshots/shot-001.webp",
      "archive-manifest.json",
    ]) {
      expect(portableFilePath(path)).toBe(path);
    }
  });
});
