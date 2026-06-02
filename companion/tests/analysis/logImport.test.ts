import { describe, it, expect } from "vitest";
import { parseLogLines, linesToText } from "../../src/analysis/logImport.js";

describe("parseLogLines", () => {
  it("returns empty lines for empty input", () => {
    expect(parseLogLines("").lines).toEqual([]);
    expect(parseLogLines("\n\n\n").lines).toEqual([]);
  });

  it("splits on LF, CRLF and CR; trims trailing whitespace; drops blank lines", () => {
    const text = "May 28 09:00:01 host sshd[1]: Failed\r\nMay 28 09:00:02 host sshd[2]: Accepted\r\n\nMay 28 09:00:03 host kernel: drop\n";
    expect(parseLogLines(text).lines).toEqual([
      "May 28 09:00:01 host sshd[1]: Failed",
      "May 28 09:00:02 host sshd[2]: Accepted",
      "May 28 09:00:03 host kernel: drop",
    ]);
  });

  it("strips a leading UTF-8 BOM", () => {
    const text = "﻿2026-05-28T09:00:01Z INFO start\n";
    expect(parseLogLines(text).lines).toEqual(["2026-05-28T09:00:01Z INFO start"]);
  });

  it("preserves leading whitespace within lines (indented stack traces)", () => {
    const text = "ERROR boom\n    at fn (x)\n    at g (y)\n";
    expect(parseLogLines(text).lines).toEqual(["ERROR boom", "    at fn (x)", "    at g (y)"]);
  });

  it("does NOT deduplicate repeated lines (each occurrence is evidence)", () => {
    const text = "heartbeat\nheartbeat\nheartbeat\n";
    expect(parseLogLines(text).lines).toHaveLength(3);
  });
});

describe("linesToText", () => {
  it("joins lines with newlines, no trailing newline", () => {
    expect(linesToText(["a", "b", "c"])).toBe("a\nb\nc");
    expect(linesToText([])).toBe("");
  });
});
