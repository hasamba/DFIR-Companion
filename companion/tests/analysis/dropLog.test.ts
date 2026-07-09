import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { formatDropLogLines, appendDropLog, DROP_LOG_FILE, type DropLogEntry } from "../../src/analysis/dropLog.js";

describe("formatDropLogLines", () => {
  const at = "2026-07-09T14:02:11.482Z";

  it("formats an IMPORTED line with no reason", () => {
    const lines = formatDropLogLines([{ status: "IMPORTED", relpath: "alerts.csv" }], at);
    expect(lines).toEqual([`${at}  IMPORTED  alerts.csv`]);
  });

  it("formats a FAILED line with a reason", () => {
    const lines = formatDropLogLines(
      [{ status: "FAILED", relpath: "weird.csv", reason: "unrecognized file type (not a supported import format)" }],
      at,
    );
    expect(lines).toEqual([`${at}  FAILED    weird.csv  — unrecognized file type (not a supported import format)`]);
  });

  it("formats a PENDING line with a reason", () => {
    const lines = formatDropLogLines(
      [{ status: "PENDING", relpath: "capture.evtx", reason: "no tool configured for .evtx" }],
      at,
    );
    expect(lines).toEqual([`${at}  PENDING   capture.evtx  — no tool configured for .evtx`]);
  });

  it("preserves entry order across multiple entries in one call", () => {
    const entries: DropLogEntry[] = [
      { status: "IMPORTED", relpath: "a.csv" },
      { status: "FAILED", relpath: "b.csv", reason: "empty file" },
      { status: "PENDING", relpath: "c.evtx", reason: "no tool configured" },
    ];
    const lines = formatDropLogLines(entries, at);
    expect(lines).toHaveLength(3);
    expect(lines[0]).toContain("a.csv");
    expect(lines[1]).toContain("b.csv");
    expect(lines[2]).toContain("c.evtx");
  });

  it("round-trips a reason containing an em-dash and pipe as plain text", () => {
    const lines = formatDropLogLines(
      [{ status: "FAILED", relpath: "x.csv", reason: "bad row — col1|col2 mismatch" }],
      at,
    );
    expect(lines[0]).toContain("bad row — col1|col2 mismatch");
  });
});

describe("appendDropLog", () => {
  let dropDir: string;
  beforeEach(async () => {
    dropDir = await mkdtemp(join(tmpdir(), "dfir-droplog-"));
  });

  it("creates the file on first append", async () => {
    await appendDropLog(dropDir, ["line one"]);
    const text = await readFile(join(dropDir, DROP_LOG_FILE), "utf8");
    expect(text).toBe("line one\n");
  });

  it("appends rather than overwrites on a second call", async () => {
    await appendDropLog(dropDir, ["line one"]);
    await appendDropLog(dropDir, ["line two", "line three"]);
    const text = await readFile(join(dropDir, DROP_LOG_FILE), "utf8");
    expect(text).toBe("line one\nline two\nline three\n");
  });

  it("does nothing for an empty entries list (no file created)", async () => {
    await appendDropLog(dropDir, []);
    await expect(readFile(join(dropDir, DROP_LOG_FILE), "utf8")).rejects.toThrow();
  });
});
