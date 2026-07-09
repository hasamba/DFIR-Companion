import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  formatDropLogLines, appendDropLog, buildSweepLogEntries, DROP_LOG_FILE, type DropLogEntry,
} from "../../src/analysis/dropLog.js";

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

  it("collapses embedded newlines in a multi-line reason to a single line", () => {
    const lines = formatDropLogLines(
      [{ status: "FAILED", relpath: "y.csv", reason: "SyntaxError: Unexpected token\n    at parse (parser.js:12)\n    at import (importer.js:5)" }],
      at,
    );
    expect(lines[0]).not.toContain("\n");
    expect(lines[0]).toContain("SyntaxError: Unexpected token at parse (parser.js:12) at import (importer.js:5)");
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

describe("buildSweepLogEntries", () => {
  it("always produces entries for imported and failed files regardless of loggedPending", () => {
    const { entries, nextLoggedPending } = buildSweepLogEntries(
      {
        imported: ["a.csv"],
        failed: [{ relpath: "b.csv", reason: "bad header" }],
        pendingRawInputs: [],
      },
      new Set(["a.csv", "b.csv"]), // even if these happen to already be "logged pending", imported/failed always log
    );
    expect(entries).toEqual([
      { status: "IMPORTED", relpath: "a.csv" },
      { status: "FAILED", relpath: "b.csv", reason: "bad header" },
    ]);
    // loggedPending tracking is only about pendingRawInputs; imported/failed relpaths pass through untouched
    expect(nextLoggedPending).toEqual(new Set(["a.csv", "b.csv"]));
  });

  it("logs a pending file not yet in loggedPending, and adds it to nextLoggedPending", () => {
    const { entries, nextLoggedPending } = buildSweepLogEntries(
      {
        imported: [],
        failed: [],
        pendingRawInputs: [{ relpath: "capture.evtx", ext: ".evtx", configured: true }],
      },
      new Set(),
    );
    expect(entries).toEqual([
      {
        status: "PENDING",
        relpath: "capture.evtx",
        reason: "awaiting tool run for .evtx (drop banner: Run)",
      },
    ]);
    expect(nextLoggedPending.has("capture.evtx")).toBe(true);
  });

  it("does not re-log a pending file already in loggedPending, but keeps it in nextLoggedPending", () => {
    const { entries, nextLoggedPending } = buildSweepLogEntries(
      {
        imported: [],
        failed: [],
        pendingRawInputs: [{ relpath: "capture.evtx", ext: ".evtx", configured: true }],
      },
      new Set(["capture.evtx"]),
    );
    expect(entries).toEqual([]);
    expect(nextLoggedPending.has("capture.evtx")).toBe(true);
  });

  it("does not carry a resolved relpath into nextLoggedPending", () => {
    // In production, server.ts deletes a resolved relpath from its stored dropPendingLogged set (via
    // dropPendingLogged.get(caseId)?.delete(file.relpath)) as soon as a file moves from pending to
    // imported/failed — BEFORE calling buildSweepLogEntries for the sweep. So loggedPending passed in
    // here already excludes "capture.evtx". buildSweepLogEntries only ever ADDS relpaths present in
    // this sweep's pendingRawInputs — it never resurrects a relpath the caller already removed.
    const { entries, nextLoggedPending } = buildSweepLogEntries(
      {
        imported: ["capture.evtx"], // resolved: now imported, no longer pending
        failed: [],
        pendingRawInputs: [], // absent from this sweep's pendingRawInputs — it resolved
      },
      new Set(), // caller already deleted "capture.evtx" from loggedPending when it resolved
    );
    expect(entries).toEqual([{ status: "IMPORTED", relpath: "capture.evtx" }]);
    expect(nextLoggedPending.has("capture.evtx")).toBe(false);
  });

  it("if a resolved file becomes pending again later, it logs again (fresh loggedPending without it)", () => {
    const { entries, nextLoggedPending } = buildSweepLogEntries(
      {
        imported: [],
        failed: [],
        pendingRawInputs: [{ relpath: "capture.evtx", ext: ".evtx", configured: true }],
      },
      new Set(), // caller already deleted "capture.evtx" from loggedPending when it resolved earlier
    );
    expect(entries).toEqual([
      {
        status: "PENDING",
        relpath: "capture.evtx",
        reason: "awaiting tool run for .evtx (drop banner: Run)",
      },
    ]);
    expect(nextLoggedPending.has("capture.evtx")).toBe(true);
  });

  it("uses the 'no tool configured' reason text when configured is false", () => {
    const { entries } = buildSweepLogEntries(
      {
        imported: [],
        failed: [],
        pendingRawInputs: [{ relpath: "traffic.pcap", ext: ".pcap", configured: false }],
      },
      new Set(),
    );
    expect(entries).toEqual([
      {
        status: "PENDING",
        relpath: "traffic.pcap",
        reason: "no tool configured for .pcap (drop banner: Configure)",
      },
    ]);
  });

  it("does not mutate the input loggedPending set", () => {
    const original = new Set(["existing.evtx"]);
    buildSweepLogEntries(
      {
        imported: [],
        failed: [],
        pendingRawInputs: [{ relpath: "new.evtx", ext: ".evtx", configured: true }],
      },
      original,
    );
    expect(original).toEqual(new Set(["existing.evtx"])); // unchanged — caller must use the returned set
  });
});
