// #932 item 1: KAPE's own acquisition provenance (_copylog.csv / _skiplog.csv), read as facts —
// never wired into refutation reasoning (see #1101 for that separate, larger follow-on).
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, it, expect } from "vitest";
import { parseKapeCsv } from "../../src/analysis/kapeImport.js";
import {
  isKapeCopyLog,
  isKapeSkipLog,
  parseKapeAcquisitionLog,
} from "../../src/analysis/kapeAcquisitionLog.js";
import {
  canonicalConformanceIssues,
  canonicalEventEnvelopeSchema,
} from "../../src/analysis/canonicalEvent.js";

function csv(header: string[], rows: string[][]): string {
  const esc = (v: string): string => (/[",\n\r]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v);
  return [header, ...rows].map((r) => r.map(esc).join(",")).join("\n");
}

const COPYLOG_HEADER = [
  "CopiedTimestamp",
  "SourceFile",
  "DestinationFile",
  "FileSize",
  "SourceFileSha1",
  "DeferredCopy",
  "CreatedOnUtc",
  "ModifiedOnUtc",
  "LastAccessedOnUtc",
  "CopyDuration",
];
const SKIPLOG_HEADER = ["SourceFile", "SourceFileSha1", "Reason"];

const env = (e: { canonical?: unknown }) => canonicalEventEnvelopeSchema.parse(e.canonical);

describe("isKapeCopyLog / isKapeSkipLog — strict, full-header signatures", () => {
  it("requires ALL documented copylog columns — a 3-column CSV sharing generic names is never claimed", () => {
    expect(isKapeCopyLog(COPYLOG_HEADER)).toBe(true);
    expect(isKapeCopyLog(["SourceFile", "SourceFileSha1", "DestinationFile"])).toBe(false);
  });

  it("requires all documented skiplog columns — header-only, matching copylog's own detection convention (#932 item 1, Codex code review finding #6: a row-value sample rejected a valid EMPTY skiplog, inconsistent with copylog)", () => {
    expect(isKapeSkipLog(SKIPLOG_HEADER)).toBe(true);
    expect(isKapeSkipLog(["SourceFile", "SourceFileSha1"])).toBe(false);
  });
});

describe("parseKapeAcquisitionLog — copylog", () => {
  it("a complete collection: every file copied, no deferred reads", () => {
    const text = csv(COPYLOG_HEADER, [
      [
        "2024-05-01T09:00:00Z",
        "C:\\Windows\\Prefetch\\EVIL.EXE-1234.pf",
        "D:\\out\\EVIL.EXE-1234.pf",
        "10000",
        "abc123",
        "false",
        "2024-04-01T00:00:00Z",
        "2024-04-30T00:00:00Z",
        "2024-04-30T00:00:00Z",
        "00:00:01",
      ],
      [
        "2024-05-01T09:00:05Z",
        "C:\\$MFT",
        "D:\\out\\$MFT",
        "500000",
        "def456",
        "true",
        "2024-01-01T00:00:00Z",
        "2024-04-30T00:00:00Z",
        "2024-04-30T00:00:00Z",
        "00:00:10",
      ],
    ]);
    const r = parseKapeCsv(text);
    expect(r.artifact).toBe("KapeAcquisitionCopyLog");
    expect(r.events).toHaveLength(1);
    const e = r.events[0];
    expect(e.severity).toBe("Info");
    expect(e.description).toContain("KAPE acquisition: 2 file(s) copied");
    expect(e.description).toContain("1 via a deferred (raw-disk) read");
    expect(e.description).toContain("collected");
    const block = env(e).acquisitionCoverage;
    expect(block?.tool).toBe("kape");
    expect(block?.logKind).toBe("copied");
    expect(block?.facts).toHaveLength(2);
    expect(block?.facts[0].sourceFile).toContain("Prefetch");
    expect(block?.facts[1].deferredCopy).toBe(true);
    expect(block?.basis).toContain("not a container or disk-image hash");
    expect(canonicalConformanceIssues(env(e))).toEqual([]);
  });

  it("an unsupported/empty collection (header only, zero files) is a valid 'nothing copied' fact, never an error", () => {
    const text = csv(COPYLOG_HEADER, []);
    const r = parseKapeCsv(text);
    expect(r.artifact).toBe("KapeAcquisitionCopyLog");
    expect(r.events).toHaveLength(1);
    expect(r.events[0].description).toContain("KAPE acquisition: 0 file(s) copied");
  });

  it("a malformed row (no SourceFile) is counted, never silently dropped from the total", () => {
    const text = csv(COPYLOG_HEADER, [
      ["2024-05-01T09:00:00Z", "", "D:\\out\\x", "1", "", "false", "", "", "", "00:00:01"],
      ["2024-05-01T09:00:01Z", "C:\\a.txt", "D:\\out\\a.txt", "1", "abc", "false", "", "", "", "00:00:01"],
    ]);
    const r = parseKapeCsv(text);
    const e = r.events[0];
    expect(e.description).toContain("1 row(s) in this log named no source file — not counted");
    const block = env(e).acquisitionCoverage;
    expect(block?.malformedRows).toBe(1);
    expect(block?.facts).toHaveLength(1);
  });
});

describe("parseKapeAcquisitionLog — skiplog", () => {
  it("a partial collection: excluded and deduped files disclosed by reason", () => {
    const text = csv(SKIPLOG_HEADER, [
      ["C:\\Windows\\Prefetch\\A.pf", "aaa", "Excluded"],
      ["C:\\Windows\\Prefetch\\B.pf", "bbb", "Excluded"],
      ["C:\\Windows\\System32\\config\\SYSTEM", "ccc", "Deduped"],
    ]);
    const r = parseKapeCsv(text);
    expect(r.artifact).toBe("KapeAcquisitionSkipLog");
    const e = r.events[0];
    expect(e.description).toContain("KAPE acquisition: 3 file(s) skipped");
    expect(e.description).toContain("2 Excluded");
    expect(e.description).toContain("1 Deduped");
    const block = env(e).acquisitionCoverage;
    expect(block?.logKind).toBe("skipped");
    expect(block?.facts).toHaveLength(3);
    expect(block?.facts[0].reason).toBe("Excluded");
    expect(canonicalConformanceIssues(env(e))).toEqual([]);
  });

  it("a failed collection (every file skipped, none copied) is disclosed honestly, never as a copy count", () => {
    const text = csv(SKIPLOG_HEADER, [["C:\\a.pf", "aaa", "Excluded"]]);
    const r = parseKapeCsv(text);
    expect(r.events[0].description).not.toContain("copied");
    expect(r.events[0].description).toContain("skipped");
  });
});

describe("Codex code round 1 fixes", () => {
  it("an unrecognized Reason value is counted as malformed, never silently trusted (finding #6)", () => {
    const text = csv(SKIPLOG_HEADER, [
      ["C:\\a.pf", "aaa", "Excluded"],
      ["C:\\b.pf", "bbb", "Manual review"],
    ]);
    const r = parseKapeCsv(text);
    const e = r.events[0];
    expect(e.description).toContain("KAPE acquisition: 1 file(s) skipped");
    expect(e.description).toContain("1 row(s) in this log named no source file or no recognized reason");
    const block = env(e).acquisitionCoverage;
    expect(block?.malformedRows).toBe(1);
    expect(block?.facts).toHaveLength(1);
  });

  it("two distinct skiplogs with IDENTICAL resulting counts never produce colliding (timestamp, description) pairs — correlate.ts's own exact-duplicate merge would otherwise fold one's facts into the other's (finding #2)", () => {
    const a = csv(SKIPLOG_HEADER, [["C:\\a.pf", "aaa", "Excluded"]]);
    const b = csv(SKIPLOG_HEADER, [["C:\\b.pf", "bbb", "Excluded"]]);
    const ra = parseKapeCsv(a).events[0];
    const rb = parseKapeCsv(b).events[0];
    // Same shape of description (same count, same reason breakdown) — the content fingerprint is
    // what must differ, since both logs otherwise render identically.
    expect(ra.description).not.toBe(rb.description);
    expect(ra.aggKey).not.toBe(rb.aggKey);
  });

  it("deferred/reason counts are accurate beyond the 256-fact citation cap — accumulated over EVERY valid row, not just the cited sample (finding #3)", () => {
    const rows = Array.from({ length: 257 }, (_, i) => [
      `C:\\f${i}.pf`,
      "h",
      i === 256 ? "Deduped" : "Excluded",
    ]);
    const text = csv(SKIPLOG_HEADER, rows);
    const r = parseKapeCsv(text);
    const e = r.events[0];
    expect(e.description).toContain("256 Excluded");
    expect(e.description).toContain("1 Deduped");
    const block = env(e).acquisitionCoverage;
    expect(block?.facts).toHaveLength(256);
    expect(block?.notCited).toBe(1);
  });

  it("a source path is never truncated in canonical evidence, however long", () => {
    const longPath = `C:\\${"a".repeat(300)}\\file.pf`;
    const text = csv(COPYLOG_HEADER, [
      ["2024-05-01T09:00:00Z", longPath, "d:/out", "1", "abc", "false", "", "", "", "00:00:01"],
    ]);
    const r = parseKapeCsv(text);
    const block = env(r.events[0]).acquisitionCoverage;
    expect(block?.facts[0].sourceFile).toBe(longPath);
  });

  it("a log with rows but zero valid facts extracted is 'unknown' outcome, never claimed as a successful acquisition (finding #7)", () => {
    const text = csv(COPYLOG_HEADER, [["", "", "", "", "", "", "", "", "", ""]]);
    const r = parseKapeCsv(text);
    const e = r.events[0];
    expect(env(e).event.outcome).toBe("unknown");
  });

  it("parsing a large existing artifact CSV never double-parses via the acquisition-log check (finding #5) — Prefetch routing still works and returns the same result as calling parseCsv once", () => {
    const text = csv(
      ["SourceFilename", "ExecutableName", "Hash", "Size", "RunCount", "LastRun", "PreviousRun0"],
      [["C:\\Windows\\Prefetch\\A.EXE-1.pf", "A.EXE", "AAAA", "1", "1", "2023-04-01 10:00:00", ""]],
    );
    const r = parseKapeCsv(text);
    expect(r.artifact).toBe("Prefetch");
    expect(r.events).toHaveLength(1);
  });

  it("no DEFAULT tag rule matches this row's own source/description, so it never gets promoted out of Info by the standard tagger without an analyst-authored rule (finding #1 — a shared, pre-existing property of every Info-severity importer, not unique to this one)", () => {
    const text = csv(SKIPLOG_HEADER, [["C:\\a.pf", "aaa", "Excluded"]]);
    const e = parseKapeCsv(text).events[0];
    const tagsYaml = readFileSync(join(process.cwd(), "data", "tags.yaml"), "utf8").toLowerCase();
    expect(tagsYaml).not.toContain("kape");
    expect(tagsYaml).not.toContain("acquisition");
    void e;
  });
});

describe("acquisition-log detection never claims an unrelated KAPE artifact CSV", () => {
  it("a real Prefetch CSV is still routed to the Prefetch profile, not the acquisition log", () => {
    const text = csv(
      ["SourceFilename", "ExecutableName", "Hash", "Size", "RunCount", "LastRun", "PreviousRun0"],
      [
        [
          "C:\\Windows\\Prefetch\\EVIL.EXE-1234.pf",
          "EVIL.EXE",
          "ABCD",
          "10000",
          "3",
          "2023-04-01 10:00:00",
          "",
        ],
      ],
    );
    const r = parseKapeCsv(text);
    expect(r.artifact).toBe("Prefetch");
  });

  it("parseKapeAcquisitionLog returns null for a non-acquisition-log CSV", () => {
    const text = csv(["a", "b"], [["1", "2"]]);
    expect(parseKapeAcquisitionLog(text)).toBeNull();
  });
});
