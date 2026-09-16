import { describe, it, expect } from "vitest";
import { parseMacFsEventTsv, MAX_FSEVENT_ROWS_SCANNED } from "../../src/analysis/macFsEventImport.js";

// Header shape verified live against FSEventsParser's (dlcowen/G-C Partners) own
// Output.R_COLUMNS / print_columns() — the real 9-column All_FSEVENTS.tsv report, not the full
// Output.COLUMNS set (which only reaches the tool's own SQLite DB).
const HEADER = [
  "id",
  "node_id",
  "fs_uid",
  "fullpath",
  "type",
  "flags",
  "approx_dates_plus_minus_one_day",
  "source",
  "source_modified_time",
].join("\t");

function row(overrides: Partial<Record<string, string>> = {}): string {
  const fields: Record<string, string> = {
    id: "123456",
    node_id: "789",
    fs_uid: "501",
    fullpath: "Users/analyst/Desktop/payload.exe",
    type: "FileEvent;",
    flags: "Created;",
    approx_dates_plus_minus_one_day: "2024.03.15",
    source: "/mnt/image/private/var/db/Spotlight-V100/.fseventsd/0000000012345678",
    source_modified_time: "2024-03-15T10:00:00Z",
    ...overrides,
  };
  return [
    fields.id,
    fields.node_id,
    fields.fs_uid,
    fields.fullpath,
    fields.type,
    fields.flags,
    fields.approx_dates_plus_minus_one_day,
    fields.source,
    fields.source_modified_time,
  ].join("\t");
}

function tsv(rows: string[]): string {
  return [HEADER, ...rows].join("\n");
}

describe("parseMacFsEventTsv — format detection", () => {
  it("returns null for text with no tab-delimited header", () => {
    expect(parseMacFsEventTsv("not,a,tsv,file")).toBeNull();
  });

  it("returns null for an empty string", () => {
    expect(parseMacFsEventTsv("")).toBeNull();
  });

  it("returns null when the header columns are reordered", () => {
    const badHeader = [...HEADER.split("\t")].reverse().join("\t");
    expect(parseMacFsEventTsv([badHeader, row()].join("\n"))).toBeNull();
  });

  it("parses a real 9-column All_FSEVENTS.tsv", () => {
    const r = parseMacFsEventTsv(tsv([row()]));
    expect(r).not.toBeNull();
    expect(r!.kept).toBe(1);
  });
});

describe("parseMacFsEventTsv — record identity and uint64 handling", () => {
  it("keeps a wd near the 2^53 float-precision boundary as an exact string", () => {
    const bigId = "9007199254740993"; // 2^53 + 1 — would silently round if passed through Number()
    const r = parseMacFsEventTsv(tsv([row({ id: bigId })]))!;
    expect(r.events[0].canonical!.macFsEvent?.recordId).toBe(bigId);
  });

  it("rejects a non-digit id as malformed rather than crashing", () => {
    const r = parseMacFsEventTsv(tsv([row({ id: "not-a-number" })]))!;
    expect(r.malformedRows).toBe(1);
    expect(r.kept).toBe(0);
  });
});

describe("parseMacFsEventTsv — coalesced type/flags preserved, never rejected", () => {
  it("keeps multiple semicolon-joined flags on one record, never collapsed to one", () => {
    const r = parseMacFsEventTsv(tsv([row({ flags: "Created;Renamed;Modified;" })]))!;
    expect(r.events[0].canonical!.macFsEvent?.flags).toEqual(["Created", "Renamed", "Modified"]);
  });

  it("does not reject a FolderEvent+FileEvent combination — the carved-only check_record() gate does not apply here", () => {
    const r = parseMacFsEventTsv(tsv([row({ type: "FolderEvent;FileEvent;" })]))!;
    expect(r.kept).toBe(1);
    expect(r.events[0].canonical!.macFsEvent?.recordTypes).toEqual(["FolderEvent", "FileEvent"]);
  });

  it("clips an oversized flag token instead of letting it abort the whole import", () => {
    const oversized = "X".repeat(41);
    const r = parseMacFsEventTsv(tsv([row({ flags: `${oversized};` })]))!;
    expect(r.kept).toBe(1);
    expect(r.events[0].canonical!.macFsEvent?.flags[0]?.length).toBe(40);
  });
});

describe("parseMacFsEventTsv — approximate date epistemics", () => {
  it("normalizes a single dotted date to a dash date, keeps the raw form separately", () => {
    const r = parseMacFsEventTsv(tsv([row({ approx_dates_plus_minus_one_day: "2024.03.15" })]))!;
    const block = r.events[0].canonical!.macFsEvent!;
    expect(block.approxDateStart).toBe("2024-03-15");
    expect(block.approxDateEnd).toBe("2024-03-15");
    expect(block.approxDateRaw).toBe("2024.03.15");
  });

  it("splits a date range into start and end", () => {
    const r = parseMacFsEventTsv(tsv([row({ approx_dates_plus_minus_one_day: "2024.03.15 - 2024.03.17" })]))!;
    const block = r.events[0].canonical!.macFsEvent!;
    expect(block.approxDateStart).toBe("2024-03-15");
    expect(block.approxDateEnd).toBe("2024-03-17");
  });

  it("never fabricates a date for 'Unknown' — timestamp and approxDateStart both stay empty", () => {
    const r = parseMacFsEventTsv(tsv([row({ approx_dates_plus_minus_one_day: "Unknown" })]))!;
    expect(r.events[0].timestamp).toBe("");
    expect(r.events[0].canonical!.macFsEvent?.approxDateStart).toBe("");
    expect(r.events[0].canonical!.time.clockConfidence).toBe("unknown");
  });

  it("marks a resolved date as inferred confidence, day precision — never 'recorded'", () => {
    const r = parseMacFsEventTsv(tsv([row({ approx_dates_plus_minus_one_day: "2024.03.15" })]))!;
    expect(r.events[0].canonical!.time.clockConfidence).toBe("inferred");
    expect(r.events[0].canonical!.time.precision).toBe("date");
  });

  it("never promotes a garbled, non-date-shaped value to an inferred timestamp", () => {
    const r = parseMacFsEventTsv(tsv([row({ approx_dates_plus_minus_one_day: "nonsense" })]))!;
    expect(r.events[0].timestamp).toBe("");
    expect(r.events[0].canonical!.macFsEvent?.approxDateStart).toBe("");
    expect(r.events[0].canonical!.time.clockConfidence).toBe("unknown");
  });
});

describe("parseMacFsEventTsv — node_id / fs_uid disclosure", () => {
  it("omits nodeId/fsUid when the export leaves them blank, never guesses", () => {
    const r = parseMacFsEventTsv(tsv([row({ node_id: "", fs_uid: "" })]))!;
    const block = r.events[0].canonical!.macFsEvent!;
    expect(block.nodeId).toBeUndefined();
    expect(block.fsUid).toBeUndefined();
  });

  it("carries nodeId/fsUid through when present", () => {
    const r = parseMacFsEventTsv(tsv([row({ node_id: "789", fs_uid: "501" })]))!;
    const block = r.events[0].canonical!.macFsEvent!;
    expect(block.nodeId).toBe("789");
    expect(block.fsUid).toBe("501");
  });
});

describe("parseMacFsEventTsv — identity and aggregation", () => {
  it("keeps two rows with the same recordId but different content as distinct events", () => {
    const r = parseMacFsEventTsv(
      tsv([row({ id: "1", fullpath: "a.txt" }), row({ id: "1", fullpath: "b.txt" })]),
    )!;
    expect(r.kept).toBe(2);
  });

  it("collapses two byte-identical rows under aggregation", () => {
    const r = parseMacFsEventTsv(tsv([row(), row()]))!;
    expect(r.kept).toBe(1);
  });

  it("keeps two rows differing only in nodeId as distinct events, never collapsed under one count", () => {
    const r = parseMacFsEventTsv(tsv([row({ node_id: "1" }), row({ node_id: "2" })]))!;
    expect(r.kept).toBe(2);
  });

  it("keeps two rows differing only past the 300-char path clip point as distinct events", () => {
    const longBase = "Users/analyst/".padEnd(310, "a");
    const r = parseMacFsEventTsv(
      tsv([row({ fullpath: `${longBase}/one.txt` }), row({ fullpath: `${longBase}/two.txt` })]),
    )!;
    expect(r.kept).toBe(2);
  });

  it("gives two content-distinct rows different description text, even with the same displayed fields", () => {
    const r = parseMacFsEventTsv(tsv([row({ node_id: "1" }), row({ node_id: "2" })]))!;
    expect(r.events[0].description).not.toBe(r.events[1].description);
  });
});

describe("parseMacFsEventTsv — scan bound", () => {
  it("truncates and discloses when the report exceeds the scan cap", () => {
    const rows = Array.from({ length: MAX_FSEVENT_ROWS_SCANNED + 1 }, (_, i) => row({ id: String(i + 1) }));
    const r = parseMacFsEventTsv(tsv(rows))!;
    expect(r.rowsTruncated).toBe(true);
    expect(r.total).toBe(MAX_FSEVENT_ROWS_SCANNED);
  });
});

describe("parseMacFsEventTsv — malformed rows", () => {
  it("counts a short row as malformed, never crashes", () => {
    const r = parseMacFsEventTsv(`${HEADER}\n1\t2\t3`)!;
    expect(r.malformedRows).toBe(1);
    expect(r.kept).toBe(0);
  });
});

describe("parseMacFsEventTsv — severity", () => {
  it("stays Info unconditionally — corroboration, not a lead", () => {
    const r = parseMacFsEventTsv(tsv([row()]))!;
    expect(r.events[0].severity).toBe("Info");
  });
});
