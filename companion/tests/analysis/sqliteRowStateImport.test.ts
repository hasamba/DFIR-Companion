import { describe, it, expect, afterEach } from "vitest";
import {
  parseSqliteRowStateCsv,
  DESCRIPTION_MAX,
  MAX_ROWS_SCANNED,
  type SqliteRowStateResult,
} from "../../src/analysis/sqliteRowStateImport.js";
import {
  sqliteRowStateBlockSchema,
  SQLITE_ROW_STATE_BASIS,
  SQLITE_ROW_STATE_BASIS_V2,
} from "../../src/analysis/canonicalSqliteRowState.js";
import { markContainerEscape } from "../../src/analysis/containerEscape.js";

// Header/enum shape verified live against sqlite-dissect's (DC3) own csv_export.py
// (CommitCsvExporter._write_cells) and constants.py — not invented.
const HEADER = [
  "File Source",
  "Version",
  "Page Version",
  "Cell Source",
  "Page Number",
  "Location",
  "Operation",
  "File Offset",
  "Row ID",
];

function quote(v: string): string {
  return `"${v.replace(/"/g, '""')}"`;
}

function csv(columnNames: string[], rows: (string | number)[][]): string {
  const lines = [
    [...HEADER, ...columnNames].map((h) => quote(h)).join(","),
    ...rows.map((r) => r.map((v) => quote(String(v))).join(",")),
  ];
  return lines.join("\n");
}

function row(overrides: Partial<Record<string, string | number>> = {}): (string | number)[] {
  const base = {
    fileSource: "DATABASE",
    version: 0,
    pageVersion: 0,
    cellSource: "B-Tree",
    pageNumber: 3,
    location: 0,
    operation: "Added",
    fileOffset: 4096,
    rowId: 1,
    ...overrides,
  };
  return [
    base.fileSource,
    base.version,
    base.pageVersion,
    base.cellSource,
    base.pageNumber,
    base.location,
    base.operation,
    base.fileOffset,
    base.rowId,
  ];
}

describe("parseSqliteRowStateCsv — header validation", () => {
  it("rejects a header missing Row ID (the WITHOUT ROWID / index-page shape, out of scope)", () => {
    const noRowId = [...HEADER.slice(0, 8), "body"].map((h) => quote(h)).join(",");
    const dataRow = ["DATABASE", 0, 0, "B-Tree", 3, 0, "Added", 4096, "hi"]
      .map((v) => quote(String(v)))
      .join(",");
    expect(parseSqliteRowStateCsv(`${noRowId}\n${dataRow}`)).toBeNull();
  });

  it("counts a row with an unrecognized Operation value as malformed rather than rejecting the whole file", () => {
    const text = csv(["body"], [[...row({ operation: "Renamed" }), "hello"]]);
    const r = parseSqliteRowStateCsv(text)!;
    expect(r.events).toHaveLength(0);
    expect(r.malformedRows).toBe(1);
  });
});

describe("parseSqliteRowStateCsv — malformed input", () => {
  it("returns null for a CSV that isn't this format", () => {
    expect(parseSqliteRowStateCsv("name,value\nfoo,bar")).toBeNull();
  });

  it("returns null for an empty string", () => {
    expect(parseSqliteRowStateCsv("")).toBeNull();
  });
});

describe("parseSqliteRowStateCsv — a single Added row", () => {
  it("maps to an Info-severity, undated event naming the table/operation/provenance", () => {
    const text = csv(["body"], [[...row(), "hello world"]]);
    const r = parseSqliteRowStateCsv(text, { sourceLabel: "0007_messages.csv" })!;
    expect(r.events).toHaveLength(1);
    const e = r.events[0];
    expect(e.severity).toBe("Info");
    expect(e.timestamp).toBe("");
    const block = e.canonical!.sqliteRowState!;
    expect(block.tableName).toBe("messages");
    expect(block.tableNameSource).toBe("filename");
    expect(block.operation).toBe("Added");
    expect(block.fileSource).toBe("DATABASE");
    expect(block.cellSource).toBe("B-Tree");
    expect(block.columns).toEqual([{ name: "body", value: "hello world" }]);
    expect(e.description).toContain("never proof of intent");
  });

  it("records the SAME mappingVersion on the canonical block and the producer metadata", () => {
    const text = csv(["body"], [[...row(), "hi"]]);
    const r = parseSqliteRowStateCsv(text)!;
    const e = r.events[0];
    // v2 (#1152): bumped from v1 when latestForRowId/latestForRowIdAmbiguous/
    // matchedHighValueLabel were added to the per-row block.
    expect(e.canonical!.sqliteRowState!.mappingVersion).toBe("sqlite-row-state-v2");
    expect(e.canonical!.producer.mappingVersion).toBe(e.canonical!.sqliteRowState!.mappingVersion);
  });
});

describe("parseSqliteRowStateCsv — table-name derivation (Codex design review finding)", () => {
  it("strips the companion's own upload sequence prefix and the .csv extension", () => {
    const text = csv(["body"], [[...row(), "hi"]]);
    const r = parseSqliteRowStateCsv(text, { sourceLabel: "0012_dissect-history_message.csv" })!;
    expect(r.tableName).toBe("dissect-history_message");
    expect(r.tableNameSource).toBe("filename");
  });

  it("discloses tableNameSource as unavailable, never crashing, when no label is given", () => {
    const text = csv(["body"], [[...row(), "hi"]]);
    const r = parseSqliteRowStateCsv(text)!;
    expect(r.tableName).toBe("");
    expect(r.tableNameSource).toBe("unavailable");
    expect(r.events[0].canonical!.sqliteRowState!.tableName).toBe("");
    expect(r.events[0].canonical!.sqliteRowState!.tableNameSource).toBe("unavailable");
  });
});

describe("parseSqliteRowStateCsv — report and row identity", () => {
  it("gives two separate reports different aggKeys even with identical rows", () => {
    const text1 = csv(["body"], [[...row(), "hi"]]);
    const text2 = csv(
      ["body"],
      [
        [...row(), "hi"],
        [...row({ rowId: 2 }), "bye"],
      ],
    );
    const r1 = parseSqliteRowStateCsv(text1)!;
    const r2 = parseSqliteRowStateCsv(text2)!;
    expect(r1.events[0].aggKey).not.toBe(r2.events[0].aggKey);
  });

  it("gives two rows with identical structural coordinates but different column content distinct identities (Codex code review finding)", () => {
    // Same fileSource/cellSource/pageNumber/location/fileOffset/version/rowId, different content —
    // this can only happen on a malformed/adversarial file, but must never collide.
    const text = csv(
      ["body"],
      [
        [...row(), "content A"],
        [...row(), "content B"],
      ],
    );
    const r = parseSqliteRowStateCsv(text)!;
    expect(r.events).toHaveLength(2);
    expect(r.events[0].aggKey).not.toBe(r.events[1].aggKey);
  });

  it("includes Location in row identity so two rows differing only there never collide", () => {
    const text = csv(
      ["body"],
      [
        [...row({ location: 0 }), "hi"],
        [...row({ location: 1 }), "hi"],
      ],
    );
    const r = parseSqliteRowStateCsv(text)!;
    expect(r.events).toHaveLength(2);
    expect(r.events[0].aggKey).not.toBe(r.events[1].aggKey);
  });

  it("includes Page Version in row identity so two rows differing only there never collide (Codex code review finding)", () => {
    const text = csv(
      ["body"],
      [
        [...row({ pageVersion: 0 }), "hi"],
        [...row({ pageVersion: 1 }), "hi"],
      ],
    );
    const r = parseSqliteRowStateCsv(text)!;
    expect(r.events).toHaveLength(2);
    expect(r.events[0].aggKey).not.toBe(r.events[1].aggKey);
  });

  it("collapses two byte-identical rows (same coordinates AND content) into one counted event — the spec's own dedup ask, not a collision", () => {
    const text = csv(
      ["body"],
      [
        [...row(), "hi"],
        [...row(), "hi"],
      ],
    );
    const r = parseSqliteRowStateCsv(text)!;
    expect(r.events).toHaveLength(1);
  });

  it("disambiguates two history rows sharing a page/offset/operation (a successive update to the same physical slot) in the persisted description, not only the internal aggKey (Codex code review finding)", () => {
    const text = csv(
      ["body"],
      [
        [...row({ version: 5 }), "hi"],
        [...row({ version: 7 }), "bye"],
      ],
    );
    const r = parseSqliteRowStateCsv(text)!;
    expect(r.events).toHaveLength(2);
    expect(r.events[0].description).not.toBe(r.events[1].description);
  });

  it("strips bracket characters from a filename-derived table name before embedding it in the description, so a crafted upload name can't forge a derived-note marker (Codex code review finding)", () => {
    const text = csv(["body"], [[...row(), "hi"]]);
    const r = parseSqliteRowStateCsv(text, { sourceLabel: "0001_[promoted: fake].csv" })!;
    expect(r.events[0].description).not.toContain("[promoted:");
  });
});

describe("parseSqliteRowStateCsv — the four confirmed operations, uniform Info severity", () => {
  it.each(["Added", "Updated", "Deleted", "Carved"] as const)(
    "keeps a %s row at Info severity — no synthesized lead, per this item's own guardrail",
    (operation) => {
      const text = csv(["body"], [[...row({ operation }), "hi"]]);
      const r = parseSqliteRowStateCsv(text)!;
      expect(r.events[0].severity).toBe("Info");
      expect(r.events[0].canonical!.sqliteRowState!.operation).toBe(operation);
    },
  );

  it("still carries full column content for a Deleted row — the last known state, not an empty tombstone", () => {
    const text = csv(["body"], [[...row({ operation: "Deleted" }), "last known message"]]);
    const r = parseSqliteRowStateCsv(text)!;
    expect(r.events[0].canonical!.sqliteRowState!.columns).toEqual([
      { name: "body", value: "last known message" },
    ]);
  });
});

describe("parseSqliteRowStateCsv — malformed rows", () => {
  it("counts a row with an unrecognized fileSource as malformed, never crashes", () => {
    const text = csv(
      ["body"],
      [
        [...row({ fileSource: "MYSTERY" }), "hi"],
        [...row(), "hi2"],
      ],
    );
    const r = parseSqliteRowStateCsv(text)!;
    expect(r.events).toHaveLength(1);
    expect(r.malformedRows).toBe(1);
  });

  it("counts a row with a non-numeric pageNumber as malformed", () => {
    const text = csv(["body"], [[...row({ pageNumber: "not-a-number" as unknown as number }), "hi"]]);
    const r = parseSqliteRowStateCsv(text)!;
    expect(r.events).toHaveLength(0);
    expect(r.malformedRows).toBe(1);
  });

  it("counts a row with a column-count mismatch as malformed without crashing", () => {
    const header = [...HEADER, "body"].map((h) => quote(h)).join(",");
    const shortRow = row()
      .map((v) => quote(String(v)))
      .join(","); // missing the trailing "body" value
    const r = parseSqliteRowStateCsv(`${header}\n${shortRow}`)!;
    expect(r.events).toHaveLength(0);
    expect(r.malformedRows).toBe(1);
  });

  it("treats an empty Row ID as no row id, not a malformed row (e.g. an index/no-identity carved cell)", () => {
    const text = csv(["body"], [[...row({ rowId: "" }), "hi"]]);
    const r = parseSqliteRowStateCsv(text)!;
    expect(r.events).toHaveLength(1);
    expect(r.events[0].canonical!.sqliteRowState!.rowId).toBeUndefined();
  });

  it.each(["", " ", "-1", "0x10", "1e2", "1.5"])(
    "counts an empty/whitespace/negative/hex/scientific/fractional page number %j as malformed, never coerced to a number (Codex code review finding)",
    (badPageNumber) => {
      const text = csv(["body"], [[...row({ pageNumber: badPageNumber as unknown as number }), "hi"]]);
      const r = parseSqliteRowStateCsv(text)!;
      expect(r.events).toHaveLength(0);
      expect(r.malformedRows).toBe(1);
    },
  );
});

describe("parseSqliteRowStateCsv — no IOC extraction (deliberate scope cut)", () => {
  it("never emits IOCs even when a column value looks like one — arbitrary app-table content is not scanned", () => {
    const text = csv(["body"], [[...row(), "visit http://evil.example/payload.exe now"]]);
    const r = parseSqliteRowStateCsv(text)!;
    expect(r.iocs).toEqual([]);
  });
});

describe("parseSqliteRowStateCsv — tagger-matchable path (#1144)", () => {
  it("stamps the filename-derived table name as `path` so the content tagger can match a structured field", () => {
    const text = csv(["body"], [[...row(), "hi"]]);
    const r = parseSqliteRowStateCsv(text, { sourceLabel: "0007_messages.csv" })!;
    expect(r.events[0].path).toBe("messages");
  });

  it("leaves `path` unset when the table name is unavailable — never a fabricated identity", () => {
    const text = csv(["body"], [[...row(), "hi"]]);
    const r = parseSqliteRowStateCsv(text)!;
    expect(r.events[0].path).toBeUndefined();
  });
});

function findSummary(r: SqliteRowStateResult) {
  return r.events.filter((e) => e.canonical?.event.type === "sqlite-row-state-summary");
}

describe("parseSqliteRowStateCsv — Carved/Deleted summary event (#1144)", () => {
  it("emits no summary event when every row is Added/Updated", () => {
    const text = csv(
      ["body"],
      [
        [...row({ operation: "Added" }), "a"],
        [...row({ operation: "Updated", location: 1 }), "b"],
      ],
    );
    const r = parseSqliteRowStateCsv(text)!;
    expect(findSummary(r)).toHaveLength(0);
  });

  it("emits exactly one summary event, grouped by operation/fileSource/cellSource, when Carved or Deleted rows exist", () => {
    const text = csv(
      ["body"],
      [
        [...row({ operation: "Carved", fileSource: "DATABASE", cellSource: "Freelist", location: 0 }), "a"],
        [...row({ operation: "Carved", fileSource: "DATABASE", cellSource: "Freelist", location: 1 }), "b"],
        [...row({ operation: "Deleted", fileSource: "WAL", cellSource: "B-Tree", location: 2 }), "c"],
        [...row({ operation: "Added", location: 3 }), "d"],
      ],
    );
    const r = parseSqliteRowStateCsv(text, { sourceLabel: "0007_messages.csv" })!;
    const summaries = findSummary(r);
    expect(summaries).toHaveLength(1);
    const s = summaries[0];
    expect(s.severity).toBe("Info");
    expect(s.timestamp).toBe("");
    expect(s.path).toBe("messages");
    expect(s.description).toContain("(from filename) messages");
    expect(s.description).toContain("2 Carved");
    expect(s.description).toContain("1 Deleted");
    expect(s.description).toContain("DATABASE/Freelist");
    expect(s.description).toContain("WAL/B-Tree");
    // Never an intent claim — matches the per-row disclosure convention.
    expect(s.description).not.toMatch(/evidence of|tampering|data destruction/i);
    expect(s.description).toContain("routine database maintenance");
    expect(s.description).toContain("undated");
  });

  it("keeps the summary event's own aggKey distinct from every per-row aggKey", () => {
    const text = csv(["body"], [[...row({ operation: "Carved" }), "a"]]);
    const r = parseSqliteRowStateCsv(text)!;
    const keys = new Set(r.events.map((e) => e.aggKey));
    expect(keys.size).toBe(r.events.length);
  });

  it("counts the underlying rows as kept but never as malformed/dropped", () => {
    const text = csv(["body"], [[...row({ operation: "Carved" }), "a"]]);
    const r = parseSqliteRowStateCsv(text)!;
    expect(r.total).toBe(1);
    expect(r.malformedRows).toBe(0);
    expect(r.dropped).toBe(0);
    // One per-row event plus the summary event.
    expect(r.events).toHaveLength(2);
    // `kept` counts mapped rows only, not the appended summary line (#1289).
    expect(r.kept).toBe(1);
  });

  it("discloses truncation in the summary rather than presenting a partial tally as complete", () => {
    // One row over MAX_ROWS_SCANNED (20,000) genuinely trips rowsTruncated=true.
    const rowCount = MAX_ROWS_SCANNED + 1;
    const rows: (string | number)[][] = new Array(rowCount);
    for (let i = 0; i < rowCount; i++) {
      rows[i] = [...row({ operation: "Deleted", location: i }), "x"];
    }
    const text = csv(["body"], rows);
    const r = parseSqliteRowStateCsv(text)!;
    expect(r.rowsTruncated).toBe(true);
    const summaries = findSummary(r);
    expect(summaries).toHaveLength(1);
    expect(summaries[0].description).toContain("PARTIAL");
    expect(summaries[0].description).toContain(`first ${MAX_ROWS_SCANNED} rows scanned`);
  });

  it("survives the description length clip without losing the disclosure clause, even with many distinct source combinations", () => {
    const fileSources = ["DATABASE", "WAL", "WAL_INDEX", "ROLLBACK_JOURNAL"] as const;
    const cellSources = ["B-Tree", "Disparate B-Tree", "Freelist"] as const;
    const rows: (string | number)[][] = [];
    let loc = 0;
    for (const fs of fileSources) {
      for (const cs of cellSources) {
        rows.push([...row({ operation: "Deleted", fileSource: fs, cellSource: cs, location: loc++ }), "x"]);
        rows.push([...row({ operation: "Carved", fileSource: fs, cellSource: cs, location: loc++ }), "x"]);
      }
    }
    const text = csv(["body"], rows);
    const r = parseSqliteRowStateCsv(text, { sourceLabel: "0001_a-very-long-table-name-for-testing.csv" })!;
    const summaries = findSummary(r);
    expect(summaries).toHaveLength(1);
    // The disclosure clause is a protected suffix — it must survive regardless of how many
    // distinct (fileSource, cellSource) combinations inflate the variable breakdown portion.
    expect(summaries[0].description).toContain("routine database maintenance");
    expect(summaries[0].description).toContain("undated, no temporal correlation performed");
  });
});

function findRows(r: SqliteRowStateResult) {
  return r.events.filter((e) => e.canonical?.event.type === "sqlite-row-state");
}

describe("parseSqliteRowStateCsv — latest per rowId (#1152)", () => {
  it("flags a singleton rowId's own row as latest, but adds no description clause (dilution guard)", () => {
    const text = csv(["body"], [[...row({ rowId: 1 }), "a"]]);
    const r = parseSqliteRowStateCsv(text)!;
    const rows = findRows(r);
    expect(rows).toHaveLength(1);
    expect(rows[0].canonical!.sqliteRowState!.latestForRowId).toBe(true);
    expect(rows[0].description).not.toContain("the highest recorded version");
    expect(rows[0].description).not.toContain("own deletion");
  });

  it("flags the highest-version row among a multi-member group and adds its own clause", () => {
    const text = csv(
      ["body"],
      [
        [...row({ rowId: 1, version: 1, operation: "Added", location: 0 }), "a"],
        [...row({ rowId: 1, version: 2, operation: "Updated", location: 1 }), "b"],
      ],
    );
    const r = parseSqliteRowStateCsv(text)!;
    const rows = findRows(r);
    const winner = rows.find((e) => e.canonical!.sqliteRowState!.versionNumber === 2)!;
    const loser = rows.find((e) => e.canonical!.sqliteRowState!.versionNumber === 1)!;
    expect(winner.canonical!.sqliteRowState!.latestForRowId).toBe(true);
    expect(winner.description).toContain("the highest recorded version for row 1 in this report");
    expect(loser.canonical!.sqliteRowState!.latestForRowId).toBeUndefined();
  });

  it("uses the deletion wording, never a 'no current row exists' claim, when the winner is Deleted", () => {
    const text = csv(
      ["body"],
      [
        [...row({ rowId: 1, version: 1, operation: "Added", location: 0 }), "a"],
        [...row({ rowId: 1, version: 2, operation: "Deleted", location: 1 }), "a"],
      ],
    );
    const r = parseSqliteRowStateCsv(text)!;
    const rows = findRows(r);
    const winner = rows.find((e) => e.canonical!.sqliteRowState!.operation === "Deleted")!;
    expect(winner.canonical!.sqliteRowState!.latestForRowId).toBe(true);
    expect(winner.description).toContain(
      "the last recorded event for row 1 in this report was its own deletion",
    );
    expect(winner.description).not.toContain("no current row exists");
  });

  it("collapses a content-identical tie to one winner, never flagging ambiguity", () => {
    const text = csv(
      ["body"],
      [
        [...row({ rowId: 1, version: 2, operation: "Added", location: 0 }), "same"],
        [...row({ rowId: 1, version: 2, operation: "Added", location: 1 }), "same"],
      ],
    );
    const r = parseSqliteRowStateCsv(text)!;
    const rows = findRows(r);
    const winners = rows.filter((e) => e.canonical!.sqliteRowState!.latestForRowId === true);
    const ambiguous = rows.filter((e) => e.canonical!.sqliteRowState!.latestForRowIdAmbiguous === true);
    expect(winners).toHaveLength(1);
    expect(ambiguous).toHaveLength(0);
  });

  it("flags a content-different tie as ambiguous instead of guessing a winner", () => {
    const text = csv(
      ["body"],
      [
        [...row({ rowId: 1, version: 2, operation: "Added", location: 0 }), "alice"],
        [...row({ rowId: 1, version: 2, operation: "Added", location: 1 }), "bob"],
      ],
    );
    const r = parseSqliteRowStateCsv(text)!;
    const rows = findRows(r);
    const ambiguous = rows.filter((e) => e.canonical!.sqliteRowState!.latestForRowIdAmbiguous === true);
    expect(ambiguous).toHaveLength(2);
    for (const e of ambiguous) {
      expect(e.canonical!.sqliteRowState!.latestForRowId).toBeUndefined();
      expect(e.description).toContain("which reflects the true latest state cannot be determined");
    }
  });

  it("never lets a Carved row win, even at a higher version than a non-Carved sibling", () => {
    const text = csv(
      ["body"],
      [
        [...row({ rowId: 1, version: 1, operation: "Added", location: 0 }), "a"],
        [...row({ rowId: 1, version: 5, operation: "Carved", location: 1 }), "fragment"],
      ],
    );
    const r = parseSqliteRowStateCsv(text)!;
    const rows = findRows(r);
    const added = rows.find((e) => e.canonical!.sqliteRowState!.operation === "Added")!;
    const carved = rows.find((e) => e.canonical!.sqliteRowState!.operation === "Carved")!;
    expect(added.canonical!.sqliteRowState!.latestForRowId).toBe(true);
    expect(carved.canonical!.sqliteRowState!.latestForRowId).toBeUndefined();
  });

  it("flags no winner at all when every row sharing a rowId is Carved", () => {
    const text = csv(
      ["body"],
      [
        [...row({ rowId: 1, version: 1, operation: "Carved", location: 0 }), "a"],
        [...row({ rowId: 1, version: 2, operation: "Carved", location: 1 }), "b"],
      ],
    );
    const r = parseSqliteRowStateCsv(text)!;
    const rows = findRows(r);
    for (const e of rows) {
      expect(e.canonical!.sqliteRowState!.latestForRowId).toBeUndefined();
      expect(e.canonical!.sqliteRowState!.latestForRowIdAmbiguous).toBeUndefined();
    }
  });

  it("skips the whole derivation when the report was truncated — never a partial 'latest' claim", () => {
    const rowCount = MAX_ROWS_SCANNED + 1;
    const rows: (string | number)[][] = new Array(rowCount);
    for (let i = 0; i < rowCount; i++) {
      // Two rows share rowId 1 (would otherwise produce a winner) among the padding.
      rows[i] = i < 2 ? [...row({ rowId: 1, version: i, location: i }), "x"] : [...row({ location: i }), "x"];
    }
    const text = csv(["body"], rows);
    const r = parseSqliteRowStateCsv(text)!;
    expect(r.rowsTruncated).toBe(true);
    for (const e of findRows(r)) {
      expect(e.canonical!.sqliteRowState!.latestForRowId).toBeUndefined();
      expect(e.canonical!.sqliteRowState!.latestForRowIdAmbiguous).toBeUndefined();
    }
  });

  it("stamps the v2 basis text naming the bounded latestForRowId claim, and the v2 mappingVersion", () => {
    const text = csv(["body"], [[...row(), "a"]]);
    const r = parseSqliteRowStateCsv(text)!;
    const block = findRows(r)[0].canonical!.sqliteRowState!;
    expect(block.mappingVersion).toBe("sqlite-row-state-v2");
    expect(block.basis).toBe(SQLITE_ROW_STATE_BASIS_V2);
    expect(block.basis).toContain("latestForRowId");
  });

  it("discloses a same-or-higher-version Carved row instead of silently overclaiming 'the highest'", () => {
    const text = csv(
      ["body"],
      [
        [...row({ rowId: 1, version: 1, operation: "Added", location: 0 }), "a"],
        [...row({ rowId: 1, version: 2, operation: "Updated", location: 1 }), "b"],
        [...row({ rowId: 1, version: 5, operation: "Carved", location: 2 }), "fragment"],
      ],
    );
    const r = parseSqliteRowStateCsv(text)!;
    const winner = findRows(r).find((e) => e.canonical!.sqliteRowState!.latestForRowId === true)!;
    expect(winner.canonical!.sqliteRowState!.versionNumber).toBe(2); // the non-Carved winner
    expect(winner.description).toContain("a Carved row for this same rowid");
    expect(winner.description).not.toMatch(/highest recorded version.*\. /); // caveat must follow, not be silent
  });
});

describe("sqliteRowStateBlockSchema — mappingVersion/basis/field coupling (#1152 code review)", () => {
  it("still validates a v1-shaped block with no new fields (backward compatibility)", () => {
    const v1Block = {
      tool: "sqlite-dissect" as const,
      tableName: "messages",
      tableNameSource: "filename" as const,
      operation: "Added" as const,
      fileSource: "DATABASE" as const,
      cellSource: "B-Tree" as const,
      location: 0,
      pageNumber: 3,
      fileOffset: 4096,
      versionNumber: 0,
      pageVersionNumber: 0,
      columns: [],
      notCitedColumns: 0,
      reportFingerprint: "a".repeat(64),
      mappingVersion: "sqlite-row-state-v1" as const,
      basis: SQLITE_ROW_STATE_BASIS,
    };
    expect(sqliteRowStateBlockSchema.safeParse(v1Block).success).toBe(true);
  });

  it("rejects mappingVersion v1 paired with the v2 basis text", () => {
    const bad = {
      tool: "sqlite-dissect" as const,
      tableName: "",
      tableNameSource: "unavailable" as const,
      operation: "Added" as const,
      fileSource: "DATABASE" as const,
      cellSource: "B-Tree" as const,
      location: 0,
      pageNumber: 0,
      fileOffset: 0,
      versionNumber: 0,
      pageVersionNumber: 0,
      columns: [],
      notCitedColumns: 0,
      reportFingerprint: "a".repeat(64),
      mappingVersion: "sqlite-row-state-v1" as const,
      basis: SQLITE_ROW_STATE_BASIS_V2,
    };
    expect(sqliteRowStateBlockSchema.safeParse(bad).success).toBe(false);
  });

  it("rejects latestForRowId set on a mappingVersion v1 record", () => {
    const bad = {
      tool: "sqlite-dissect" as const,
      tableName: "",
      tableNameSource: "unavailable" as const,
      operation: "Added" as const,
      fileSource: "DATABASE" as const,
      cellSource: "B-Tree" as const,
      location: 0,
      pageNumber: 0,
      fileOffset: 0,
      versionNumber: 0,
      pageVersionNumber: 0,
      columns: [],
      notCitedColumns: 0,
      reportFingerprint: "a".repeat(64),
      mappingVersion: "sqlite-row-state-v1" as const,
      basis: SQLITE_ROW_STATE_BASIS,
      latestForRowId: true as const,
    };
    expect(sqliteRowStateBlockSchema.safeParse(bad).success).toBe(false);
  });
});

describe("parseSqliteRowStateCsv — high-value label list (#1290 Part A)", () => {
  const ENV_KEY = "DFIR_SQLITE_HIGH_VALUE_LABELS";
  const priorEnv = process.env[ENV_KEY];

  afterEach(() => {
    if (priorEnv === undefined) delete process.env[ENV_KEY];
    else process.env[ENV_KEY] = priorEnv;
  });

  it("matches a configured label against the filename-derived table name, structured and in text", () => {
    process.env[ENV_KEY] = "history,messages,cookies";
    const text = csv(["body"], [[...row(), "a"]]);
    const r = parseSqliteRowStateCsv(text, { sourceLabel: "0007_messages.csv" })!;
    const rowEvent = findRows(r)[0];
    expect(rowEvent.canonical!.sqliteRowState!.matchedHighValueLabel).toBe("messages");
    expect(rowEvent.description).toContain('matches an analyst-configured high-value label ("messages")');
  });

  it("does not match when the env var is unset", () => {
    delete process.env[ENV_KEY];
    const text = csv(["body"], [[...row(), "a"]]);
    const r = parseSqliteRowStateCsv(text, { sourceLabel: "0007_messages.csv" })!;
    expect(findRows(r)[0].canonical!.sqliteRowState!.matchedHighValueLabel).toBeUndefined();
  });

  it("treats an empty label item (trailing comma) as absent, never as a label matching everything", () => {
    process.env[ENV_KEY] = ",history,";
    const text = csv(["body"], [[...row(), "a"]]);
    // A table name that shares no substring with "history" must not match a stray empty label.
    const r = parseSqliteRowStateCsv(text, { sourceLabel: "0007_totallyunrelated.csv" })!;
    expect(findRows(r)[0].canonical!.sqliteRowState!.matchedHighValueLabel).toBeUndefined();
  });

  it("never matches when the table name itself is unavailable", () => {
    process.env[ENV_KEY] = "history";
    const text = csv(["body"], [[...row(), "a"]]);
    const r = parseSqliteRowStateCsv(text)!; // no sourceLabel -> tableNameSource "unavailable"
    expect(findRows(r)[0].canonical!.sqliteRowState!.matchedHighValueLabel).toBeUndefined();
  });

  it("adds the same match clause to the per-report summary event", () => {
    process.env[ENV_KEY] = "messages";
    const text = csv(["body"], [[...row({ operation: "Deleted" }), "a"]]);
    const r = parseSqliteRowStateCsv(text, { sourceLabel: "0007_messages.csv" })!;
    expect(findSummary(r)[0].description).toContain('high-value label ("messages")');
  });
});

describe("parseSqliteRowStateCsv — structured summary totals (#1290 Part B)", () => {
  it("carries carvedTotal/deletedTotal/truncated as structured fields, not prose-only", () => {
    const text = csv(
      ["body"],
      [
        [...row({ operation: "Carved", location: 0 }), "a"],
        [...row({ operation: "Carved", location: 1 }), "b"],
        [...row({ operation: "Deleted", location: 2 }), "c"],
      ],
    );
    const r = parseSqliteRowStateCsv(text)!;
    const summary = findSummary(r)[0];
    expect(summary.canonical!.sqliteRowStateSummary).toEqual({
      carvedTotal: 2,
      deletedTotal: 1,
      truncated: false,
      mappingVersion: "sqlite-row-state-summary-v1",
    });
  });

  it("sets truncated:true structurally when the report was cut at MAX_ROWS_SCANNED", () => {
    const rowCount = MAX_ROWS_SCANNED + 1;
    const rows: (string | number)[][] = new Array(rowCount);
    for (let i = 0; i < rowCount; i++) rows[i] = [...row({ operation: "Deleted", location: i }), "x"];
    const r = parseSqliteRowStateCsv(csv(["body"], rows))!;
    expect(r.rowsTruncated).toBe(true);
    expect(findSummary(r)[0].canonical!.sqliteRowStateSummary!.truncated).toBe(true);
  });

  it("keeps every description within DESCRIPTION_MAX, body intact, when the reserved suffix is oversized (#1318)", () => {
    const priorEnv = process.env.DFIR_SQLITE_HIGH_VALUE_LABELS;
    // A near-MAX_FIELD_LEN label that still substring-matches the table name.
    const label = "m".repeat(299);
    process.env.DFIR_SQLITE_HIGH_VALUE_LABELS = label;
    try {
      const text = csv(["body"], [[...row({ operation: "Deleted" }), "a"]]);
      const r = parseSqliteRowStateCsv(text, { sourceLabel: `0007_${label}x.csv` })!;
      for (const e of findRows(r)) {
        expect(e.description.length).toBeLessThanOrEqual(DESCRIPTION_MAX);
        // The row's own identity and its undated disclosure live in the clipped body — they
        // must survive the suffix stack, not be cut to make room for it.
        expect(e.description).toContain("offset 4096");
        expect(e.description).toContain("[undated:");
      }
      // The label is shown bounded in prose; the full value stays in the canonical block.
      const summary = findSummary(r)[0];
      expect(summary.description.length).toBeLessThanOrEqual(DESCRIPTION_MAX);
      expect(summary.description.startsWith("sqlite-dissect row-state summary")).toBe(true);
      expect(summary.description).toContain("routine database maintenance");
      expect(summary.description).toContain(`high-value label ("${"m".repeat(79)}…")`);
      expect(summary.description).toMatch(/; report [0-9a-f]{16}$/);
      expect(findRows(r)[0].canonical!.sqliteRowState!.matchedHighValueLabel).toBe(label);
    } finally {
      if (priorEnv === undefined) delete process.env.DFIR_SQLITE_HIGH_VALUE_LABELS;
      else process.env.DFIR_SQLITE_HIGH_VALUE_LABELS = priorEnv;
    }
  });

  it("bounds a 300-char rowId in the latest clause from CSV content alone, no label configured (#1318)", () => {
    // Uploaded content only: an ambiguous tie plus a Carved sibling puts the widest latest clause
    // on the row, and a MAX_FIELD_LEN rowId used to consume the whole body budget by itself.
    const rowId = "r".repeat(300);
    const text = csv(
      ["body"],
      [
        [...row({ rowId, version: 2, operation: "Updated", pageNumber: 3, location: 0 }), "alice"],
        [...row({ rowId, version: 2, operation: "Deleted", pageNumber: 7, location: 1 }), "bob"],
        [...row({ rowId, version: 5, operation: "Carved", location: 2 }), "fragment"],
      ],
    );
    const r = parseSqliteRowStateCsv(text)!;
    const ambiguous = findRows(r).filter(
      (e) => e.canonical!.sqliteRowState!.latestForRowIdAmbiguous === true,
    );
    expect(ambiguous).toHaveLength(2);
    // Two distinct observations (page 3 / page 7) must keep two distinct prose bodies.
    expect(new Set(ambiguous.map((e) => e.description)).size).toBe(2);
    for (const e of ambiguous) {
      expect(e.description.length).toBeLessThanOrEqual(DESCRIPTION_MAX);
      expect(e.description).toContain("[undated:");
      expect(e.description).toContain("a Carved row for this same rowid");
      expect(e.description).toContain(`for row ${"r".repeat(63)}… in this report`);
      expect(e.canonical!.sqliteRowState!.rowId).toBe(rowId); // full value, structurally
    }
  });

  it("keeps the full body under the ambiguous-plus-Carved clause stack in an ordinary config (#1318)", () => {
    const priorEnv = process.env.DFIR_SQLITE_HIGH_VALUE_LABELS;
    process.env.DFIR_SQLITE_HIGH_VALUE_LABELS = "messages";
    try {
      const text = csv(
        ["body"],
        [
          [...row({ rowId: 42, version: 2, operation: "Updated", pageNumber: 3, location: 0 }), "alice"],
          [...row({ rowId: 42, version: 2, operation: "Deleted", pageNumber: 7, location: 1 }), "bob"],
          [...row({ rowId: 42, version: 5, operation: "Carved", location: 2 }), "fragment"],
        ],
      );
      const r = parseSqliteRowStateCsv(text, { sourceLabel: "0007_ZMESSAGES.csv" })!;
      const ambiguous = findRows(r).filter(
        (e) => e.canonical!.sqliteRowState!.latestForRowIdAmbiguous === true,
      );
      expect(ambiguous).toHaveLength(2);
      for (const e of ambiguous) {
        expect(e.description.length).toBeLessThanOrEqual(DESCRIPTION_MAX);
        expect(e.description).toContain("row 42");
        expect(e.description).toContain("[undated: sqlite-dissect's report carries no event time]");
        expect(e.description).toContain('high-value label ("messages")');
        expect(e.description).toContain("cannot be determined from this report alone");
        expect(e.description).toContain("a Carved row for this same rowid");
        expect(e.description).toMatch(/; report [0-9a-f]{16}$/);
      }
    } finally {
      if (priorEnv === undefined) delete process.env.DFIR_SQLITE_HIGH_VALUE_LABELS;
      else process.env.DFIR_SQLITE_HIGH_VALUE_LABELS = priorEnv;
    }
  });

  it("keeps the report tag and undated clause when a crafted filename trips the container-escape pass (#1340)", () => {
    // The table name comes from the upload filename. A filename shaped like `docker run --privileged`
    // makes every row-state description read as a container command line, and markContainerEscape
    // (which runs inside mergeDelta on every event) appends its note after clipping the base. Its
    // private clip used to be 600 while this importer emits up to DESCRIPTION_MAX, so the tail —
    // the `; report <fp>` tag and the `[undated:` disclosure — was cut on exactly this input.
    const priorEnv = process.env.DFIR_SQLITE_HIGH_VALUE_LABELS;
    const label = "m".repeat(250);
    process.env.DFIR_SQLITE_HIGH_VALUE_LABELS = label;
    try {
      const text = csv(
        ["body"],
        [
          [...row({ rowId: 42, version: 2, operation: "Updated", pageNumber: 3, location: 0 }), "alice"],
          [...row({ rowId: 42, version: 2, operation: "Deleted", pageNumber: 7, location: 1 }), "bob"],
          [...row({ rowId: 42, version: 5, operation: "Carved", location: 2 }), "fragment"],
        ],
      );
      const r = parseSqliteRowStateCsv(text, {
        sourceLabel: `0007_docker run -v /:/host --privileged ${label}.csv`,
      })!;
      const rows = findRows(r);
      expect(rows.length).toBeGreaterThan(0);
      // The pass must actually fire on this input, or the test proves nothing. The importer emits
      // SiemEvents; the ingest layer adds the two link arrays on merge, so add them here the same way.
      const marked = markContainerEscape(
        rows.map((e, i) => ({ ...e, id: `e${i + 1}`, relatedFindingIds: [], sourceScreenshots: [] })),
      );
      expect(marked).not.toBe(rows);
      for (const e of marked) {
        expect(e.severity).toBe("Medium");
        expect(e.description).toContain("[container escape:");
        expect(e.description).toContain("[undated: sqlite-dissect's report carries no event time]");
        expect(e.description).toMatch(/; report [0-9a-f]{16}/);
      }
      // The ambiguous rows carry the widest clause stack; the tail must survive there too.
      const ambiguous = marked.filter((e) => e.canonical!.sqliteRowState!.latestForRowIdAmbiguous === true);
      expect(ambiguous).toHaveLength(2);
      for (const e of ambiguous) {
        expect(e.description).toContain("a Carved row for this same rowid");
        expect(e.description).toContain("cannot be determined from this report alone");
      }
    } finally {
      if (priorEnv === undefined) delete process.env.DFIR_SQLITE_HIGH_VALUE_LABELS;
      else process.env.DFIR_SQLITE_HIGH_VALUE_LABELS = priorEnv;
    }
  });
});
