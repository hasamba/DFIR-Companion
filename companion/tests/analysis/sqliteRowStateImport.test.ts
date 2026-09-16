import { describe, it, expect } from "vitest";
import { parseSqliteRowStateCsv, isSqliteRowStateCsv } from "../../src/analysis/sqliteRowStateImport.js";

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

describe("isSqliteRowStateCsv", () => {
  it("recognizes a real sqlite-dissect commit-history CSV", () => {
    const text = csv(["body"], [[...row(), "hello"]]);
    expect(isSqliteRowStateCsv(text)).toBe(true);
  });

  it("rejects a header missing Row ID (the WITHOUT ROWID / index-page shape, out of scope)", () => {
    const noRowId = [...HEADER.slice(0, 8), "body"].map((h) => quote(h)).join(",");
    const dataRow = ["DATABASE", 0, 0, "B-Tree", 3, 0, "Added", 4096, "hi"]
      .map((v) => quote(String(v)))
      .join(",");
    expect(isSqliteRowStateCsv(`${noRowId}\n${dataRow}`)).toBe(false);
  });

  it("rejects a CSV with the right header shape but no recognized Operation value", () => {
    const text = csv(["body"], [[...row({ operation: "Renamed" }), "hello"]]);
    expect(isSqliteRowStateCsv(text)).toBe(false);
  });

  it("rejects a plain unrelated CSV", () => {
    expect(isSqliteRowStateCsv("name,value\nfoo,bar")).toBe(false);
  });

  it("rejects an empty string", () => {
    expect(isSqliteRowStateCsv("")).toBe(false);
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
    expect(e.canonical!.sqliteRowState!.mappingVersion).toBe("sqlite-row-state-v1");
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
});

describe("parseSqliteRowStateCsv — no IOC extraction (deliberate scope cut)", () => {
  it("never emits IOCs even when a column value looks like one — arbitrary app-table content is not scanned", () => {
    const text = csv(["body"], [[...row(), "visit http://evil.example/payload.exe now"]]);
    const r = parseSqliteRowStateCsv(text)!;
    expect(r.iocs).toEqual([]);
  });
});
