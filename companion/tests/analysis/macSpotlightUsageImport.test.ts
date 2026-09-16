import { describe, it, expect } from "vitest";
import {
  parseMacSpotlightUsageCsv,
  MAX_SPOTLIGHT_ROWS_SCANNED,
} from "../../src/analysis/macSpotlightUsageImport.js";

// Column set verified live against mac_apt's (ydkhatri) own spotlight.py — ProcessStoreItem()'s
// sparse per-item row and CreateViewAndIndexes()'s real kMDItem* column names.
const HEADER = [
  "ID",
  "Parent_ID",
  "Date_Updated",
  "kMDItemDisplayName",
  "_kMDItemFileName",
  "kMDItemUseCount",
  "kMDItemLastUsedDate",
  "kMDItemUsedDates",
  "kMDItemDownloadedDate",
  "kMDItemWhereFroms",
];

function csvRow(fields: Record<string, string>): string {
  return HEADER.map((h) => {
    const v = fields[h] ?? "";
    return v.includes(",") ? `"${v}"` : v;
  }).join(",");
}

function csv(rows: string[]): string {
  return [HEADER.join(","), ...rows].join("\n");
}

const BASE_ROW = {
  ID: "1001",
  Parent_ID: "42",
  Date_Updated: "2024-03-01T00:00:00Z",
  kMDItemDisplayName: "payload.exe",
  _kMDItemFileName: "payload.exe",
  kMDItemUseCount: "3",
  kMDItemLastUsedDate: "2024-03-10T00:00:00Z",
  kMDItemUsedDates: "2024-03-08, 2024-03-09, 2024-03-10",
  kMDItemDownloadedDate: "2024-03-08T00:00:00Z",
  kMDItemWhereFroms: "https://example.com/download?ref=1,https://example.com/",
};

describe("parseMacSpotlightUsageCsv — format detection", () => {
  it("returns null for an empty string", () => {
    expect(parseMacSpotlightUsageCsv("")).toBeNull();
  });

  it("returns null when neither ID nor Date_Updated is present", () => {
    expect(parseMacSpotlightUsageCsv("foo,bar\n1,2")).toBeNull();
  });

  it("returns null when ID/Date_Updated are present but no usage/download column exists", () => {
    expect(parseMacSpotlightUsageCsv("ID,Date_Updated,kMDItemKind\n1,2024-01-01,Application")).toBeNull();
  });

  it("parses a real mac_apt Spotlight store-item CSV", () => {
    const r = parseMacSpotlightUsageCsv(csv([csvRow(BASE_ROW)]));
    expect(r).not.toBeNull();
    expect(r!.kept).toBe(1);
  });
});

describe("parseMacSpotlightUsageCsv — usage-signal filtering", () => {
  it("filters out a row with only Date_Updated and no usage/download signal", () => {
    const r = parseMacSpotlightUsageCsv(
      csv([
        csvRow({
          ...BASE_ROW,
          kMDItemUseCount: "",
          kMDItemLastUsedDate: "",
          kMDItemUsedDates: "",
          kMDItemDownloadedDate: "",
          kMDItemWhereFroms: "",
        }),
      ]),
    )!;
    expect(r.kept).toBe(0);
    expect(r.filteredNoSignalRows).toBe(1);
  });

  it("keeps a row whose only signal is an explicit useCount of 0 — never conflated with absent", () => {
    const r = parseMacSpotlightUsageCsv(
      csv([
        csvRow({
          ...BASE_ROW,
          kMDItemUseCount: "0",
          kMDItemLastUsedDate: "",
          kMDItemUsedDates: "",
          kMDItemDownloadedDate: "",
          kMDItemWhereFroms: "",
        }),
      ]),
    )!;
    expect(r.kept).toBe(1);
    expect(r.events[0].canonical!.spotlightUsage?.useCount).toBe(0);
  });
});

describe("parseMacSpotlightUsageCsv — flattened text preserved, never re-split", () => {
  it("keeps a comma-containing whereFroms value as flattened text, not silently mis-split", () => {
    const r = parseMacSpotlightUsageCsv(csv([csvRow(BASE_ROW)]))!;
    expect(r.events[0].canonical!.spotlightUsage?.whereFromsRaw).toBe(BASE_ROW.kMDItemWhereFroms);
  });
});

describe("parseMacSpotlightUsageCsv — timestamp epistemics", () => {
  it("anchors the event timestamp on lastUsedDate, never dateUpdated", () => {
    const r = parseMacSpotlightUsageCsv(csv([csvRow(BASE_ROW)]))!;
    expect(r.events[0].timestamp).toBe(BASE_ROW.kMDItemLastUsedDate);
  });

  it("stays empty when lastUsedDate is absent, even though dateUpdated is present", () => {
    const r = parseMacSpotlightUsageCsv(csv([csvRow({ ...BASE_ROW, kMDItemLastUsedDate: "" })]))!;
    expect(r.events[0].timestamp).toBe("");
    expect(r.events[0].canonical!.time.clockConfidence).toBe("unknown");
    expect(r.events[0].canonical!.spotlightUsage?.dateUpdated).toBe(BASE_ROW.Date_Updated);
  });

  it("never expands useCount into multiple synthetic events", () => {
    const r = parseMacSpotlightUsageCsv(csv([csvRow({ ...BASE_ROW, kMDItemUseCount: "47" })]))!;
    expect(r.kept).toBe(1);
  });
});

describe("parseMacSpotlightUsageCsv — path disclosure", () => {
  it("marks pathStatus not-exported when no FullPath column is present", () => {
    const r = parseMacSpotlightUsageCsv(csv([csvRow(BASE_ROW)]))!;
    expect(r.events[0].canonical!.spotlightUsage?.pathStatus).toBe("not-exported");
    expect(r.events[0].canonical!.spotlightUsage?.path).toBeUndefined();
  });
});

describe("parseMacSpotlightUsageCsv — identity, never silently collapsed across a stale index", () => {
  it("keeps two rows sharing an itemId but carrying different content as distinct events", () => {
    const r = parseMacSpotlightUsageCsv(
      csv([
        csvRow({ ...BASE_ROW, ID: "1001", kMDItemUseCount: "3" }),
        csvRow({ ...BASE_ROW, ID: "1001", kMDItemUseCount: "9" }),
      ]),
    )!;
    expect(r.kept).toBe(2);
  });

  it("collapses two byte-identical rows under aggregation", () => {
    const r = parseMacSpotlightUsageCsv(csv([csvRow(BASE_ROW), csvRow(BASE_ROW)]))!;
    expect(r.kept).toBe(1);
  });
});

describe("parseMacSpotlightUsageCsv — scan bound", () => {
  it("truncates and discloses when the report exceeds the scan cap", () => {
    const rows = Array.from({ length: MAX_SPOTLIGHT_ROWS_SCANNED + 1 }, (_, i) =>
      csvRow({ ...BASE_ROW, ID: String(i + 1) }),
    );
    const r = parseMacSpotlightUsageCsv(csv(rows))!;
    expect(r.rowsTruncated).toBe(true);
    expect(r.total).toBe(MAX_SPOTLIGHT_ROWS_SCANNED);
  });
});

describe("parseMacSpotlightUsageCsv — malformed rows", () => {
  it("counts a short row as malformed, never crashes", () => {
    const r = parseMacSpotlightUsageCsv(`${HEADER.join(",")}\n1,2`)!;
    expect(r.malformedRows).toBe(1);
    expect(r.kept).toBe(0);
  });
});

describe("parseMacSpotlightUsageCsv — severity", () => {
  it("stays Info unconditionally — corroboration, not a lead", () => {
    const r = parseMacSpotlightUsageCsv(csv([csvRow(BASE_ROW)]))!;
    expect(r.events[0].severity).toBe("Info");
  });
});
