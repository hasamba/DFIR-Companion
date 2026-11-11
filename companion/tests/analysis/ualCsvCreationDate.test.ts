import { describe, it, expect } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseM365Audit } from "../../src/analysis/m365Import.js";
import { undatedRowsNote } from "../../src/analysis/m365ExportAdapters.js";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { CloudRecordStore } from "../../src/analysis/cloudRecordStore.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";

// #2552 — a UAL CSV row whose AuditData does not parse falls back to the CSV `CreationDate`
// column, a PowerShell Export-Csv local date ("3/25/2021 12:36:42 PM"). It must be read with the
// same per-file day/month order as the MES mailbox `LastAccessed`, never passed through raw.

const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;
const HEADER = "CreationDate,UserIds,Operations,AuditData";
// AuditData cut off mid-value, as in the report: JSON.parse fails, the outer row is kept.
const TRUNCATED = '{"CreationTime":"2021-03-25T12:36:';
const goodAuditData = (creationTime: string): string =>
  JSON.stringify({
    CreationTime: creationTime,
    Operation: "New-InboxRule",
    Workload: "Exchange",
    UserId: "attacker@example.com",
  });
const row = (creationDate: string, auditData: string): string =>
  `"${creationDate}","attacker@example.com","New-InboxRule","${auditData.replace(/"/g, '""')}"`;
const csv = (...rows: string[]): string => [HEADER, ...rows].join("\n");
const times = (text: string): string[] =>
  parseM365Audit(text, { aggregate: false }).events.map((e) => e.timestamp);

describe("UAL CSV CreationDate fallback is normalised (#2552)", () => {
  it("reads a US-format CreationDate as UTC ISO when AuditData does not parse", () => {
    expect(times(csv(row("3/25/2021 12:36:42 PM", TRUNCATED)))).toEqual(["2021-03-25T12:36:42Z"]);
  });

  it("reads a day-first file day-first, including its ambiguous rows", () => {
    // 25/03 fixes the file's order; 3/4 is then 3 April, not 4 March.
    const text = csv(row("25/03/2021 14:40:00", TRUNCATED), row("3/4/2021 10:00:00", TRUNCATED));
    expect(times(text).sort()).toEqual(["2021-03-25T14:40:00Z", "2021-04-03T10:00:00Z"]);
  });

  it("an ambiguous-only file leaves the failed row undated and counts it in the import note", () => {
    const text = csv(
      row("3/4/2021 10:00:00 AM", TRUNCATED),
      row("3/5/2021 10:00:00 AM", goodAuditData("2021-03-05T10:00:00")),
    );
    const parsed = parseM365Audit(text, { aggregate: false });
    expect(parsed.events.map((e) => e.timestamp).sort()).toEqual(["", "2021-03-05T10:00:00Z"]);
    // Only the row that actually needed CreationDate is undated; the one AuditData dated is not.
    expect(parsed.undatedRows).toEqual({ rows: 1, mixedOrders: false });
    expect(undatedRowsNote(parsed.undatedRows)).toContain(
      "1 audit row(s) have no time: the file's day/month order could not be determined",
    );
  });

  it("a parsed AuditData CreationTime wins over a disagreeing CreationDate", () => {
    const text = csv(row("3/25/2021 12:36:42 PM", goodAuditData("2021-03-25T09:00:00")));
    expect(times(text)).toEqual(["2021-03-25T09:00:00Z"]);
  });

  it("every timestamp from the MES UAL-Combined.csv fixture is ISO or empty, with no undated rows", () => {
    const text = readFileSync(
      new URL("../fixtures/cloudCompat/mes-4.1.0/UAL-Combined.csv", import.meta.url),
      "utf8",
    );
    const parsed = parseM365Audit(text, { aggregate: false });
    expect(parsed.events.length).toBeGreaterThan(0);
    for (const e of parsed.events) expect(e.timestamp === "" || ISO.test(e.timestamp)).toBe(true);
    expect(parsed.undatedRows?.rows ?? 0).toBe(0);
  });

  it("the streaming import reads the same fallback date", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-ual-csv-date-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const superTimelineStore = new SuperTimelineStore(cases);
    const pipeline = new AnalysisPipeline({
      stateStore: new StateStore(cases),
      superTimelineStore,
      cloudRecordStore: new CloudRecordStore(cases),
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    });
    const path = join(root, "ual.csv");
    await writeFile(path, csv(row("3/25/2021 12:36:42 PM", TRUNCATED)));
    const { state } = await pipeline.importCloudFile("c1", "m365", path, {
      label: "ual.csv",
      idPrefix: "s1",
      importedAt: "2026-11-02T00:00:00Z",
      batchRecords: 2,
    });
    const forensic = state.forensicTimeline.filter((e) => e.description.includes("New-InboxRule"));
    const superRows = (await superTimelineStore.query("c1", { limit: 50 })).events.filter((e) =>
      e.description.includes("New-InboxRule"),
    );
    const stamps = [...forensic.map((e) => e.timestamp), ...superRows.map((e) => e.timestamp)];
    expect(stamps.length).toBeGreaterThan(0);
    expect(new Set(stamps)).toEqual(new Set(["2021-03-25T12:36:42Z"]));
  });
});
