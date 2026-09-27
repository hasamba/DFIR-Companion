import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createImportDebugRecorder } from "../../src/analysis/importDebug.js";
import { parseVelociraptorJson } from "../../src/analysis/velociraptorImport.js";
import { pickTime, setTimeKeySink } from "../../src/analysis/veloRowTime.js";
import { parseHayabusaTimeline } from "../../src/analysis/hayabusaImport.js";
import { parseChainsawReport } from "../../src/analysis/chainsawImport.js";
import { parseKapeCsv } from "../../src/analysis/kapeImport.js";
import { parseThorReport } from "../../src/analysis/thorImport.js";
import { parsePlasoCsv } from "../../src/analysis/plasoImport.js";
import { parseCybertriage } from "../../src/analysis/cybertriageImport.js";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { MockProvider } from "../../src/providers/provider.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";

// Every row value below carries "zqendmark", so one substring check proves no VALUE reached the summary.
const MARK = "zqendmark";

function noMarker(summary: unknown): void {
  expect(JSON.stringify(summary).toLowerCase()).not.toContain(MARK);
}
const ndjson = (rows: object[]): string => rows.map((r) => JSON.stringify(r)).join("\n");
const csv = (rows: string[][]): string =>
  rows.map((r) => r.map((v) => (/[",\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v)).join(",")).join("\n");

// ── Velociraptor ──────────────────────────────────────────────────────────────────────────────
// A generic artifact dated by Mtime (Ctime is present too, but Mtime wins), named by Fqdn.
const VR_MTIME = {
  _Source: "Custom.Zq.Listing",
  Fqdn: `${MARK}-a.example.com`,
  Mtime: "2026-02-01T10:00:00Z",
  Ctime: "2026-02-02T10:00:00Z",
  Note: `${MARK} note one`,
};
// No host key: the analyst-declared host stands in.
const VR_KEYWRITE = {
  _Source: "Custom.Zq.Listing",
  KeyLastWriteTimestamp: "2026-02-03T10:00:00Z",
  Note: `${MARK} note two`,
};
// Only the collection time dates this row.
const VR_COLLECTED = { _Source: "Custom.Zq.Listing", _ts: 1767261600, Note: `${MARK} note three` };

describe("Velociraptor import debug (#1736)", () => {
  it("records the time column pickTime SELECTED, the host source and the generic route", () => {
    const debug = createImportDebugRecorder();
    const text = ndjson([VR_MTIME, VR_KEYWRITE, VR_COLLECTED]);
    const opts = { hostFallback: `${MARK}-declared.example.com`, hostFallbackBasis: "analyst" as const };
    const r = parseVelociraptorJson(text, { ...opts, debug });
    const s = debug.summary();

    expect(s.fields.timestamp).toEqual({ Mtime: 1, KeyLastWriteTimestamp: 1, "<unlisted>": 1 });
    expect(s.fields.host).toEqual({ Fqdn: 1 });
    expect(s.fallbacks).toEqual({ generic_artifact: 3, asset_host_declared: 2 });
    expect(s.observations).toEqual({ collection_time_used: 1 });
    noMarker(s);
    // Output unchanged with a recorder.
    expect(r).toEqual(parseVelociraptorJson(text, opts));
  });

  it("the time-key hook hears pickTime only while a tally listens", () => {
    const heard: string[] = [];
    setTimeKeySink((k) => heard.push(k));
    pickTime({ LastExecution: "2026-01-01T00:00:00Z", Mtime: "2026-01-02T00:00:00Z" }, ["LastExecution"]);
    pickTime({ zq_written_at: "2026-01-03T00:00:00Z" }); // the time-NAMED column scan
    setTimeKeySink(undefined);
    pickTime({ Mtime: "2026-01-02T00:00:00Z" });
    expect(heard).toEqual(["LastExecution", "zq_written_at"]);
  });

  it("the ingest wrapper records the counts", async () => {
    const debug = createImportDebugRecorder();
    await pipeline().importVelociraptor("c1", ndjson([VR_MTIME, VR_KEYWRITE]), {
      ...BASE,
      label: "Custom.Zq.Listing.json",
      minSeverity: "Critical",
      debug,
    });
    const s = debug.summary();
    // An all-Info import is ungraded, so the floor keeps everything (severityFloor.ts).
    expect(s.omitted.below_severity_floor).toBeUndefined();
    expect(s.counts).toEqual({ total: 2, kept: 2, dropped: 0 });
    expect(s.fields.timestamp).toEqual({ Mtime: 1, KeyLastWriteTimestamp: 1 });
    noMarker(s);
  });
});

// ── Hayabusa ──────────────────────────────────────────────────────────────────────────────────
const HAYA = {
  Timestamp: "2026-02-01 10:00:00.000 +00:00",
  Computer: `${MARK}-h.example.com`,
  Channel: "Sysmon",
  EventID: 1,
  Level: "high",
  RuleTitle: `${MARK} rule`,
  Details: { Proc: `C:\\${MARK}.exe`, CmdLine: `${MARK}.exe --run` },
};
const HAYA_NO_TITLE = { Timestamp: "2026-02-01 10:00:00.000 +00:00", Level: "low", Details: {} };

describe("Hayabusa import debug (#1736)", () => {
  it("records the rule, time, host and detail keys, and a record with no rule or EID", () => {
    const debug = createImportDebugRecorder();
    const text = JSON.stringify([HAYA, HAYA_NO_TITLE]);
    const r = parseHayabusaTimeline(text, { debug });
    const s = debug.summary();
    expect(s.fields).toMatchObject({
      timestamp: { Timestamp: 1 },
      rule: { RuleTitle: 1 },
      event_id: { EventID: 1 },
      channel: { Channel: 1 },
      host: { Computer: 1 },
      process: { "<unlisted>": 1 },
      command_line: { CmdLine: 1 }, // the row's own spelling, not the candidate "Cmdline"
    });
    expect(s.skipped).toEqual({ no_rule_or_event_id: 1 });
    noMarker(s);
    expect(r).toEqual(parseHayabusaTimeline(text));
  });

  it("an analyst-declared host is a fallback, not a column", () => {
    const debug = createImportDebugRecorder();
    const { Computer: _c, ...bare } = HAYA;
    parseHayabusaTimeline(JSON.stringify([bare]), {
      hostFallback: `${MARK}-d.example.com`,
      hostFallbackBasis: "analyst",
      debug,
    });
    const s = debug.summary();
    expect(s.fallbacks).toEqual({ asset_host_declared: 1 });
    expect(s.fields.host).toBeUndefined();
    noMarker(s);
  });
});

// ── Chainsaw ──────────────────────────────────────────────────────────────────────────────────
const CHAINSAW_HIT = {
  group: "Sigma",
  kind: "individual",
  document: {
    kind: "evtx",
    data: {
      Event: {
        System: {
          Provider: { "#attributes": { Name: "Microsoft-Windows-Sysmon" } },
          EventID: 1,
          Channel: "Microsoft-Windows-Sysmon/Operational",
          Computer: `${MARK}-c.example.com`,
          TimeCreated: { "#attributes": { SystemTime: "2026-02-01T10:00:00.000Z" } },
        },
        EventData: { Image: `C:\\${MARK}.exe`, CommandLine: `${MARK}.exe -x` },
      },
    },
  },
  rule: { name: `${MARK} rule`, level: "high", tags: ["attack.t1059.001"] },
  timestamp: "2026-02-01T10:00:00.000Z",
};
const CHAINSAW_NO_DOC = { note: `${MARK} not an event` };

describe("Chainsaw import debug (#1736)", () => {
  it("records the System keys of the embedded event and a record with no event", () => {
    const debug = createImportDebugRecorder();
    const text = JSON.stringify([CHAINSAW_HIT, CHAINSAW_NO_DOC]);
    const r = parseChainsawReport(text, { debug });
    const s = debug.summary();
    // System.* paths are not on the column allowlist, so they arrive as <unlisted> — the KEY was
    // chosen, and no value can leak through it.
    expect(s.fields.timestamp).toEqual({ "<unlisted>": 1 });
    expect(s.fields.channel).toEqual({ "<unlisted>": 1 });
    expect(s.fields.host).toEqual({ "<unlisted>": 1 });
    expect(s.skipped).toEqual({ no_event_document: 1 });
    noMarker(s);
    expect(r).toEqual(parseChainsawReport(text));
  });
});

// ── KAPE ──────────────────────────────────────────────────────────────────────────────────────
describe("KAPE import debug (#1736)", () => {
  it("records which EZ timestamp column dated each row, and a row missing its required field", () => {
    const debug = createImportDebugRecorder();
    const text = csv([
      ["SourceFilename", "ExecutableName", "RunCount", "LastRun", "SourceModified"],
      [`C:\\${MARK}.pf`, `${MARK}.EXE`, "2", "2026-02-01 10:00:00", "2026-02-02 10:00:00"],
      [`C:\\${MARK}2.pf`, `${MARK}2.EXE`, "1", "", "2026-02-03 10:00:00"],
      [`C:\\${MARK}3.pf`, "", "1", "2026-02-01 10:00:00", ""],
    ]);
    const r = parseKapeCsv(text, { debug });
    const s = debug.summary();
    expect(s.fields.timestamp).toEqual({ LastRun: 1, SourceModified: 1 });
    expect(s.skipped).toEqual({ missing_required_field: 1 });
    noMarker(s);
    expect(r).toEqual(parseKapeCsv(text));
  });

  it("an unrecognized EZ tool skips every row", () => {
    const debug = createImportDebugRecorder();
    parseKapeCsv(
      csv([
        ["Zq", "Other"],
        [MARK, MARK],
      ]),
      { debug },
    );
    expect(debug.summary().skipped).toEqual({ unrecognized_ez_tool: 1 });
  });
});

// ── THOR ──────────────────────────────────────────────────────────────────────────────────────
describe("THOR import debug (#1736)", () => {
  it("records skip reasons, the time key, the host key and aggregation", () => {
    const debug = createImportDebugRecorder();
    const hit = {
      level: "Alert",
      module: "Filescan",
      message: `${MARK} malware`,
      file: `C:\\${MARK}.exe`,
      modified: "2026-02-01T10:00:00Z",
      hostname: `${MARK}-t.example.com`,
    };
    const text = [
      JSON.stringify(hit),
      JSON.stringify(hit),
      JSON.stringify({ level: "Info", module: "Filescan", message: `${MARK} info` }),
      JSON.stringify({ level: "Notice", module: "Init", message: `${MARK} init` }),
      `{ ${MARK} not json`,
    ].join("\n");
    const r = parseThorReport(text, { debug });
    const s = debug.summary();
    expect(s.skipped).toEqual({ unparseable_json: 1, info_level: 1, lifecycle_module: 1 });
    expect(s.fields.timestamp).toEqual({ modified: 2 });
    expect(s.fields.host).toEqual({ hostname: 2 });
    expect(s.omitted).toEqual({ aggregated: 1 });
    noMarker(s);
    expect(r).toEqual(parseThorReport(text));
  });

  it("the ingest wrapper records the severity floor and the counts", async () => {
    const debug = createImportDebugRecorder();
    const row = (level: string, n: number) =>
      JSON.stringify({
        level,
        module: "Filescan",
        message: `${MARK} ${n}`,
        modified: "2026-02-01T10:00:00Z",
      });
    await pipeline().importThor("c1", [row("Alert", 1), row("Warning", 2)].join("\n"), {
      ...BASE,
      label: "thor.jsonl",
      minSeverity: "Critical",
      debug,
    });
    const s = debug.summary();
    expect(s.omitted).toEqual({ below_severity_floor: 1 });
    expect(s.counts).toEqual({ total: 2, kept: 1, dropped: 1 });
    expect(s.observations.missing_host).toBe(2);
    noMarker(s);
  });
});

// ── Plaso ─────────────────────────────────────────────────────────────────────────────────────
describe("Plaso import debug (#1736)", () => {
  it("dynamic: records the flavor's columns and a row with no message", () => {
    const debug = createImportDebugRecorder();
    const text = csv([
      ["datetime", "timestamp_desc", "source", "source_long", "message", "parser", "display_name"],
      ["2026-02-01T10:00:00.000000+00:00", "Mod", "FILE", "File stat", `${MARK} one`, "filestat", `/${MARK}`],
      ["2026-02-01T11:00:00.000000+00:00", "Mod", "FILE", "File stat", "", "filestat", `/${MARK}2`],
    ]);
    const r = parsePlasoCsv(text, { debug });
    const s = debug.summary();
    expect(s.fields).toEqual({ timestamp: { datetime: 1 }, message: { message: 1 } });
    expect(s.skipped).toEqual({ no_message: 1 });
    noMarker(s);
    expect(r).toEqual(parsePlasoCsv(text));
  });

  it("l2tcsv: records desc vs short and the host column", () => {
    const debug = createImportDebugRecorder();
    const text = csv([
      ["date", "time", "timezone", "source", "sourcetype", "type", "host", "short", "desc", "filename"],
      ["02/01/2026", "10:00:00", "UTC", "FILE", "OS", "Mod", `${MARK}-p.example.com`, "s", `${MARK} d`, "-"],
      ["02/01/2026", "11:00:00", "UTC", "FILE", "OS", "Mod", "-", `${MARK} s`, "", "-"],
    ]);
    parsePlasoCsv(text, { debug });
    const s = debug.summary();
    expect(s.fields).toEqual({ timestamp: { date: 2 }, message: { desc: 1, short: 1 }, host: { host: 1 } });
    noMarker(s);
  });

  it("the ingest wrapper records the counts (an all-Info feed is never floored)", async () => {
    const debug = createImportDebugRecorder();
    const text = csv([
      ["datetime", "timestamp_desc", "source", "source_long", "message", "parser", "display_name"],
      ["2026-02-01T10:00:00.000000+00:00", "Mod", "FILE", "File stat", `${MARK} one`, "filestat", `/${MARK}`],
    ]);
    await pipeline().importPlaso("c1", text, { ...BASE, label: "p.csv", minSeverity: "High", debug });
    const s = debug.summary();
    expect(s.omitted.below_severity_floor).toBeUndefined();
    expect(s.counts).toEqual({ total: 1, kept: 1, dropped: 0 });
    noMarker(s);
  });
});

// ── Cyber Triage ──────────────────────────────────────────────────────────────────────────────
describe("Cyber Triage import debug (#1736)", () => {
  it("records the time and host keys, and the two row kinds it never maps", () => {
    const debug = createImportDebugRecorder();
    const rows = [
      {
        ctType: "Process",
        hostName: `${MARK}-ct.example.com`,
        epoch_timestamp: 1767261600,
        message: `${MARK}.exe -a`,
        path: `C:\\${MARK}.exe`,
      },
      { ctType: "File", hostName: `${MARK}-ct.example.com`, message: `C:\\${MARK}.txt` },
      { timestamp_desc: "Active Connection", message: `To 203.0.113.5:443 ${MARK}` },
    ];
    const text = ndjson(rows);
    const r = parseCybertriage(text, { debug });
    const s = debug.summary();
    expect(s.fields.timestamp).toEqual({ "<unlisted>": 1 });
    expect(s.fields.host).toEqual({ hostName: 1 });
    expect(s.skipped).toEqual({ unscored_file_telemetry: 1, network_row_ioc_only: 1 });
    noMarker(s);
    expect(r).toEqual(parseCybertriage(text));
  });
});

// ── Recovery reports ──────────────────────────────────────────────────────────────────────────
describe("recovery-report import debug (#1736)", () => {
  it("bulk_extractor url.txt records its malformed rows and the counts", async () => {
    const debug = createImportDebugRecorder();
    const text = [
      "# BULK_EXTRACTOR-Version: 2.0.0",
      "# Feature-Recorder: url",
      "# Feature-File-Version: 1.1",
      `48198832\thttps://${MARK}.example.com/a\tctx ${MARK}`,
      `${MARK} a line with no tabs`,
    ].join("\n");
    await pipeline().importBulkExtractorUrl("c1", text, { ...BASE, label: "url.txt", debug });
    const s = debug.summary();
    expect(s.skipped).toEqual({ malformed_row: 1 });
    expect(s.counts).toMatchObject({ total: 2, kept: 1 });
    noMarker(s);
  });

  it("a file the sqlite-dissect reader rejects records a detect-phase failure", async () => {
    const debug = createImportDebugRecorder();
    await expect(
      pipeline().importSqliteRowState("c1", `${MARK},not,a,report`, { ...BASE, label: "t.csv", debug }),
    ).rejects.toThrow();
    const s = debug.summary();
    expect(s.failure).toEqual({ phase: "detect" });
    noMarker(s);
  });
});

// ── pipeline harness ─────────────────────────────────────────────────────────────────────────
const BASE = { idPrefix: "x1", importedAt: "2026-06-01T00:00:00Z" };
let stateStore: StateStore;
beforeEach(async () => {
  const caseStore = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-importdebug-endpoint-")));
  await caseStore.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
  stateStore = new StateStore(caseStore);
});
function pipeline(): AnalysisPipeline {
  return new AnalysisPipeline({
    provider: new MockProvider("mock", "{}"),
    stateStore,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
}
