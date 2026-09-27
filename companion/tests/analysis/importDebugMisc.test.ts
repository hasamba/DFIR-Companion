import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import {
  createImportDebugRecorder,
  type DebugTarget,
  type ImportDebugRecorder,
} from "../../src/analysis/importDebug.js";
import { parseYaraOutput } from "../../src/analysis/yaraImport.js";
import { parseMemory } from "../../src/analysis/memoryImport.js";
import { parseMemoryOrIntact } from "../../src/analysis/intactImport.js";
import { parseLeappTsv } from "../../src/analysis/mobileLeappImport.js";
import { parseEmail } from "../../src/analysis/emailImport.js";
import { parseSandboxReport } from "../../src/analysis/sandboxImport.js";
import { parseMacPersist } from "../../src/analysis/macosPersistImport.js";

// #1736: the malware-report, macOS, memory, mobile, email and ECAR importers record what they
// DECIDED — which key fed a field, which rows they skipped and why, what the cap and floor removed
// — and never a value from a row. Every fixture carries unique marker values; none may reach the
// summary.

const MARKERS = [
  "mk-ecar-host.example.com",
  "MarkerPrincipalQ",
  "MarkerCmdLineQ",
  "MarkerImageQ",
  "MarkerRuleQ",
  "MarkerTargetQ",
  "MarkerProcQ",
  "MarkerAppQ",
  "MarkerSubjectQ",
  "marker-sender@example.com",
  "198.51.100.77",
  "MarkerDisplayQ",
  "MarkerFileNameQ",
  "MarkerPlistQ",
];

function expectNoMarkers(r: ImportDebugRecorder): void {
  const text = JSON.stringify(r.summary());
  for (const m of MARKERS) expect(text).not.toContain(m);
}

/** A real recorder that also remembers the raw (target, key) of every field() call. */
function spyRecorder(): ImportDebugRecorder & { picks: Array<[DebugTarget, string, number]> } {
  const real = createImportDebugRecorder();
  const picks: Array<[DebugTarget, string, number]> = [];
  return {
    ...real,
    field(target, source, n) {
      picks.push([target, source, n ?? 1]);
      real.field(target, source, n);
    },
    picks,
  };
}

/** Rows per selected key for one target, summed over every field() call. */
function picked(picks: Array<[DebugTarget, string, number]>, target: DebugTarget): Record<string, number> {
  const out: Record<string, number> = {};
  for (const [t, k, n] of picks) if (t === target) out[k] = (out[k] ?? 0) + n;
  return out;
}

async function makePipeline(caseId: string): Promise<AnalysisPipeline> {
  const root = await mkdtemp(join(tmpdir(), "dfir-importdebug-misc-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId, name: "n", investigator: "i", aiProvider: null });
  return new AnalysisPipeline({
    stateStore: new StateStore(cases),
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
}

const base = (debug: ImportDebugRecorder, extra: Record<string, unknown> = {}) => ({
  label: "upload.json",
  idPrefix: "dx",
  importedAt: "2026-09-27T00:00:00.000Z",
  debug,
  ...extra,
});

describe("ECAR debug (#1736)", () => {
  it("records the time and host keys, the unmappable records, and the counts", async () => {
    const rec = (extra: Record<string, unknown>) =>
      JSON.stringify({
        timestamp_ms: 1715688049745,
        hostname: "mk-ecar-host.example.com",
        object: "PROCESS",
        action: "CREATE",
        principal: "MarkerPrincipalQ",
        properties: { command_line: "MarkerCmdLineQ -x", image_path: "C:\\MarkerImageQ.exe" },
        ...extra,
      });
    const text = [
      rec({}),
      rec({ timestamp_ms: 0, properties: { image_path: "C:\\MarkerImageQ2.exe" } }),
      rec({ hostname: "", properties: { image_path: "C:\\MarkerImageQ3.exe" } }),
      rec({ object: "", action: "" }),
      rec({ object: "WIDGET", action: "SPIN" }),
    ].join("\n");
    const debug = spyRecorder();
    const p = await makePipeline("c-ecar");
    await p.importEcar("c-ecar", text, base(debug));
    const s = debug.summary();
    expect(picked(debug.picks, "timestamp")).toEqual({ timestamp_ms: 3 });
    expect(picked(debug.picks, "host")).toEqual({ hostname: 3 });
    expect(s.skipped).toMatchObject({ no_object_or_action: 1 });
    expect(s.observations).toMatchObject({ empty_timestamp: 1, missing_host: 1, unknown_object_action: 1 });
    expect(s.counts).toMatchObject({ total: 5 });
    expectNoMarkers(debug);
  });
});

describe("capa / olevba / MobSF wrapper debug (#1736)", () => {
  const SAMPLE = {
    md5: "7a450304b58917290f54ffbdccb095b6",
    sha1: "db054d79d4d913671732d9ff696dca69f911601a",
    sha256: "afed46612dce2c6fa48d95192426366dcc0a4517f4b56240f0c8e39a5104748a",
    path: "samples/MarkerTargetQ.dll",
  };
  const rule = (name: string, namespace: string) => ({
    meta: { name, namespace, attack: [], mbc: [] },
    source: `rule: ${name}`,
    matches: [
      [
        { type: "no address" },
        {
          success: true,
          node: { type: "feature", feature: { type: "string", string: "UPX!" } },
          children: [],
          locations: [],
          captures: {},
        },
      ],
    ],
  });
  const capa = (rules: Record<string, unknown>) =>
    JSON.stringify({
      meta: {
        timestamp: "2026-08-08T20:30:07",
        version: "9.4.0",
        argv: ["-j"],
        sample: SAMPLE,
        flavor: "static",
        analysis: {},
      },
      rules,
    });

  it("capa: counts, a malformed rule entry by reason, and the floor removal", async () => {
    const doc = capa({
      "packed with MarkerRuleQ": rule("packed with MarkerRuleQ", "anti-analysis/packer/upx"),
      "accept command line arguments": rule("accept command line arguments", "host-interaction/cli"),
      broken: "not an object",
    });
    const debug = createImportDebugRecorder();
    const p = await makePipeline("c-capa");
    await p.importCapaResult("c-capa", doc, base(debug, { minSeverity: "Medium" }));
    const s = debug.summary();
    expect(s.counts.total).toBe(3);
    expect(s.skipped).toMatchObject({ malformed_rule: 1 });
    expect(s.omitted.below_severity_floor).toBeGreaterThan(0);
    expect(s.counts.kept).toBe(0);
    expectNoMarkers(debug);
  });

  it("capa: a document the parser does not recognise marks the parse phase before it throws", async () => {
    const debug = createImportDebugRecorder();
    const p = await makePipeline("c-capa2");
    await expect(p.importCapaResult("c-capa2", "{}", base(debug))).rejects.toThrow(/capa/);
    expect(debug.summary().failure).toEqual({ phase: "parse" });
  });
});

describe("YARA debug (#1736)", () => {
  it("records the meta keys it graded and hashed from, and the lines it could not read", () => {
    const sha = "a".repeat(64);
    const text = [
      `MarkerRuleQ [score=95,sha256="${sha}"] C:\\MarkerTargetQ\\a.exe`,
      `OtherRule [threat_level="high"] C:\\MarkerTargetQ\\b.exe`,
      `PlainRule C:\\MarkerTargetQ\\c.exe`,
      "!!! MarkerRuleQ garbage line that is not a match !!!",
    ].join("\n");
    const debug = spyRecorder();
    const r = parseYaraOutput(text, { debug });
    expect(r.total).toBe(3);
    const s = debug.summary();
    expect(picked(debug.picks, "severity")).toEqual({ score: 1, threat_level: 1 });
    expect(picked(debug.picks, "hash")).toEqual({ sha256: 1 });
    expect(s.fallbacks).toMatchObject({ default_severity: 1 });
    expect(s.skipped).toMatchObject({ unrecognized_line: 1 });
    expectNoMarkers(debug);
  });
});

describe("memory debug (#1736)", () => {
  const pslist = () => ({
    "windows.pslist.PsList": [
      {
        __children: [],
        PID: 4,
        PPID: 0,
        ImageFileName: "MarkerProcQ.exe",
        CreateTime: "2021-04-29 21:26:48.000000",
      },
      {
        __children: [],
        PID: 8,
        PPID: 4,
        ImageFileName: "MarkerProcQ2.exe",
        create_time: "2021-04-29 21:27:48",
      },
      { __children: [], PID: 9, PPID: 4, ImageFileName: "MarkerProcQ3.exe", CreateTime: "N/A" },
    ],
  });

  it("records the process name and start-time columns, the counts, and the output unchanged", () => {
    const debug = spyRecorder();
    const withDebug = parseMemory(JSON.stringify(pslist()), { debug });
    const without = parseMemory(JSON.stringify(pslist()), {});
    expect(withDebug.events).toEqual(without.events);
    expect(picked(debug.picks, "process")).toEqual({ ImageFileName: 3 });
    expect(picked(debug.picks, "timestamp")).toEqual({ CreateTime: 1, create_time: 1 });
    const s = debug.summary();
    expect(s.observations).toMatchObject({ empty_timestamp: 1 });
    expect(s.counts).toEqual({ total: withDebug.total, kept: withDebug.kept, dropped: withDebug.dropped });
    expectNoMarkers(debug);
  });

  it("records an unclassified table as the generic mapper, through the Intact adapter too", () => {
    const debug = createImportDebugRecorder();
    parseMemoryOrIntact(JSON.stringify({ "windows.odd.Odd": [{ Thing: "MarkerProcQ", Other: 1 }] }), {
      debug,
    });
    expect(debug.summary().fallbacks).toMatchObject({ generic_table_mapper: 1 });
    expectNoMarkers(debug);
  });
});

describe("LEAPP debug (#1736)", () => {
  it("records the dating column by name and no row value", () => {
    const tsv = [
      "Timestamp\tApp Name\tBundle ID\tAction",
      "2026-05-02 10:00:00\tMarkerAppQ\torg.example.markerapp\tinstalled",
      "2026-05-02 11:30:00\tMarkerAppQ2\tcom.example.invalid.app\tinstalled",
    ].join("\n");
    const debug = spyRecorder();
    parseLeappTsv(tsv, "Installed Apps.tsv", { debug });
    expect(picked(debug.picks, "timestamp")).toEqual({ Timestamp: 2 });
    expectNoMarkers(debug);
  });
});

describe("email debug (#1736)", () => {
  it("records which header dated the message and where the originating IP came from", () => {
    const eml = [
      "From: Marker <marker-sender@example.com>",
      "To: someone@example.com",
      "Subject: MarkerSubjectQ",
      "Date: Tue, 01 Sep 2026 10:00:00 +0000",
      "X-Originating-IP: [198.51.100.77]",
      "Message-ID: <abc@example.com>",
      "",
      "body",
    ].join("\r\n");
    const debug = spyRecorder();
    parseEmail(eml, { debug });
    expect(picked(debug.picks, "timestamp")).toEqual({ Date: 1 });
    expect(picked(debug.picks, "source_ip")).toEqual({ "X-Originating-IP": 1 });
    expect(debug.summary().counts).toEqual({ total: 1, kept: 1, dropped: 0 });
    expectNoMarkers(debug);
  });

  it("names an unrecoverable upload as skipped", () => {
    const debug = createImportDebugRecorder();
    parseEmail("MarkerSubjectQ", { debug });
    expect(debug.summary().skipped).toEqual({ not_recoverable_email: 1 });
    expectNoMarkers(debug);
  });
});

describe("sandbox debug (#1736)", () => {
  it("names reports that matched neither mapper and non-object entries", () => {
    const debug = createImportDebugRecorder();
    parseSandboxReport(JSON.stringify([{ unrelated: "MarkerTargetQ" }, 5]), { debug });
    const s = debug.summary();
    expect(s.skipped).toMatchObject({ unknown_report_format: 1, not_an_object: 1 });
    expect(s.counts).toEqual({ total: 1, kept: 0, dropped: 1 });
    expectNoMarkers(debug);
  });
});

describe("macOS debug (#1736)", () => {
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
  const row = (f: Record<string, string>) => HEADER.map((h) => f[h] ?? "").join(",");
  const BASE = {
    ID: "1001",
    Parent_ID: "42",
    Date_Updated: "2024-03-01T00:00:00Z",
    kMDItemDisplayName: "MarkerDisplayQ.app",
    _kMDItemFileName: "MarkerFileNameQ.app",
    kMDItemUseCount: "3",
    kMDItemLastUsedDate: "2024-03-10T00:00:00Z",
  };

  it("Spotlight: the display-name column chosen, the usage date, skipped rows by reason", async () => {
    const csv = [
      HEADER.join(","),
      row(BASE),
      row({ ...BASE, ID: "1002", kMDItemDisplayName: "", kMDItemLastUsedDate: "" }),
      row({ ID: "1003", Date_Updated: "2024-03-01T00:00:00Z", _kMDItemFileName: "MarkerFileNameQ2" }),
      "1004,MarkerFileNameQ3",
    ].join("\n");
    const debug = spyRecorder();
    const p = await makePipeline("c-spot");
    await p.importMacSpotlightUsage("c-spot", csv, base(debug, { label: "spotlight.csv" }));
    const s = debug.summary();
    expect(picked(debug.picks, "path")).toEqual({ kMDItemDisplayName: 1, _kMDItemFileName: 1 });
    expect(picked(debug.picks, "timestamp")).toEqual({ kMDItemLastUsedDate: 1 });
    expect(s.observations).toMatchObject({ empty_timestamp: 1 });
    expect(s.skipped).toMatchObject({ malformed_row: 1, no_usage_signal: 1 });
    expect(s.counts).toMatchObject({ total: 4, kept: 2 });
    expectNoMarkers(debug);
  });

  it("macOS persistence: counts the collected files and names the ones it could not grade", () => {
    const text = [
      "==> /Users/MarkerPlistQ/.zshrc <==",
      "export PATH=/usr/bin",
      "==> /tmp/suid-list.txt <==",
      "/usr/bin/MarkerPlistQ",
      "==> /opt/MarkerPlistQ/readme <==",
      "hello",
    ].join("\n");
    const debug = createImportDebugRecorder();
    const r = parseMacPersist("collection.txt", text, {}, undefined, debug);
    const s = debug.summary();
    expect(s.counts).toEqual({ total: 3, kept: r.events.length });
    expect(s.skipped).toEqual({ unknown_artifact: 1, suid_listing_not_graded: 1 });
    expectNoMarkers(debug);
  });
});
