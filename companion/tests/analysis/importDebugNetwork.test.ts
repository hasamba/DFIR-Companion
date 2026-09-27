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
import { parseSnortLog } from "../../src/analysis/snortImport.js";
import { parseNetworkLogs } from "../../src/analysis/networkImport.js";
import { parseSecurityOnion } from "../../src/analysis/securityOnionImport.js";
import { parseExporterFlowNdjson } from "../../src/analysis/exporterFlowImport.js";

// #1736: the network importers record their decisions — which rule routed a record, which key fed
// a field, which rows they skipped — and never a value from a row. None of the marker values below
// (RFC 5737 addresses, example.com names) may reach the summary.

const MARKERS = [
  "198.51.100.77",
  "203.0.113.55",
  "marker-sensor.example.com",
  "MARKER SIGNATURE",
  "marker-rule",
];

function expectNoMarkers(r: ImportDebugRecorder): void {
  const text = JSON.stringify(r.summary());
  for (const m of MARKERS) expect(text).not.toContain(m);
}

function spyRecorder(): ImportDebugRecorder & { picks: Array<[DebugTarget, string]> } {
  const real = createImportDebugRecorder();
  const picks: Array<[DebugTarget, string]> = [];
  return {
    ...real,
    field(target, source, n) {
      picks.push([target, source]);
      real.field(target, source, n);
    },
    picks,
  };
}

const picked = (picks: Array<[DebugTarget, string]>, target: DebugTarget) =>
  picks.filter(([t]) => t === target).map(([, k]) => k);

async function makePipeline(caseId: string): Promise<AnalysisPipeline> {
  const root = await mkdtemp(join(tmpdir(), "dfir-importdebug-net-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId, name: "n", investigator: "i", aiProvider: null });
  return new AnalysisPipeline({
    stateStore: new StateStore(cases),
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
}

describe("Snort debug (#1736)", () => {
  const alert =
    "05/01-10:00:00.123456 [**] [1:2009714:9] MARKER SIGNATURE [**] [Classification: Web Attack] [Priority: 1] {TCP} 198.51.100.77:51000 -> 203.0.113.55:80";

  it("skips non-alert lines and marks every kept row year-inferred", async () => {
    const debug = createImportDebugRecorder();
    await (
      await makePipeline("sn1")
    ).importSnort("sn1", [alert, alert, "garbage marker-rule"].join("\n"), {
      label: "alert.fast",
      idPrefix: "sn",
      importedAt: "2026-09-27T00:00:00.000Z",
      snort: { assumeYear: 2024 },
      debug,
    });
    const s = debug.summary();
    expect(s.skipped).toEqual({ not_an_alert_line: 1 });
    expect(s.omitted).toEqual({ aggregated: 1 });
    expect(s.observations).toEqual({ timestamp_inferred: 1 });
    expect(s.fallbacks).toEqual({ caller_year: 1 });
    expect(s.counts).toEqual({ total: 2, kept: 1, dropped: 0 });
    expectNoMarkers(debug);
  });

  it("parses exactly as before without a recorder", () => {
    expect(parseSnortLog(alert, { assumeYear: 2024 })).toEqual(
      parseSnortLog(alert, { assumeYear: 2024, debug: createImportDebugRecorder() }),
    );
  });
});

describe("Suricata / Zeek debug (#1736)", () => {
  it("records which rule routed each record, never the stream's content", () => {
    const debug = createImportDebugRecorder();
    const text = [
      JSON.stringify({
        timestamp: "2024-05-01T10:00:00Z",
        event_type: "alert",
        src_ip: "198.51.100.77",
        dest_ip: "203.0.113.55",
        host: "marker-sensor.example.com",
        alert: { signature: "MARKER SIGNATURE", severity: 1 },
      }),
      JSON.stringify({ ts: 1714557600, _path: "notice", note: "marker-rule", src: "198.51.100.77" }),
    ].join("\n");
    parseNetworkLogs(text, { debug });
    const s = debug.summary();
    expect(s.fallbacks).toEqual({ suricata_event_type: 1, zeek_path: 1 });
    expectNoMarkers(debug);
  });

  it("names the filename rule for a per-stream Zeek file", () => {
    const debug = createImportDebugRecorder();
    const row = JSON.stringify({
      ts: 1714557600,
      query: "marker-sensor.example.com",
      "id.orig_h": "198.51.100.77",
    });
    parseNetworkLogs(row, { filename: "dns.json", debug });
    expect(debug.summary().fallbacks).toEqual({ zeek_filename_stream: 1 });
    expectNoMarkers(debug);
  });
});

describe("Security Onion debug (#1736)", () => {
  it("records the keys that named the rule, the addresses, the host and the time", () => {
    const debug = spyRecorder();
    parseSecurityOnion(
      JSON.stringify([
        {
          "@timestamp": "2024-05-01T10:00:00Z",
          "rule.name": "MARKER SIGNATURE",
          src_ip: "198.51.100.77",
          "destination.ip": "203.0.113.55",
          "agent.name": "marker-sensor.example.com",
          "event.severity_label": "high",
        },
        { timestamp: "2024-05-01T10:01:00Z", message: "marker-rule" },
      ]),
      { debug },
    );
    expect(picked(debug.picks, "rule")).toEqual(["rule.name", "message"]);
    expect(picked(debug.picks, "source_ip")).toEqual(["src_ip"]);
    expect(picked(debug.picks, "dest_ip")).toEqual(["destination.ip"]);
    expect(picked(debug.picks, "host")).toEqual(["agent.name"]);
    expect(picked(debug.picks, "timestamp")).toEqual(["@timestamp", "timestamp"]);
    expect(debug.summary().observations).toEqual({ missing_host: 1 });
    expectNoMarkers(debug);
  });
});

describe("nfdump exporter flow debug (#1736)", () => {
  const record = (overrides: Record<string, unknown> = {}) => ({
    first: "2026-01-01T00:00:00.000",
    last: "2026-01-01T00:00:05.000",
    received: "2026-01-01T00:05:00.000",
    proto: 6,
    src4_addr: "198.51.100.77",
    dst4_addr: "203.0.113.55",
    src_port: 51000,
    dst_port: 443,
    in_bytes: 1000,
    in_packets: 10,
    export_sysid: 1,
    ...overrides,
  });

  it("names each skip reason and the interim-merge fold", () => {
    const debug = createImportDebugRecorder();
    const lines = [
      JSON.stringify(record()),
      // An interim re-export of the same connection, adjacent in time: merged into one flow.
      JSON.stringify(record({ first: "2026-01-01T00:00:06.000", last: "2026-01-01T00:00:09.000" })),
      "{ not json marker-sensor.example.com",
      JSON.stringify({ note: "marker-rule" }),
      JSON.stringify(record({ in_bytes: "lots" })),
    ];
    parseExporterFlowNdjson(lines.join("\n"), { debug });
    const s = debug.summary();
    expect(s.skipped).toEqual({ unparseable_json: 1, unrecognized_record: 1, missing_required_field: 1 });
    expect(s.omitted).toEqual({ interim_flow_merge: 1 });
    expectNoMarkers(debug);
  });
});
