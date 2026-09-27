import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createImportDebugRecorder } from "../../src/analysis/importDebug.js";
import { parseSiemExport } from "../../src/analysis/siemImport.js";
import { parseEvtxXml, parseEvtxXmlProgress } from "../../src/analysis/evtxXmlImport.js";
import { noteParsed } from "../../src/analysis/ingest/importState.js";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { MockProvider } from "../../src/providers/provider.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";

// Every value below carries "zqmark" so one substring check proves no row VALUE reached the summary.
const MARK = "zqmark";

// Record 1 carries BOTH @timestamp and timestamp: pickTimestamp takes @timestamp, so only that key
// may be reported. Its host is an ECS host:{name} object.
const GENERIC_BOTH = {
  "@timestamp": "2026-03-01T10:00:00Z",
  timestamp: "2026-03-01T11:00:00Z",
  host: { name: `${MARK}-a.example.com` },
  message: `${MARK} generic event one`,
};
// A Sysmon process creation: the Windows mapper prefers EventData.UtcTime over @timestamp.
const SYSMON = {
  EventID: 1,
  Channel: "Microsoft-Windows-Sysmon/Operational",
  Computer: `${MARK}-b.example.com`,
  "@timestamp": "2026-03-01T12:00:00Z",
  EventData: {
    UtcTime: "2026-03-01 12:00:01.000",
    Image: `C:\\Temp\\${MARK}.exe`,
    CommandLine: `${MARK}.exe --flag ${MARK}secret`,
  },
};
// No host key at all; a hostname-less generic row.
const GENERIC_NO_HOST = { timestamp: "2026-03-01T13:00:00Z", message: `${MARK} generic event two` };
// No time key at all.
const GENERIC_NO_TIME = { hostname: `${MARK}-c.example.com`, message: `${MARK} generic event three` };

const ndjson = (rows: object[]): string => rows.map((r) => JSON.stringify(r)).join("\n");

function noMarker(summary: unknown): void {
  expect(JSON.stringify(summary).toLowerCase()).not.toContain(MARK);
}

describe("SIEM import debug (#1736)", () => {
  it("records the key each picker SELECTED, the mapper per record, and the counts", () => {
    const debug = createImportDebugRecorder();
    const r = parseSiemExport(ndjson([GENERIC_BOTH, SYSMON, GENERIC_NO_HOST, GENERIC_NO_TIME]), { debug });
    const s = debug.summary();

    // Only the key pickTimestamp used — "timestamp" is present on record 1 but never selected there.
    expect(s.fields.timestamp).toEqual({ "@timestamp": 1, UtcTime: 1, timestamp: 1 });
    expect(s.fields.host).toEqual({ "host.name": 1, Computer: 1, hostname: 1 });
    expect(s.fallbacks).toEqual({ windows_mapper: 1, generic_mapper: 3 });
    expect(s.observations).toEqual({ missing_host: 1, no_timestamp: 1 });
    expect(s.counts).toEqual({ total: 4, kept: r.kept, dropped: r.dropped });
    noMarker(s);
  });

  it("does not change the parse result", () => {
    const text = ndjson([GENERIC_BOTH, SYSMON, GENERIC_NO_HOST, GENERIC_NO_TIME]);
    const plain = parseSiemExport(text);
    const withDebug = parseSiemExport(text, { debug: createImportDebugRecorder() });
    expect(withDebug).toEqual(plain);
  });

  it("counts rows removed by the parser floor, aggregation and the event cap", () => {
    // Distinct words, not numbers: the generic aggregation key folds digits together.
    const high = (w: string) => ({
      timestamp: "2026-03-01T10:00:00Z",
      severity: "high",
      message: `${MARK} ${w}`,
    });
    const low = { timestamp: "2026-03-01T10:00:00Z", message: `${MARK} low row` };
    const debug = createImportDebugRecorder();
    // alpha twice (one aggregates into the other), bravo and charlie distinct, one Low below the
    // High floor, cap 2.
    const r = parseSiemExport(ndjson([high("alpha"), high("alpha"), high("bravo"), high("charlie"), low]), {
      debug,
      minSeverity: "High",
      maxEvents: 2,
    });
    const s = debug.summary();
    expect(r.kept).toBe(2);
    expect(s.omitted).toEqual({ below_severity_floor: 1, aggregated: 1, over_event_cap: 1 });
    expect(s.counts.total).toBe(5);
    noMarker(s);
  });
});

const xmlEvent = (system: string, data: string): string =>
  `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>${system}</System>` +
  `<EventData>${data}</EventData></Event>`;
const EVTX = [
  "<Events>",
  xmlEvent(
    `<Provider Name="Microsoft-Windows-Sysmon"/><EventID>1</EventID><Channel>Microsoft-Windows-Sysmon/Operational</Channel>` +
      `<Computer>${MARK}-x.example.com</Computer><TimeCreated SystemTime="2026-03-01T09:00:00.000Z"/>`,
    `<Data Name="UtcTime">2026-03-01 09:00:01.000</Data><Data Name="Image">C:\\${MARK}.exe</Data>`,
  ),
  xmlEvent(
    `<Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4624</EventID><Channel>Security</Channel>` +
      `<Computer>${MARK}-y.example.com</Computer><TimeCreated SystemTime="2026-03-01T09:05:00.000Z"/>`,
    `<Data Name="TargetUserName">${MARK}user</Data><Data Name="LogonType">3</Data>`,
  ),
  // No EventID: not an event, the parser skips the block.
  xmlEvent(`<Channel>Security</Channel><Computer>${MARK}-z.example.com</Computer>`, ""),
  "</Events>",
].join("\n");

describe("Windows Event XML import debug — the WindowsEventBuilder path (#1736)", () => {
  it("records the Sysmon UtcTime pick, the TimeCreated fallback and the skipped block (sync)", () => {
    const debug = createImportDebugRecorder();
    const r = parseEvtxXml(EVTX, { debug });
    const s = debug.summary();
    expect(s.fields.timestamp).toEqual({ UtcTime: 1, "@timestamp": 1 });
    expect(s.fields.host).toEqual({ Computer: 2 });
    expect(s.fallbacks).toEqual({ windows_mapper: 2 });
    expect(s.skipped).toEqual({ no_event_id: 1 });
    expect(s.counts).toEqual({ total: 2, kept: r.kept, dropped: r.dropped });
    noMarker(s);
  });

  it("records the same through the progress builder", async () => {
    const debug = createImportDebugRecorder();
    const r = await parseEvtxXmlProgress(EVTX, { debug });
    const s = debug.summary();
    expect(s.fields.timestamp).toEqual({ UtcTime: 1, "@timestamp": 1 });
    expect(s.fallbacks).toEqual({ windows_mapper: 2 });
    expect(s.skipped).toEqual({ no_event_id: 1 });
    expect(s.counts.total).toBe(2);
    expect(r).toEqual(await parseEvtxXmlProgress(EVTX));
    noMarker(s);
  });

  it("counts the builder's floor through the streaming aggregator", async () => {
    const debug = createImportDebugRecorder();
    await parseEvtxXmlProgress(EVTX, { debug, minSeverity: "Critical" });
    expect(debug.summary().omitted.below_severity_floor).toBe(2);
  });
});

describe("the deterministic wrappers' shared tail (#1736)", () => {
  it("noteParsed records the wrapper floor and the represented counts", () => {
    const debug = createImportDebugRecorder();
    noteParsed(debug, 10, [{}, {}, {}], [{ count: 4 }]);
    const s = debug.summary();
    expect(s.omitted).toEqual({ below_severity_floor: 2 });
    expect(s.counts).toEqual({ total: 10, kept: 1, dropped: 6 });
  });

  let stateStore: StateStore;
  beforeEach(async () => {
    const caseStore = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-importdebug-siem-")));
    await caseStore.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
    stateStore = new StateStore(caseStore);
  });
  const pipeline = () =>
    new AnalysisPipeline({
      provider: new MockProvider("mock", "{}"),
      stateStore,
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    });

  it("importSiem records the parse and the unified-import floor", async () => {
    const debug = createImportDebugRecorder();
    const base = { label: "export.ndjson", idPrefix: "s1", importedAt: "2026-06-01T00:00:00Z" };
    await pipeline().importSiem("c1", ndjson([GENERIC_BOTH, SYSMON]), {
      ...base,
      minSeverity: "High",
      debug,
    });
    const s = debug.summary();
    expect(s.fallbacks).toEqual({ windows_mapper: 1, generic_mapper: 1 });
    expect(s.counts.total).toBe(2);
    noMarker(s);
  });

  it("an import that yields nothing records no_events and kept 0", async () => {
    const debug = createImportDebugRecorder();
    const base = { label: "export.ndjson", idPrefix: "s1", importedAt: "2026-06-01T00:00:00Z" };
    await pipeline().importSiem("c1", ndjson([GENERIC_NO_HOST]), { ...base, minSeverity: "Critical", debug });
    const s = debug.summary();
    expect(s.observations.no_events).toBe(1);
    expect(s.counts).toMatchObject({ total: 1, kept: 0 });
    noMarker(s);
  });
});
