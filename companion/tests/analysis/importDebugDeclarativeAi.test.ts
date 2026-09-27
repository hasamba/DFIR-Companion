import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createImportDebugRecorder } from "../../src/analysis/importDebug.js";
import { buildImporter } from "../../src/analysis/declarativeImporter.js";
import { EXAMPLE_IMPORTER_SPEC, parseImporterSpec } from "../../src/analysis/importerSpec.js";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";

// Every value carries "zqmark" so one substring check proves no row VALUE reached the summary.
const MARK = "zqmark";
const noMarker = (summary: unknown): void =>
  expect(JSON.stringify(summary).toLowerCase()).not.toContain(MARK);

function spec() {
  const r = parseImporterSpec(EXAMPLE_IMPORTER_SPEC);
  if (!r.ok) throw new Error("example invalid");
  return r.spec;
}

// The example spec renders "{{ActionType}} on {{DeviceName}} — {{FileName}}", reads Timestamp, the
// asset from DeviceName and the user as AccountDomain\AccountName.
const HEADER = "Timestamp,DeviceName,ActionType,FileName,Severity,AccountDomain,AccountName";
const CSV = [
  HEADER,
  `2026-06-10T12:00:00Z,${MARK}host01,ProcessCreated,${MARK}.exe,High,${MARK}corp,${MARK}user`,
  // An EMPTY time column resolves to "" and the row is kept (mergeDelta dates it at import).
  `,${MARK}host02,FileCreated,${MARK}two.exe,High,,${MARK}solo`,
].join("\n");

describe("declarative importer debug (#1736)", () => {
  it("records the keys each binding used, the kept empty timestamp and the counts", () => {
    const debug = createImportDebugRecorder();
    const r = buildImporter(spec()).parse(CSV, { debug });
    const s = debug.summary();
    expect(s.fields.timestamp).toEqual({ Timestamp: 1 });
    // DeviceName is on the support bundle's generic column allowlist (an importer field key).
    expect(s.fields.host).toEqual({ DeviceName: 2 });
    // A join records every part it read: row 1 both, row 2 only AccountName.
    expect(Object.values(s.fields.user ?? {}).reduce((a, b) => a + b, 0)).toBe(3);
    expect(s.observations).toEqual({ empty_timestamp: 1 });
    expect(s.counts).toEqual({ total: 2, kept: r.kept, dropped: r.dropped });
    noMarker(s);
  });

  it("skips a row whose description renders empty as no_description", () => {
    const r = parseImporterSpec({
      ...EXAMPLE_IMPORTER_SPEC,
      map: { ...EXAMPLE_IMPORTER_SPEC.map, description: "{{ActionType}}" },
    });
    if (!r.ok) throw new Error("spec invalid");
    const debug = createImportDebugRecorder();
    const csv = [
      HEADER,
      `2026-06-10T12:00:00Z,${MARK}h,,${MARK}.exe,High,,`,
      `2026-06-10T12:00:00Z,${MARK}h,Ran,x,High,,`,
    ].join("\n");
    const parsed = buildImporter(r.spec).parse(csv, { debug });
    expect(parsed.total).toBe(2);
    expect(debug.summary().skipped).toEqual({ no_description: 1 });
    noMarker(debug.summary());
  });

  it("does not change the parse result", () => {
    const imp = buildImporter(spec());
    expect(imp.parse(CSV, { debug: createImportDebugRecorder() })).toEqual(imp.parse(CSV));
  });
});

describe("AI csv / log extraction debug (#1736)", () => {
  let stateStore: StateStore;
  beforeEach(async () => {
    const caseStore = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-importdebug-ai-")));
    await caseStore.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
    stateStore = new StateStore(caseStore);
  });

  function pipelineReturning(severities: string[]) {
    let call = 0;
    return new AnalysisPipeline({
      provider: {
        name: "spy",
        model: "mock-model",
        analyze: async () => {
          call += 1;
          return {
            rawText: JSON.stringify({
              findings: [],
              iocs: [],
              mitreTechniques: [],
              threadsOpened: [],
              threadsClosed: [],
              timelineNote: "read rows",
              summary: "",
              forensicEvents: severities.map((severity, i) => ({
                id: `e${i + 1}`,
                timestamp: `2026-05-20T09:0${call}:0${i}Z`,
                description: `row event ${call}-${i}`,
                severity,
                mitreTechniques: [],
                relatedFindingIds: [],
              })),
            }),
          };
        },
      },
      stateStore,
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    });
  }
  const opts = { label: "0001_results.csv", idPrefix: "m1", importedAt: "2026-06-01T00:00:00Z" };

  it("analyzeCsv records rows in, events kept and the floor", async () => {
    const debug = createImportDebugRecorder();
    const csv = `Time,Process\n09:00,${MARK}a.exe\n09:01,${MARK}b.exe\n09:02,${MARK}c.exe\n`;
    await pipelineReturning(["High", "Info"]).analyzeCsv("c1", csv, {
      ...opts,
      rowsPerBatch: 2,
      minSeverity: "Low",
      debug,
    });
    const s = debug.summary();
    // 3 rows → 2 batches; each batch returns one High and one Info, and the Low floor removes the Info.
    expect(s.counts).toEqual({ total: 3, kept: 2 });
    expect(s.omitted).toEqual({ below_severity_floor: 2 });
    expect(s.skipped).toEqual({});
    noMarker(s);
  });

  it("a cancel between batches is an observation, not a skip or a failure", async () => {
    const debug = createImportDebugRecorder();
    const ac = new AbortController();
    const csv = `Time,Process\n09:00,${MARK}a.exe\n09:01,${MARK}b.exe\n`;
    await pipelineReturning(["High"]).analyzeCsv("c1", csv, {
      ...opts,
      rowsPerBatch: 1,
      signal: ac.signal,
      onProgress: () => ac.abort(),
      debug,
    });
    const s = debug.summary();
    expect(s.observations).toEqual({ cancelled_between_batches: 1 });
    expect(s.counts).toEqual({ total: 2, kept: 1 });
    expect(s.failure).toBeUndefined();
  });

  it("a batch that fails records the ai phase and still throws", async () => {
    const debug = createImportDebugRecorder();
    const pipeline = new AnalysisPipeline({
      provider: {
        name: "spy",
        model: "mock-model",
        analyze: async () => {
          throw new Error(`provider down ${MARK}`);
        },
      },
      stateStore,
      retries: 0,
      backoffMs: 0,
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    });
    await expect(pipeline.analyzeCsv("c1", `a,b\n${MARK},1\n`, { ...opts, debug })).rejects.toThrow();
    const s = debug.summary();
    expect(s.failure).toEqual({ phase: "ai" });
    expect(s.skipped).toEqual({});
    noMarker(s);
  });

  it("analyzeLog records lines in and the pattern count", async () => {
    const debug = createImportDebugRecorder();
    const log = `${MARK} login ok\n${MARK} login ok\n${MARK} disk full\n`;
    await pipelineReturning(["High"]).analyzeLog("c1", log, { ...opts, label: "app.log", debug });
    const s = debug.summary();
    expect(s.counts).toEqual({ total: 3, kept: 1 });
    expect(s.fallbacks.log_patterns).toBeGreaterThan(0);
    noMarker(s);
  });
});
