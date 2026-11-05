// Shared assertions for the cloud tool compatibility matrix (#2300). Each per-tool test file runs
// `checkRow` over its rows, so every status in matrix.ts is backed by the real detector, the real
// ingest-level resolver the import route calls, and — for every deterministic kind — the real
// dispatch switch in composition/importIngest.ts.

import { expect } from "vitest";
import { detectImportKind } from "../../../src/analysis/importDetect.js";
import { parseM365Audit } from "../../../src/analysis/m365Import.js";
import { parseCloudActivity } from "../../../src/analysis/cloudActivityImport.js";
import { parseCloudTrail } from "../../../src/analysis/awsImport.js";
import { parseCloudSnapshot } from "../../../src/analysis/cloudSnapshotParse.js";
import { createImportIngest, type ImportIngestDeps } from "../../../src/composition/importIngest.js";
import { ImportLock } from "../../../src/analysis/importLock.js";
import { fixtureText, uploadName, type CompatRow } from "./matrix.js";
import { readFileSync } from "node:fs";
import { mkdtemp, open, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import { sniffImportFileHeadDetail } from "../../../src/routes/importFileHead.js";
import { openCloudRecordStream } from "../../../src/analysis/cloudStreamReader.js";
import { cloudTrailConsoleRow } from "../../../src/analysis/cloudRecords.js";

const FIXTURES = new URL("../../fixtures/cloudCompat/", import.meta.url);

/** The pipeline method dispatchImport calls for each deterministic kind in the matrix. */
const DISPATCH_METHOD: Record<string, string> = {
  m365: "importM365",
  cloud: "importCloudActivity",
  aws: "importAws",
  cloudsnapshot: "importCloudSnapshot",
};

/** The import time the harness dispatches with — and the observation time of a snapshot whose file
 * name carries no MES collection time (#2305). */
const IMPORTED_AT = "2026-11-01T00:00:00Z";

/** The real parser behind each dispatched kind: what the pipeline method above runs on the text. */
const PARSERS: Record<
  string,
  (
    text: string,
    name: string,
  ) => { total: number; events: Array<{ timestamp?: string; description: string }> }
> = {
  m365: (t) => parseM365Audit(t),
  cloud: (t) => parseCloudActivity(t),
  aws: (t) => parseCloudTrail(t),
  // A snapshot's events are observations of state at collection (#2305): the first-import view.
  cloudsnapshot: (t, name) => parseCloudSnapshot(t, { label: name, importedAt: IMPORTED_AT }),
};

/** An ImportIngest over a pipeline stub that records which importer method it was handed. */
function recordingIngest(): { ingest: ReturnType<typeof createImportIngest>; calls: string[] } {
  const calls: string[] = [];
  const pipeline = new Proxy(
    {},
    {
      get: (_t, prop) => async () => {
        calls.push(String(prop));
        return undefined;
      },
    },
  );
  const deps = {
    store: {} as ImportIngestDeps["store"],
    options: { pipeline },
    runStateExclusive: async (_c: string, fn: () => Promise<unknown>) => fn(),
    importLock: new ImportLock(),
    recordImporterRun: () => {},
    redactErr: (err: unknown) => String(err),
    autoTagImported: async () => {},
    getControl: async () => ({ enabled: true }),
    applyWhitelistToCase: async () => ({ matched: 0, added: 0 }),
    applyNsrlToCase: async () => ({ matchedIocs: 0, matchedEvents: 0, added: 0 }),
    applyDeobfuscationToCase: async () => ({ deobfuscated: 0, newIocs: 0, reanalyzed: 0 }),
    resynthesizeInBackground: () => {},
  } as unknown as ImportIngestDeps;
  return { ingest: createImportIngest(deps), calls };
}

/**
 * A gzip row as the server receives it since #2303: the file by path, sniffed from its decompressed
 * head (the import-file route's sniff), then read by the streaming reader the cloud importers use.
 */
async function checkGzipRow(row: CompatRow): Promise<void> {
  const dir = await mkdtemp(join(tmpdir(), "dfir-compat-gz-"));
  const path = join(dir, uploadName(row));
  await writeFile(path, gzipSync(readFileSync(new URL(row.fixture, FIXTURES))));
  const fh = await open(path, "r");
  const { sample, gzip } = await sniffImportFileHeadDetail(fh).finally(() => fh.close());
  expect(gzip, `${row.fixture}: gzip sniffed`).toBe(true);
  const { ingest } = recordingIngest();
  const kind = ingest.resolveImportKind(uploadName(row).replace(/\.gz$/i, ""), sample);
  expect(kind, `${row.fixture}: resolved kind`).toBe(row.detectedToday);
  if (row.status !== "works") return;
  const stream = await openCloudRecordStream(path, { adapt: cloudTrailConsoleRow });
  const records: Array<Record<string, unknown>> = [];
  for await (const r of stream.records) records.push(r);
  const parsed = parseCloudTrail("", { records });
  expect(parsed.total, `${row.fixture}: records read`).toBe(row.parsed.records);
  expect(
    parsed.events.some((e) => e.description.includes(row.parsed.shows)),
    `${row.fixture}: shows`,
  ).toBe(true);
}

export async function checkRow(row: CompatRow): Promise<void> {
  if (row.gzip) return checkGzipRow(row);
  const name = uploadName(row);
  const text = fixtureText(row);
  const { ingest, calls } = recordingIngest();

  // What the import route resolves today (the binary refusal runs here, ahead of the sniff).
  const kind = ingest.resolveImportKind(name, text);
  expect(kind, `${row.fixture}: resolved kind`).toBe(row.detectedToday);
  // The pure sniff agrees for every text file; a gzip is refused before it is ever sniffed.
  if (!row.gzip) expect(detectImportKind(name, text), `${row.fixture}: sniffed kind`).toBe(row.detectedToday);

  const method = DISPATCH_METHOD[kind];
  if (method) {
    await ingest.dispatchImport(kind, "c1", text, {
      label: name,
      idPrefix: "1",
      importedAt: IMPORTED_AT,
    });
    expect(calls, `${row.fixture}: dispatched importer`).toEqual([method]);
  }

  // A "works" row claims the importer it reaches maps it: run that importer's real parser on the
  // fixture. The evidence is mandatory, so a works row nobody proved fails here.
  if (row.status === "works") {
    expect(row.parsed, `${row.fixture}: a works row needs parser evidence`).toBeDefined();
    const parse = PARSERS[kind];
    expect(parse, `${row.fixture}: no real parser for kind ${kind}`).toBeDefined();
    const parsed = parse(text, name);
    expect(parsed.total, `${row.fixture}: records read`).toBe(row.parsed.records);
    expect(parsed.events.length, `${row.fixture}: events mapped`).toBeGreaterThan(0);
    const hit = parsed.events.find((e) => e.description.includes(row.parsed.shows));
    expect(hit, `${row.fixture}: an event showing "${row.parsed.shows}"`).toBeDefined();
    expect(hit?.timestamp, `${row.fixture}: that event's time`).toMatch(/^2026-11-01T\d\d:\d\d/);
  }

  // A misrouted row claims an existing importer can map it: prove that by forcing it through.
  if (row.provenWith === "m365") {
    const parsed = parseM365Audit(text);
    expect(parsed.events.length, `${row.fixture}: rows m365 maps when forced`).toBeGreaterThan(0);
  }
}
