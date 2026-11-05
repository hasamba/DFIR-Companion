// Shared assertions for the cloud tool compatibility matrix (#2300). Each per-tool test file runs
// `checkRow` over its rows, so every status in matrix.ts is backed by the real detector, the real
// ingest-level resolver the import route calls, and — for every deterministic kind — the real
// dispatch switch in composition/importIngest.ts.

import { expect } from "vitest";
import { detectImportKind } from "../../../src/analysis/importDetect.js";
import { parseM365Audit } from "../../../src/analysis/m365Import.js";
import { createImportIngest, type ImportIngestDeps } from "../../../src/composition/importIngest.js";
import { ImportLock } from "../../../src/analysis/importLock.js";
import { fixtureText, uploadName, type CompatRow } from "./matrix.js";

/** The pipeline method dispatchImport calls for each deterministic kind in the matrix. */
const DISPATCH_METHOD: Record<string, string> = {
  m365: "importM365",
  cloud: "importCloudActivity",
  aws: "importAws",
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

export async function checkRow(row: CompatRow): Promise<void> {
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
      importedAt: "2026-11-01T00:00:00Z",
    });
    expect(calls, `${row.fixture}: dispatched importer`).toEqual([method]);
  }

  // A misrouted row claims an existing importer can map it: prove that by forcing it through.
  if (row.provenWith === "m365") {
    const parsed = parseM365Audit(text);
    expect(parsed.events.length, `${row.fixture}: rows m365 maps when forced`).toBeGreaterThan(0);
  }
}
