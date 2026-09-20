import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { LoggerImpl, type Logger, type LogWriter } from "../../src/logging/logger.js";
import { getServerLogger, setServerLogger } from "../../src/logging/serverLogger.js";
import { createDiagnosticsRings } from "../../src/composition/diagnosticsRings.js";
import { createImportIngest, type ImportIngestDeps } from "../../src/composition/importIngest.js";
import { ImportLock } from "../../src/analysis/importLock.js";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { pollFor, POLL_TIMEOUT_MS } from "../helpers/poll.js";

// #1438: an import used to log nothing at all — not its start, not its end, not its failure — so
// a crash mid-import left an empty session log and a case log that never mentioned the file.
// These tests drive the three seams the fix logs at (dispatchImport, recordImportFailure and the
// AbortError branch) through a capturing logger, and pin the one property that matters most: a
// line carrying the caseId lands in the SESSION log AND in the CASE log.

const SESSION = "session.log";
const caseLog = (caseId: string): string => `case-${caseId}.log`;
const ISO = "2026-05-02T10:00:00Z";
const THOR = [
  { level: "Warning", module: "Filescan", message: "Suspicious file", time: ISO, file: "C:\\Temp\\a.exe" },
  { level: "Notice", module: "Filescan", message: "Noticed file", time: ISO, file: "C:\\Temp\\b.exe" },
]
  .map((r) => JSON.stringify(r))
  .join("\n");

let lines: { path: string; line: string }[];
let previous: Logger;

beforeEach(() => {
  lines = [];
  const writer: LogWriter = {
    write: (path, line) => lines.push({ path, line }),
    close: async () => {},
  };
  previous = getServerLogger();
  setServerLogger(new LoggerImpl({ writer, console: false, sessionLogPath: SESSION, caseLogPath: caseLog }));
});

afterEach(() => {
  setServerLogger(previous);
});

const at = (path: string): string[] => lines.filter((l) => l.path === path).map((l) => l.line);
// The session log's [import] lines; the case-log tee is asserted separately where it matters.
const importLines = (): string[] => at(SESSION).filter((l) => l.includes("[import]"));

describe("dispatchImport logs start and merged at the seam every text import crosses", () => {
  it(
    "writes the same [import] lines to the session log and to the case log",
    async () => {
      const root = await mkdtemp(join(tmpdir(), "dfir-1438-"));
      const store = new CaseStore(root);
      const stateStore = new StateStore(store);
      const pipeline = buildRuntimePipeline({
        stateStore,
        store,
        imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
      });
      const app = createApp(store, { pipeline, stateStore });
      await request(app)
        .post("/cases")
        .send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });

      const res = await request(app).post("/cases/c1/import").send({ text: THOR, filename: "thor.json" });
      expect(res.status, JSON.stringify(res.body)).toBe(202);
      const stored = res.body.file as string;

      const merged = await pollFor("the merged line", async () =>
        at(SESSION).find((l) => l.includes(`[import] c1 ${stored}: parsed and merged in `)),
      );
      expect(merged).toMatch(/ INFO {2}\[c1\] \[import\] c1 \S+: parsed and merged in \d+(\.\d)? s$/);

      const start = at(SESSION).find((l) => l.includes(`[import] c1 ${stored}: start — `));
      expect(start).toMatch(/ INFO {2}\[c1\] \[import\] c1 \S+: start — thor, 0\.0 MB$/);

      // The per-case tee: both lines are in the case's own log, byte for byte.
      expect(at(caseLog("c1"))).toContain(start);
      expect(at(caseLog("c1"))).toContain(merged);
      // And the start line was written before the importer finished, in both files.
      for (const path of [SESSION, caseLog("c1")]) {
        const idx = at(path).findIndex((l) => l === start);
        expect(idx, path).toBeGreaterThanOrEqual(0);
        expect(at(path).indexOf(merged), path).toBeGreaterThan(idx);
      }
    },
    POLL_TIMEOUT_MS * 2,
  );
});

describe("recordImportFailure is the one place a FAILED line is written", () => {
  it("logs a warn line with the redacted message and the filename's basename only", () => {
    const rings = createDiagnosticsRings("/srv/cases");
    rings.recordImportFailure(
      "c1",
      "thor",
      "/srv/cases/c1/imports/0003_thor.json",
      new Error("ENOENT: /srv/cases/c1/imports/0003_thor.json missing"),
    );

    const failed = at(SESSION).find((l) => l.includes("FAILED"));
    expect(failed).toBeDefined();
    expect(failed).toMatch(/ WARN {2}\[c1\] \[import\] c1 0003_thor\.json: FAILED \(thor\) — /);
    // Neither the label nor the message carries the operator's path into the case log.
    expect(failed).not.toContain("/srv/cases");
    expect(at(caseLog("c1"))).toContain(failed);
    // The ring holds the same redacted message the log line carries.
    expect(failed).toContain(rings.recentImportFailures[0].error);
    expect(rings.recentImportFailures[0]).toMatchObject({ caseId: "c1", kind: "thor" });
  });
});

describe("dispatchImport on a rejected importer", () => {
  function ingestWith(importThor: () => Promise<unknown>) {
    const deps = {
      store: {} as ImportIngestDeps["store"],
      options: { pipeline: { importThor } },
      runStateExclusive: async (_caseId: string, fn: () => Promise<unknown>) => fn(),
      importLock: new ImportLock(),
      recordImporterRun: () => {},
      redactErr: (err: unknown) => String((err as Error).message ?? err),
      autoTagImported: async () => {},
      getControl: async () => ({ enabled: true }),
      applyWhitelistToCase: async () => ({ matched: 0, added: 0 }),
      applyNsrlToCase: async () => ({ matchedIocs: 0, matchedEvents: 0, added: 0 }),
      applyDeobfuscationToCase: async () => ({ deobfuscated: 0, newIocs: 0, reanalyzed: 0 }),
      resynthesizeInBackground: () => {},
    } as unknown as ImportIngestDeps;
    return createImportIngest(deps);
  }
  const base = { label: "0002_thor.json", idPrefix: "2", importedAt: ISO };

  it("logs a cancelled line, never FAILED, when the analyst aborted it", async () => {
    const abort = Object.assign(new Error("The operation was aborted"), { name: "AbortError" });
    const ingest = ingestWith(() => Promise.reject(abort));

    await expect(ingest.dispatchImport("thor", "c1", "{}", base)).rejects.toBe(abort);

    expect(importLines()).toEqual([
      expect.stringMatching(/INFO {2}\[c1\] \[import\] c1 0002_thor\.json: start — thor, 0\.0 MB$/),
      expect.stringMatching(
        /INFO {2}\[c1\] \[import\] c1 0002_thor\.json: cancelled after \d+(\.\d)? s — stored evidence retained$/,
      ),
    ]);
    expect(importLines().some((l) => l.includes("FAILED"))).toBe(false);
    // Two lines, and both reached the case log.
    expect(at(caseLog("c1")).filter((l) => l.includes("[import]"))).toHaveLength(2);
  });

  it("logs neither merged nor FAILED on any other error — recordImportFailure owns that line", async () => {
    const boom = new Error("Invalid string length");
    const ingest = ingestWith(() => Promise.reject(boom));

    await expect(ingest.dispatchImport("thor", "c1", "{}", base)).rejects.toBe(boom);

    expect(importLines()).toHaveLength(1);
    expect(importLines()[0]).toContain(": start — thor");
  });
});
