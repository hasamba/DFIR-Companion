import { describe, it, expect, afterEach } from "vitest";
import { createDiagnosticsRings } from "../../src/composition/diagnosticsRings.js";
import { createImportDebugRecorder } from "../../src/analysis/importDebug.js";
import { LoggerImpl, createConsoleLogger } from "../../src/logging/logger.js";
import { setServerLogger } from "../../src/logging/serverLogger.js";

// #1736: a failed import's own recorder travels with the failure into the diagnostics ring (and so
// into the support bundle), and its one [import-debug] line reaches the debug log.

afterEach(() => setServerLogger(createConsoleLogger("error")));

function captureLogger() {
  const lines: string[] = [];
  const logger = new LoggerImpl({
    level: "info",
    console: false,
    writer: { write: () => {}, close: async () => {} },
    debugLog: {
      write: (l: string) => lines.push(l),
      files: () => ({ previous: "", current: "" }),
      close: () => {},
    },
  });
  setServerLogger(logger);
  return lines;
}

describe("recordImportFailure with a debug recorder", () => {
  it("attaches the sanitized summary and writes one failed [import-debug] line", () => {
    const lines = captureLogger();
    const rings = createDiagnosticsRings("/tmp/cases-root-not-used");
    const debug = createImportDebugRecorder();
    debug.detected("siem", { confident: false, decision: "builtin_unconfident" });
    debug.skipped("unparseable_record", 4);
    debug.field("timestamp", "@timestamp", 10);
    rings.recordImportFailure("c1", "siem", "0001_export.json", new Error("boom"), debug);
    const entry = rings.recentImportFailures[0];
    expect(entry.importer?.kind).toBe("siem");
    expect(entry.importer?.skipped).toEqual({ unparseable_record: 4 });
    expect(entry.importer?.outcome).toBe("failed");
    const debugLines = lines.filter((l) => l.includes("[import-debug] importer siem"));
    expect(debugLines).toHaveLength(1);
    expect(debugLines[0]).not.toContain("export.json");
  });

  it("keeps the old shape when no recorder is passed", () => {
    captureLogger();
    const rings = createDiagnosticsRings("/tmp/cases-root-not-used");
    rings.recordImportFailure("c1", "csv", "0002_x.csv", new Error("boom"));
    expect(rings.recentImportFailures[0].importer).toBeUndefined();
  });
});
