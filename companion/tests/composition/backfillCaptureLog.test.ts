// backfill() used to JSON.parse every captures.jsonl line inside the same try block that handles
// "the file does not exist". captures.jsonl is appendFile-written (storage/caseStore.ts), so a
// crash or ENOSPC mid-append can truncate exactly one line — and that single bad line made the
// whole parse throw, which the catch then misread as "no capture log (import-only case)": every
// screenshot captured while AI was off was silently never analyzed, and never would be, because
// the corrupt line stays and lastAnalyzedSeq never advances.
//
// The fix mirrors the importLog loops in routes/caseLifecycle.ts and routes/system.ts: parse per
// line, skip only the malformed line (saying so), and reserve the readFile catch for ENOENT.
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createCaptureAnalysis } from "../../src/composition/captureAnalysis.js";
import { setServerLogger, getServerLogger } from "../../src/logging/serverLogger.js";
import type { Logger } from "../../src/logging/logger.js";
import type { AppOptions } from "../../src/composition/appOptions.js";
import type { CaptureMetadata } from "../../src/types.js";

function capture(seq: number): CaptureMetadata {
  return {
    caseId: "c1",
    sequenceNumber: seq,
    timestamp: "2026-08-20T10:00:00Z",
    url: `https://console.example/page${seq}`,
    tabTitle: `page ${seq}`,
    triggerType: "timer",
    contentHash: `hash${seq}`,
    isDuplicate: false,
    screenshotFile: `00000${seq}.webp`,
  };
}

interface Seen {
  status: string;
  detail?: string;
}

/** A case whose captures.jsonl holds exactly `logText`; null → no log file at all. */
async function harness(logText: string | null) {
  const root = await mkdtemp(join(tmpdir(), "dfir-backfill-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  if (logText !== null) await writeFile(cases.capturesLogPath("c1"), logText, "utf8");

  const analyzed: number[] = [];
  const statuses: Seen[] = [];
  const pipeline = {
    hasSynthesisProvider: () => false,
    analyzeWindow: async (_caseId: string, win: CaptureMetadata[]) => {
      analyzed.push(...win.map((c) => c.sequenceNumber));
    },
  };
  const analysis = createCaptureAnalysis({
    store: cases,
    options: { pipeline, onAiStatus: (_c: string, e: Seen) => statuses.push(e) } as unknown as AppOptions,
    hasAiProvider: () => true,
    getControl: async () => ({ enabled: true, lastAnalyzedSeq: 0 }),
    setControl: async () => ({ enabled: true, lastAnalyzedSeq: 0 }),
    recordAiError: () => {},
    autoEnrichIfEnabled: () => {},
    dispatchNotify: () => {},
  });
  return { analysis, analyzed, statuses };
}

describe("backfill and a damaged captures.jsonl", () => {
  // Capture warnLine output instead of letting the default console logger spray test output.
  const warnings: string[] = [];
  let previous: Logger;
  beforeEach(() => {
    warnings.length = 0;
    previous = getServerLogger();
    setServerLogger({
      debug: () => {},
      info: () => {},
      warn: (m: string) => warnings.push(m),
      error: () => {},
      getLevel: () => "info",
      setLevel: () => {},
      close: async () => {},
    });
  });
  afterEach(() => setServerLogger(previous));

  it("skips a truncated final line and still analyzes every remaining capture", async () => {
    const log =
      JSON.stringify(capture(1)) +
      "\n" +
      JSON.stringify(capture(2)) +
      "\n" +
      '{"caseId":"c1","sequenceNumber":3,"time'; // appendFile died mid-line
    const { analysis, analyzed, statuses } = await harness(log);
    await analysis.backfill("c1");
    expect(analyzed).toEqual([1, 2]);
    // A real catch-up run ending on a terminal idle — not the "no capture log" degradation.
    expect(statuses.at(-1)?.status).toBe("idle");
    expect(warnings.join("\n")).toContain("skipped 1 malformed captures.jsonl line");
  });

  it("still treats a missing captures.jsonl as an import-only case, quietly", async () => {
    const { analysis, analyzed, statuses } = await harness(null);
    await analysis.backfill("c1");
    expect(analyzed).toEqual([]);
    expect(statuses.at(-1)?.status).toBe("idle");
    expect(warnings).toEqual([]); // ENOENT is the expected case, not a read failure
  });
});
