import { describe, it, expect } from "vitest";
import { buildDiagnosticsText, type DiagnosticsReport } from "../../src/analysis/diagnostics.js";
import type { EvidenceIntegrityStatus } from "../../src/analysis/custodyIntegrity.js";

function report(evidenceIntegrity: EvidenceIntegrityStatus): DiagnosticsReport {
  return {
    generatedAt: "2026-07-28T12:00:00.000Z",
    uptimeMs: 3_600_000,
    disk: {
      freeBytes: 1,
      totalBytes: 2,
      usedPct: 50,
      level: "none",
      thresholds: { warnPct: 80, dangerPct: 90, criticalPct: 95 },
    },
    cases: { count: 1, open: 1, closed: 0, archived: 0 },
    queue: {
      bufferedCaptures: 0,
      casesBuffering: 0,
      oldestBufferedAgeMs: null,
      synthInFlight: 0,
      pendingAnalysisCases: 0,
    },
    ai: { configured: false, recentErrors: [], errorCounts: {} } as unknown as DiagnosticsReport["ai"],
    importers: {
      attempts: { last24h: 0, last7d: 0, total: 0 },
      recentFailures: [],
      customImporters: 0,
      perImporter: [],
      loadErrors: [],
    },
    backups: { enabled: true, totalCount: 0, totalBytes: 0, retain: 24, maxBytes: 0, overBudgetCases: 0 },
    evidenceIntegrity,
  };
}

const base: EvidenceIntegrityStatus = {
  enabled: false,
  intervalMs: 0,
  verifyOnOpen: true,
  onOpenThrottleMs: 14_400_000,
  lastRunAt: null,
  lastDurationMs: null,
  casesVerified: 0,
  artifacts: 0,
  failedArtifacts: 0,
  chainBreaks: 0,
  problemCaseIds: [],
};

describe("evidence integrity in the diagnostics text", () => {
  it("names the triggers, and says plainly that nothing has been verified yet", () => {
    const text = buildDiagnosticsText(report(base));

    expect(text).toContain("-- Evidence integrity --");
    expect(text).toContain("on case open");
    expect(text).toContain("no case verified yet");
  });

  it("mentions the all-cases sweep only when the operator opted in", () => {
    expect(buildDiagnosticsText(report(base))).not.toContain("scheduled sweep");
    expect(buildDiagnosticsText(report({ ...base, enabled: true, intervalMs: 86_400_000 }))).toContain(
      "scheduled sweep of all cases every 1d",
    );
  });

  it("reports an all-clear with the artifact count", () => {
    const text = buildDiagnosticsText(
      report({
        ...base,
        lastRunAt: "2026-07-28T10:00:00.000Z",
        lastDurationMs: 4200,
        artifacts: 1247,
        casesVerified: 3,
      }),
    );

    expect(text).toContain("all 1247 artifacts OK across 3 case(s)");
  });

  it("leads with the failure count when artifacts fail", () => {
    const text = buildDiagnosticsText(
      report({
        ...base,
        lastRunAt: "2026-07-28T10:00:00.000Z",
        artifacts: 1247,
        failedArtifacts: 3,
        problemCaseIds: ["INC-1"],
      }),
    );

    expect(text).toContain("3 of 1247 artifacts FAILED verification");
    expect(text).toContain("INC-1");
  });

  it("reports a broken custody log even when every artifact hashes clean", () => {
    const text = buildDiagnosticsText(
      report({
        ...base,
        lastRunAt: "2026-07-28T10:00:00.000Z",
        artifacts: 5,
        chainBreaks: 2,
        problemCaseIds: ["INC-2"],
      }),
    );

    expect(text).toContain("2 custody-log chain break(s)");
  });

  it("says so when every trigger is switched off", () => {
    const text = buildDiagnosticsText(
      report({ ...base, enabled: false, intervalMs: 0, verifyOnOpen: false, onOpenThrottleMs: 0 }),
    );

    expect(text).toContain("verification is switched off");
  });
});
