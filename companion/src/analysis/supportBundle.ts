import { AI_ERROR_KINDS, type AiErrorKind } from "./operationalMetrics.js";
import type { OperationalDiagnostics } from "./operationalDiagnostics.js";

export interface SupportBundleInput {
  generatedAt: string;
  version: string;
  uptimeMs: number;
  disk: { totalBytes: number; freeBytes: number; usedPct: number; level: string };
  cases: { count: number; open: number; closed: number; archived: number };
  queue: { queued: number; running: number; stalled: number };
  ai: { configured: boolean; local: boolean; errorsByKind: Record<string, number> };
  operational: OperationalDiagnostics | null;
}

export interface SupportBundle {
  schemaVersion: 1;
  generatedAt: string;
  application: { name: "DFIR Companion"; version: string; node: string; platform: string };
  system: {
    uptimeMs: number;
    disk: SupportBundleInput["disk"];
    caseCounts: SupportBundleInput["cases"];
    queue: SupportBundleInput["queue"];
    ai: {
      configured: boolean;
      local: boolean;
      errorsByKind: Partial<Record<AiErrorKind, number>>;
    };
  };
  operational: OperationalDiagnostics | null;
  redactions: {
    secrets: "excluded";
    caseEvidence: "excluded";
    caseIdentifiers: "excluded";
    evidenceFilenames: "excluded";
    hostnamesAndUsers: "excluded";
    iocs: "excluded";
    absolutePaths: "excluded";
  };
}

function safeErrorCounts(input: Readonly<Record<string, number>>): Partial<Record<AiErrorKind, number>> {
  return Object.fromEntries(
    AI_ERROR_KINDS.flatMap((kind) => {
      const value = input[kind];
      return value !== undefined && Number.isFinite(value) && value > 0 ? [[kind, Math.floor(value)]] : [];
    }),
  );
}

/** Build the deliberately aggregate-only payload shown before a support download. */
export function buildSupportBundle(input: SupportBundleInput): SupportBundle {
  return {
    schemaVersion: 1,
    generatedAt: input.generatedAt,
    application: {
      name: "DFIR Companion",
      version: input.version,
      node: process.version,
      platform: process.platform,
    },
    system: {
      uptimeMs: Math.max(0, input.uptimeMs),
      disk: { ...input.disk },
      caseCounts: { ...input.cases },
      queue: { ...input.queue },
      ai: {
        configured: input.ai.configured,
        local: input.ai.local,
        errorsByKind: safeErrorCounts(input.ai.errorsByKind),
      },
    },
    operational: input.operational,
    redactions: {
      secrets: "excluded",
      caseEvidence: "excluded",
      caseIdentifiers: "excluded",
      evidenceFilenames: "excluded",
      hostnamesAndUsers: "excluded",
      iocs: "excluded",
      absolutePaths: "excluded",
    },
  };
}
