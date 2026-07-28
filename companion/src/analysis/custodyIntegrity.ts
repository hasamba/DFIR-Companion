import type { CaseStore } from "../storage/caseStore.js";
import type { CustodyStore, CustodyMismatch, CustodyChainBreak } from "./custody.js";

/** Default sweep interval: once a day. Re-hashing every artifact is I/O-heavy, not a health ping. */
export const DEFAULT_VERIFY_INTERVAL_MS = 86_400_000;

export interface IntegrityConfig {
  /** How often to re-verify all stored evidence (DFIR_CUSTODY_VERIFY_INTERVAL_MS). 0 = disabled. */
  intervalMs: number;
}

export function resolveIntegrityConfig(env: NodeJS.ProcessEnv = process.env): IntegrityConfig {
  const raw = env.DFIR_CUSTODY_VERIFY_INTERVAL_MS;
  // Parsed explicitly rather than with `|| DEFAULT`, which would swallow a literal "0" — the one
  // value an operator uses to turn the sweep OFF, and the one a fallback must not override.
  const parsed = raw != null && raw !== "" ? Number(raw) : DEFAULT_VERIFY_INTERVAL_MS;
  const intervalMs = Number.isFinite(parsed) ? Math.max(0, parsed) : DEFAULT_VERIFY_INTERVAL_MS;
  return { intervalMs };
}

/** One case's verification result, only kept when something is actually wrong with it. */
export interface CaseIntegrityProblem {
  caseId: string;
  mismatches: CustodyMismatch[];
  chainBreaks: CustodyChainBreak[];
}

export interface IntegritySweep {
  startedAt: string;
  finishedAt: string;
  durationMs: number;
  casesChecked: number;
  /** Distinct artifacts re-hashed across every case. */
  artifacts: number;
  /** Artifacts whose bytes no longer match, or that have gone missing. */
  failedArtifacts: number;
  /** Places where a custody log stopped being a chain. */
  chainBreaks: number;
  problemCases: CaseIntegrityProblem[];
}

/** What /diagnostics shows: the headline of the last sweep, without the per-record detail. */
export interface EvidenceIntegrityStatus {
  enabled: boolean;
  intervalMs: number;
  lastRunAt: string | null;
  lastDurationMs: number | null;
  artifacts: number;
  failedArtifacts: number;
  chainBreaks: number;
  problemCaseIds: string[];
}

/**
 * Periodic re-verification of all stored evidence (#231 item 3).
 *
 * A custody record asserts a hash at collection time; nothing re-checks it afterwards, so silent
 * corruption — a failing disk, a botched restore, a deliberate swap — would surface only when
 * someone happened to hit the verify endpoint, potentially long after it mattered. This sweeps
 * every case on a schedule and raises an alert the moment the answer changes.
 *
 * Both questions are asked per case: did the EVIDENCE change (re-hash each artifact) and did the LOG
 * change (walk the chain). Archived cases are included — archived evidence is still evidence.
 *
 * Deliberately timer-free. The interval lives in createApp beside the scheduled-backup timer, which
 * keeps the scheduling in one place and leaves this class synchronously testable.
 */
export class EvidenceIntegrityMonitor {
  private last: IntegritySweep | null = null;
  private running = false;

  constructor(
    private readonly cases: CaseStore,
    private readonly custody: CustodyStore,
    private readonly config: IntegrityConfig,
    private readonly onProblem?: (sweep: IntegritySweep) => void,
  ) {}

  status(): EvidenceIntegrityStatus {
    return {
      enabled: this.config.intervalMs > 0,
      intervalMs: this.config.intervalMs,
      lastRunAt: this.last?.finishedAt ?? null,
      lastDurationMs: this.last?.durationMs ?? null,
      artifacts: this.last?.artifacts ?? 0,
      failedArtifacts: this.last?.failedArtifacts ?? 0,
      chainBreaks: this.last?.chainBreaks ?? 0,
      problemCaseIds: this.last?.problemCases.map((c) => c.caseId) ?? [],
    };
  }

  /**
   * Verify every case once. Returns the sweep and retains it as the reported status. A case that
   * throws mid-sweep is skipped rather than abandoning the run — one unreadable case must not hide
   * the verification state of every other one.
   */
  async runSweep(): Promise<IntegritySweep> {
    const startedAt = new Date();
    const metas = await this.cases.listCases().catch(() => []);
    let artifacts = 0;
    let failedArtifacts = 0;
    let chainBreaks = 0;
    const problemCases: CaseIntegrityProblem[] = [];

    for (const meta of metas) {
      try {
        const records = await this.custody.load(meta.caseId);
        artifacts += new Set(records.map((r) => r.artifactPath)).size;
        const [mismatches, breaks] = await Promise.all([
          this.custody.verifyIntegrity(meta.caseId),
          this.custody.verifyChain(meta.caseId),
        ]);
        failedArtifacts += mismatches.length;
        chainBreaks += breaks.length;
        if (mismatches.length > 0 || breaks.length > 0) {
          problemCases.push({ caseId: meta.caseId, mismatches, chainBreaks: breaks });
        }
      } catch {
        continue;
      }
    }

    const finishedAt = new Date();
    const sweep: IntegritySweep = {
      startedAt: startedAt.toISOString(),
      finishedAt: finishedAt.toISOString(),
      durationMs: finishedAt.getTime() - startedAt.getTime(),
      casesChecked: metas.length,
      artifacts,
      failedArtifacts,
      chainBreaks,
      problemCases,
    };
    this.last = sweep;
    if (problemCases.length > 0) this.onProblem?.(sweep);
    return sweep;
  }

  /**
   * Run a sweep unless one is already in flight. Re-hashing can outlast the interval on a large
   * install, and overlapping sweeps would compete for the same disk and report over each other.
   */
  async runSweepIfIdle(): Promise<IntegritySweep | null> {
    if (this.running) return null;
    this.running = true;
    try {
      return await this.runSweep();
    } finally {
      this.running = false;
    }
  }
}
