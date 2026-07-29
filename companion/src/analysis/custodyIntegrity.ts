import type { CaseStore } from "../storage/caseStore.js";
import type { CustodyStore, CustodyMismatch, CustodyChainBreak } from "./custody.js";

/**
 * How long a case's verification stays fresh. Re-opening a case a minute later must not re-hash
 * gigabytes of evidence, so an on-open check inside this window is skipped.
 */
export const DEFAULT_ON_OPEN_THROTTLE_MS = 14_400_000; // 4h

export interface IntegrityConfig {
  /**
   * Sweep interval for ALL cases, archived included (DFIR_CUSTODY_VERIFY_INTERVAL_MS).
   * 0 = disabled, and that is the DEFAULT: an idle install should not spend hours re-hashing
   * evidence nobody is looking at. Operators who want unattended assurance across the whole store
   * opt in by setting it.
   */
  intervalMs: number;
  /**
   * Freshness window for verifying a case when an analyst opens it
   * (DFIR_CUSTODY_VERIFY_ON_OPEN_MS). 0 = never verify on open.
   */
  onOpenThrottleMs: number;
}

function parseMs(raw: string | undefined, fallback: number): number {
  // Parsed explicitly rather than with `|| fallback`, which would swallow a literal "0" — the one
  // value an operator uses to turn a trigger OFF, and the one a fallback must not override.
  const parsed = raw != null && raw !== "" ? Number(raw) : fallback;
  return Number.isFinite(parsed) ? Math.max(0, parsed) : fallback;
}

export function resolveIntegrityConfig(env: NodeJS.ProcessEnv = process.env): IntegrityConfig {
  return {
    intervalMs: parseMs(env.DFIR_CUSTODY_VERIFY_INTERVAL_MS, 0),
    onOpenThrottleMs: parseMs(env.DFIR_CUSTODY_VERIFY_ON_OPEN_MS, DEFAULT_ON_OPEN_THROTTLE_MS),
  };
}

/** What one case's verification found. Retained per case, and replaced on every re-verification. */
export interface CaseVerification {
  caseId: string;
  at: string;
  durationMs: number;
  artifacts: number;
  mismatches: CustodyMismatch[];
  chainBreaks: CustodyChainBreak[];
}

/** One case's verification, kept only when something is wrong with it. */
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
  artifacts: number;
  failedArtifacts: number;
  chainBreaks: number;
  problemCases: CaseIntegrityProblem[];
}

/** What /diagnostics shows: the aggregate of what is currently known, without the per-record detail. */
export interface EvidenceIntegrityStatus {
  /** Is the all-cases scheduled sweep switched on? */
  enabled: boolean;
  intervalMs: number;
  /** Is a case verified when an analyst opens it? */
  verifyOnOpen: boolean;
  onOpenThrottleMs: number;
  /** Most recent verification of ANY case, however it was triggered. */
  lastRunAt: string | null;
  lastDurationMs: number | null;
  casesVerified: number;
  artifacts: number;
  failedArtifacts: number;
  chainBreaks: number;
  problemCaseIds: string[];
}

/**
 * Re-verification of stored evidence (#231 item 3).
 *
 * A custody record asserts a hash at collection time; nothing re-checks it afterwards, so silent
 * corruption — a failing disk, a botched restore, a deliberate swap — would surface only when
 * someone happened to hit the verify endpoint, potentially long after it mattered.
 *
 * Two triggers, because they answer different questions:
 *   - ON OPEN (default): verify the case an analyst just connected to, throttled. The answer is
 *     fresh at the moment someone is actually relying on the evidence.
 *   - SCHEDULED SWEEP (opt-in): verify every case including archived ones. Catches rot in evidence
 *     nobody is looking at — the thing on-open verification structurally cannot see — at the cost
 *     of re-hashing the entire store on a timer.
 *
 * Both ask the same two questions per case: did the EVIDENCE change (re-hash each artifact) and did
 * the LOG change (walk the chain).
 *
 * Deliberately timer-free. Scheduling lives in createApp beside the scheduled-backup timer, which
 * keeps the scheduling in one place and leaves this class synchronously testable.
 */
export class EvidenceIntegrityMonitor {
  /** Latest verification per case. The status is derived from this, never from one sweep's snapshot. */
  private readonly byCase = new Map<string, CaseVerification>();
  private readonly inFlight = new Set<string>();
  private sweeping = false;

  constructor(
    private readonly cases: CaseStore,
    private readonly custody: CustodyStore,
    private readonly config: IntegrityConfig,
    private readonly onProblem?: (sweep: IntegritySweep) => void,
  ) {}

  status(): EvidenceIntegrityStatus {
    const results = [...this.byCase.values()];
    const latest = results.reduce<CaseVerification | null>(
      (newest, r) => (newest === null || r.at > newest.at ? r : newest),
      null,
    );
    return {
      enabled: this.config.intervalMs > 0,
      intervalMs: this.config.intervalMs,
      verifyOnOpen: this.config.onOpenThrottleMs > 0,
      onOpenThrottleMs: this.config.onOpenThrottleMs,
      lastRunAt: latest?.at ?? null,
      lastDurationMs: latest?.durationMs ?? null,
      casesVerified: results.length,
      artifacts: results.reduce((n, r) => n + r.artifacts, 0),
      failedArtifacts: results.reduce((n, r) => n + r.mismatches.length, 0),
      chainBreaks: results.reduce((n, r) => n + r.chainBreaks.length, 0),
      problemCaseIds: results.filter((r) => r.mismatches.length > 0 || r.chainBreaks.length > 0).map((r) => r.caseId),
    };
  }

  /** Verify one case now, replacing whatever was previously known about it. */
  async verifyCase(caseId: string): Promise<CaseVerification> {
    const startedAt = Date.now();
    const records = await this.custody.load(caseId);
    const [mismatches, chainBreaks] = await Promise.all([
      this.custody.verifyIntegrity(caseId),
      this.custody.verifyChain(caseId),
    ]);
    const finishedAt = Date.now();
    const result: CaseVerification = {
      caseId,
      at: new Date(finishedAt).toISOString(),
      durationMs: finishedAt - startedAt,
      artifacts: new Set(records.map((r) => r.artifactPath)).size,
      mismatches,
      chainBreaks,
    };
    // Replaces the previous result rather than accumulating: a case restored from backup must be
    // able to go back to clean, or the operator can never clear an alert.
    this.byCase.set(caseId, result);
    if (mismatches.length > 0 || chainBreaks.length > 0) this.alert([result], startedAt, finishedAt, 1);
    return result;
  }

  /**
   * Verify a case an analyst just opened, unless it was verified recently or a check is already
   * running for it. Returns null when it was skipped, so the caller can tell "clean" from "not run".
   * `now` is a parameter for the same reason summarizeImportAttempts takes one — the throttle is
   * pure arithmetic and testing it should not need a clock.
   */
  async verifyCaseIfStale(caseId: string, now: number = Date.now()): Promise<CaseVerification | null> {
    if (this.config.onOpenThrottleMs <= 0) return null;
    if (this.inFlight.has(caseId)) return null;
    const previous = this.byCase.get(caseId);
    if (previous && now - Date.parse(previous.at) < this.config.onOpenThrottleMs) return null;

    this.inFlight.add(caseId);
    try {
      return await this.verifyCase(caseId);
    } finally {
      this.inFlight.delete(caseId);
    }
  }

  /**
   * Verify every case, archived included. A case that throws is skipped rather than abandoning the
   * run — one unreadable case must not hide the verification state of every other one.
   */
  async runSweep(): Promise<IntegritySweep> {
    const startedAt = Date.now();
    const metas = await this.cases.listCases().catch(() => []);
    const results: CaseVerification[] = [];
    for (const meta of metas) {
      try {
        results.push(await this.verifyCaseQuietly(meta.caseId));
      } catch {
        continue;
      }
    }
    const finishedAt = Date.now();
    const problems = results.filter((r) => r.mismatches.length > 0 || r.chainBreaks.length > 0);
    const sweep = this.buildSweep(results, problems, startedAt, finishedAt, metas.length);
    if (problems.length > 0) this.onProblem?.(sweep);
    return sweep;
  }

  /** Run a sweep unless one is already in flight — overlapping sweeps compete for the same disk. */
  async runSweepIfIdle(): Promise<IntegritySweep | null> {
    if (this.sweeping) return null;
    this.sweeping = true;
    try {
      return await this.runSweep();
    } finally {
      this.sweeping = false;
    }
  }

  // As verifyCase, but without the per-case alert: a sweep reports its problems once, at the end,
  // rather than firing a separate notification for every failing case as it walks the store.
  private async verifyCaseQuietly(caseId: string): Promise<CaseVerification> {
    const startedAt = Date.now();
    const records = await this.custody.load(caseId);
    const [mismatches, chainBreaks] = await Promise.all([
      this.custody.verifyIntegrity(caseId),
      this.custody.verifyChain(caseId),
    ]);
    const finishedAt = Date.now();
    const result: CaseVerification = {
      caseId,
      at: new Date(finishedAt).toISOString(),
      durationMs: finishedAt - startedAt,
      artifacts: new Set(records.map((r) => r.artifactPath)).size,
      mismatches,
      chainBreaks,
    };
    this.byCase.set(caseId, result);
    return result;
  }

  private alert(results: CaseVerification[], startedAt: number, finishedAt: number, casesChecked: number): void {
    const problems = results.filter((r) => r.mismatches.length > 0 || r.chainBreaks.length > 0);
    this.onProblem?.(this.buildSweep(results, problems, startedAt, finishedAt, casesChecked));
  }

  private buildSweep(
    results: CaseVerification[],
    problems: CaseVerification[],
    startedAt: number,
    finishedAt: number,
    casesChecked: number,
  ): IntegritySweep {
    return {
      startedAt: new Date(startedAt).toISOString(),
      finishedAt: new Date(finishedAt).toISOString(),
      durationMs: finishedAt - startedAt,
      casesChecked,
      artifacts: results.reduce((n, r) => n + r.artifacts, 0),
      failedArtifacts: results.reduce((n, r) => n + r.mismatches.length, 0),
      chainBreaks: results.reduce((n, r) => n + r.chainBreaks.length, 0),
      problemCases: problems.map((r) => ({ caseId: r.caseId, mismatches: r.mismatches, chainBreaks: r.chainBreaks })),
    };
  }
}
