// Analyst severity restore (#1973). Nine deterministic grading gates lower a finding's severity
// (findingGrounding.ts). Each one now records what it lowered and why, on `severityCap`. The analyst
// can lift that cap on ONE finding with one click: "Restore High".
//
// What a restore pins (user decision D1): the cap, not a severity. The gates still run every
// synthesis. A restored finding takes the severity the gates took away on THIS run, so a later model
// call that grades it lower still wins. The case-wide simulation cap (simulationVerdict.ts) applies
// after the restore and keeps its own "Treat as real intrusion" switch (D3).
//
// The record lives in a per-case side file (`state/finding-severity-restore.json`), keyed like the
// outcome store (findingOutcome.ts): findingId plus the finding's semanticKey, so a reused id on a
// different claim never inherits a restore. It is applied at WRITE time, straight after grading
// (ai/synthesis.ts finalizeFindings) and by the route, because severity feeds counts, reports, CSV,
// MCP and the next prompt, and a read-time overlay would have to be repeated in every one of them.
//
// The types live here, not in stateTypes.ts, which sits at its size ledger.

import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import type { CaseStore } from "../storage/caseStore.js";
import { atomicWrite } from "../storage/atomicWrite.js";
import { StateLock } from "./stateLock.js";
import { deriveSemanticKey } from "./semanticKey.js";
import { SEVERITY_RANK, type Finding, type InvestigationState, type Severity } from "./stateTypes.js";

/** Every grading gate that can lower a finding's severity, in grading order. */
export const SEVERITY_CAP_GATES = [
  "content-mismatch",
  "lateral-unconfirmed",
  "self-disclaimed",
  "decoy-binary",
  "echo-only",
  "tamper-timing",
  "lab-setup",
  "build-baseline",
  "intel-only",
] as const;
export type SeverityCapGate = (typeof SEVERITY_CAP_GATES)[number];

/** Plain-English gate names for the report badge. The dashboard keeps its own copy. */
export const SEVERITY_CAP_GATE_LABELS: Record<SeverityCapGate, string> = {
  "content-mismatch": "citation mismatch",
  "lateral-unconfirmed": "unconfirmed lateral movement",
  "self-disclaimed": "subject not in evidence",
  "decoy-binary": "renamed shell",
  "echo-only": "echo-only commands",
  "tamper-timing": "Defender-tamper timing",
  "lab-setup": "lab setup",
  "build-baseline": "build baseline",
  "intel-only": "threat-intel only",
};

/** What the gates did: the severity before them, the severity after them, and which gates lowered it. */
export interface SeverityCap {
  from: Severity;
  to: Severity;
  gates: SeverityCapGate[];
}
export interface SeverityRestored {
  by: string;
  at: string;
}
export interface FindingSeverityMarks {
  severityCap?: SeverityCap;
  severityRestored?: SeverityRestored;
}

export function severityCapOf(f: Finding): SeverityCap | undefined {
  return (f as Finding & FindingSeverityMarks).severityCap;
}
export function severityRestoredOf(f: Finding): SeverityRestored | undefined {
  return (f as Finding & FindingSeverityMarks).severityRestored;
}

/** Drop both marks: grading recomputes the cap, and only the restore step may set the restore mark. */
export function withoutSeverityMarks<T extends Finding>(f: T): T {
  const { severityCap: _cap, severityRestored: _restored, ...rest } = f as T & FindingSeverityMarks;
  return rest as T;
}

const lower = (a: Severity, b: Severity): boolean => SEVERITY_RANK[a] > SEVERITY_RANK[b];

/**
 * The cap mark for a graded finding. A gate that lowered the severity this pass writes a fresh cap.
 * Otherwise a cap recorded by an earlier pass is kept while the finding still sits at that capped
 * severity: a re-grade of an already-capped finding (a carried finding) sees no drop, but the cap is
 * still what put it there.
 */
export function severityCapMark(
  prior: Finding,
  from: Severity,
  to: Severity,
  gates: readonly SeverityCapGate[],
): FindingSeverityMarks {
  if (gates.length && lower(to, from)) return { severityCap: { from, to, gates: [...gates] } };
  const old = severityCapOf(prior);
  return old && old.to === prior.severity && to === prior.severity ? { severityCap: old } : {};
}

/** Add one more lowering gate to a finding's cap (the intel-only gate runs after grounding). */
export function addSeverityCap<T extends Finding>(f: T, to: Severity, gate: SeverityCapGate): T {
  if (!lower(to, f.severity)) return f;
  const old = severityCapOf(f);
  const from = old && old.to === f.severity ? old.from : f.severity;
  const gates = old && old.to === f.severity ? [...old.gates, gate] : [gate];
  return { ...f, severityCap: { from, to, gates } };
}

export const severityRestoreRecordSchema = z.object({
  findingId: z.string(),
  // The finding's claim key when the analyst restored it. Empty only when it had none.
  semanticKey: z.string().default("").catch(""),
  restoredBy: z.string().default("").catch(""),
  restoredAt: z.string().default("").catch(""),
});
export type SeverityRestoreRecord = z.infer<typeof severityRestoreRecordSchema>;
const recordsSchema = z.array(severityRestoreRecordSchema).catch([]);

// Serializes load→modify→save per case: the file is rewritten whole on every change.
const restoreLock = new StateLock();

export class FindingSeverityRestoreStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "finding-severity-restore.json");
  }

  async load(caseId: string): Promise<SeverityRestoreRecord[]> {
    try {
      return recordsSchema.parse(JSON.parse(await readFile(this.path(caseId), "utf8")));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw err;
    }
  }

  /** Record (or replace) the restore of one finding. Throws on a blank findingId. */
  async restore(
    caseId: string,
    findingId: string,
    input: { semanticKey: string; by: string },
  ): Promise<SeverityRestoreRecord> {
    const id = requireId(findingId);
    return restoreLock.runExclusive(caseId, async () => {
      const records = await this.load(caseId);
      const record: SeverityRestoreRecord = {
        findingId: id,
        semanticKey: String(input.semanticKey ?? "").trim(),
        restoredBy: String(input.by ?? "")
          .trim()
          .slice(0, 200),
        restoredAt: new Date().toISOString(),
      };
      const at = records.findIndex((r) => r.findingId === id);
      const next = at < 0 ? [...records, record] : records.map((r, i) => (i === at ? record : r));
      await this.save(caseId, next);
      return record;
    });
  }

  /** Remove one finding's restore. Returns false when there was none. */
  async clear(caseId: string, findingId: string): Promise<boolean> {
    const id = requireId(findingId);
    return restoreLock.runExclusive(caseId, async () => {
      const records = await this.load(caseId);
      const rest = records.filter((r) => r.findingId !== id);
      if (rest.length === records.length) return false;
      await this.save(caseId, rest);
      return true;
    });
  }

  private async save(caseId: string, records: SeverityRestoreRecord[]): Promise<void> {
    await atomicWrite(this.path(caseId), JSON.stringify(records, null, 2));
  }
}

function requireId(findingId: string): string {
  const id = String(findingId ?? "").trim();
  if (!id) throw new Error("findingId is required");
  return id;
}

/**
 * Apply the restore records to a graded state. Pure: new objects, the input is untouched; returns
 * the same state when nothing changes. Only a CAPPED finding is touched. A matching record sets the
 * pre-cap severity and the restore mark; a finding marked restored with no record left goes back to
 * its capped severity. Run the simulation step after this one.
 */
export function applySeverityRestores(
  state: InvestigationState,
  records: readonly SeverityRestoreRecord[],
): InvestigationState {
  const byId = new Map(records.map((r) => [r.findingId, r] as const));
  let changed = false;
  const findings = state.findings.map((f) => {
    const cap = severityCapOf(f);
    if (!cap) return f;
    const candidate = byId.get(f.id);
    const rec = candidate && sameClaim(candidate, f) ? candidate : undefined;
    if (!rec && !severityRestoredOf(f)) return f;
    changed = true;
    const { severityRestored: _old, ...rest } = f as Finding & FindingSeverityMarks;
    const live = setLiveSeverity(rest, rec ? cap.from : cap.to);
    return rec ? { ...live, severityRestored: { by: rec.restoredBy, at: rec.restoredAt } } : live;
  });
  return changed ? { ...state, findings } : state;
}

function sameClaim(r: SeverityRestoreRecord, f: Finding): boolean {
  return !r.semanticKey || r.semanticKey === (f.semanticKey || deriveSemanticKey(f));
}

// The severity the finding has BEFORE the simulation step. When that step capped it, its stored
// original is the value the step restores on its next pass, so the restore goes there instead.
// Exported for the second-opinion Drop (#1972), which writes the same live severity.
export function setLiveSeverity(f: Finding, severity: Severity): Finding {
  const sim = f.simulation;
  if (sim && f.severity === sim.appliedSeverity)
    return { ...f, simulation: { ...sim, originalSeverity: severity } };
  return { ...f, severity };
}

/** The report line for a restored finding, or "" when the analyst restored nothing. */
export function severityRestoredLine(f: Finding): string {
  const restored = severityRestoredOf(f);
  const cap = severityCapOf(f);
  if (!restored || !cap) return "";
  const gates = cap.gates.map((g) => SEVERITY_CAP_GATE_LABELS[g] ?? g).join(", ");
  const by = restored.by || "an analyst";
  return `> ℹ️ **Severity restored by analyst** — ${by} restored ${cap.from} over the ${gates} cap, which had lowered it to ${cap.to}. The cap reason stays in the confidence note.`;
}
