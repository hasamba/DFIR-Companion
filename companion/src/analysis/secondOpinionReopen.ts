import { SEVERITY_RANK, type Finding, type InvestigationState, type Severity } from "./stateTypes.js";
import type { SecondOpinion, SecondOpinionDelta } from "./secondOpinion.js";
import { resolveDecisionTargets } from "./secondOpinionTargets.js";
import {
  applySeverityRestores,
  setLiveSeverity,
  severityCapOf,
  withoutSeverityMarks,
  type SeverityCap,
  type SeverityRestoreRecord,
} from "./findingSeverityRestore.js";

// Reopen an accepted second-opinion decision that the primary model now contradicts (#1972).
//
// Synthesis re-applies every accepted decision before it saves, so the primary model's own call on
// new evidence never reached the analyst. Synthesis now keeps that call on each finding an accepted
// severity change or dismissal targets: the GRADED severity of the model's own output, taken before
// the accepted decision and before an analyst severity restore (#1973) are applied. Graded, because
// a raw "High" that a gate would cap to Medium anyway is not a new call.
//
// A decision is reopened when that call differs from BOTH the model's original call and the
// analyst's accepted call (a dismissal: when the call rises above its original one). Repeating the
// overruled call is the normal case and reopens nothing. A reopened decision stays applied until the
// analyst presses Keep (the new call becomes the overruled one) or Drop (the decision is rejected
// and the finding goes back to the primary's call).
//
// #1973 interaction: a restore never opens or closes a reopen — the check reads the call taken
// before it. On Drop the finding takes the primary's graded call AND its cap, and a restore on that
// finding then lifts the cap, exactly as the next synthesis would. So the restore wins over Drop.
//
// The finding field lives here, not in stateTypes.ts, which sits at its size ledger.

/** The primary model's own graded call on a finding, before any analyst value was re-applied. */
export interface PrimaryCall {
  severity: Severity;
  status: Finding["status"];
  cap?: SeverityCap;
}
export interface FindingPrimaryMark {
  primaryCall?: PrimaryCall;
}

export function primaryCallOf(f: Finding): PrimaryCall | undefined {
  return (f as Finding & FindingPrimaryMark).primaryCall;
}

function withoutPrimaryCall<T extends Finding>(f: T): T {
  if (!primaryCallOf(f)) return f;
  const { primaryCall: _c, ...rest } = f as T & FindingPrimaryMark;
  return rest as T;
}

const TARGETED: ReadonlySet<SecondOpinionDelta["kind"]> = new Set(["a_only", "severity"]);
const isTargeted = (d: SecondOpinionDelta): boolean => d.status === "accepted" && TARGETED.has(d.kind);

/**
 * The primary's call on every finding an accepted severity change or dismissal targets, keyed by
 * finding id. `gradeUnapplied` grades the model's output WITHOUT the accepted decisions; it is called
 * only when there is a decision to snapshot for, since grading is not free.
 */
export function primaryCallSnapshot(
  so: SecondOpinion | null,
  gradeUnapplied: () => InvestigationState,
): Map<string, PrimaryCall> {
  const decisions = (so?.deltas ?? []).filter(isTargeted);
  const calls = new Map<string, PrimaryCall>();
  if (decisions.length === 0) return calls;
  const findings = gradeUnapplied().findings;
  for (const d of decisions) {
    const { ids } = resolveDecisionTargets(findings, d);
    for (const f of findings) {
      if (!ids.has(f.id) || calls.has(f.id)) continue;
      const cap = severityCapOf(f);
      calls.set(f.id, { severity: f.severity, status: f.status, ...(cap ? { cap } : {}) });
    }
  }
  return calls;
}

/** Replace every finding's primary call with this run's snapshot. Pure; same state when unchanged. */
export function stampPrimaryCalls(
  state: InvestigationState,
  calls: ReadonlyMap<string, PrimaryCall>,
): InvestigationState {
  let changed = false;
  const findings = state.findings.map((f) => {
    const call = calls.get(f.id);
    if (!call && !primaryCallOf(f)) return f;
    changed = true;
    const rest = withoutPrimaryCall(f);
    return call ? { ...rest, primaryCall: call } : rest;
  });
  return changed ? { ...state, findings } : state;
}

const above = (a: Severity, b: Severity): boolean => SEVERITY_RANK[a] < SEVERITY_RANK[b];

/** The primary's new call when this accepted decision is reopened, else undefined. Pure. */
export function reopenedCall(findings: readonly Finding[], d: SecondOpinionDelta): Severity | undefined {
  if (!isTargeted(d)) return undefined;
  const original = d.aSeverity ?? d.finding?.severity;
  if (!original) return undefined;
  const { ids } = resolveDecisionTargets(findings, d);
  for (const f of findings) {
    const call = ids.has(f.id) ? primaryCallOf(f) : undefined;
    if (!call) continue;
    if (d.kind === "severity" && call.severity !== original && call.severity !== d.bSeverity)
      return call.severity;
    if (d.kind === "a_only" && above(call.severity, original)) return call.severity;
  }
  return undefined;
}

/** A copy of the record whose reopened decisions carry `reopened`, for the panel. Never stored. */
export function markReopenedDecisions(so: SecondOpinion, findings: readonly Finding[]): SecondOpinion {
  return {
    ...so,
    deltas: so.deltas.map((d) => {
      const { reopened: _stale, ...rest } = d;
      const call = reopenedCall(findings, rest);
      return call ? { ...rest, reopened: call } : rest;
    }),
  };
}

/** Keep: the decision stands, and the primary's new call becomes the call it overrules. */
export function keepReopenedDecision(
  so: SecondOpinion,
  deltaId: string,
  findings: readonly Finding[],
): SecondOpinion {
  const d = so.deltas.find((x) => x.id === deltaId);
  const call = d ? reopenedCall(findings, d) : undefined;
  if (!call) throw new Error(`second-opinion decision ${deltaId} is not reopened`);
  return { ...so, deltas: so.deltas.map((x) => (x.id === deltaId ? { ...x, aSeverity: call } : x)) };
}

/**
 * Drop, on the case: every finding the (now rejected) decision targeted goes back to the primary's
 * graded call and its cap; then the analyst's severity restores (#1973) are re-applied to those
 * findings only, so a restore lifts that cap. Pure; other findings are untouched.
 */
export function dropToPrimaryCall(
  state: InvestigationState,
  d: SecondOpinionDelta,
  restores: readonly SeverityRestoreRecord[],
): InvestigationState {
  const { ids } = resolveDecisionTargets(state.findings, d);
  const reset = state.findings.flatMap((f) => {
    const call = ids.has(f.id) ? primaryCallOf(f) : undefined;
    if (!call) return [];
    const bare = { ...withoutSeverityMarks(f), status: call.status };
    const live = setLiveSeverity(bare, call.severity);
    return [call.cap ? { ...live, severityCap: call.cap } : live];
  });
  if (reset.length === 0) return state;
  const lifted = applySeverityRestores({ ...state, findings: reset }, restores).findings;
  const byId = new Map(lifted.map((f) => [f.id, f] as const));
  return { ...state, findings: state.findings.map((f) => byId.get(f.id) ?? f) };
}
