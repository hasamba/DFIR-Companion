import type { Finding } from "./stateTypes.js";
import { deriveSemanticKey } from "./semanticKey.js";
import type { SecondOpinion, SecondOpinionDelta, UnappliedReason } from "./secondOpinion.js";

// Which finding an accepted second-opinion decision lands on (#1590).
//
// A decision used to find its finding only by the derived key — dominant technique plus a noun
// phrase from the title. A re-synthesis that retitles a finding or retags it changes that key, and
// the analyst's dismissal or severity change silently stopped applying. The finding id is the
// better signal: synthesis shows the model the prior findings and it re-emits them by id. But an id
// is a model-kept hint, not proof, so the id wins only while there is evidence it is still the same
// claim: the same key, the same title, a shared cited event, or a shared technique. With no such
// evidence the id holds a different claim now, and the decision is reported, not applied.

export const norm = (title: string): string => String(title).trim().toLowerCase().replace(/\s+/g, " ");

/**
 * The derived cross-run key of a finding (issue #69): stored semanticKey, else derived. Never empty.
 * The FALLBACK identity since #1590 — the finding id comes first.
 */
export const matchKey = (f: Finding): string => f.semanticKey?.trim() || deriveSemanticKey(f);

const overlaps = (a: readonly string[] | undefined, b: readonly string[] | undefined): boolean =>
  !!a?.length && !!b?.length && a.some((x) => b.includes(x));

function sameClaim(snapshot: Finding, now: Finding): boolean {
  // A snapshot saved before #1590 lost its cited events to the store schema (the field is absent,
  // not empty). It has no evidence to check, so its id is trusted as it stands — otherwise every
  // decision accepted before this fix would fall to the old retitle/retag loss.
  if (snapshot.relatedEventIds === undefined) return true;
  return (
    matchKey(snapshot) === matchKey(now) ||
    norm(snapshot.title) === norm(now.title) ||
    overlaps(snapshot.relatedEventIds, now.relatedEventIds) ||
    overlaps(snapshot.mitreTechniques, now.mitreTechniques)
  );
}

export interface TargetResolution {
  ids: ReadonlySet<string>; // the findings the decision applies to; empty when it applies to none
  problem?: UnappliedReason;
}

/** Resolve an a_only / severity decision to the findings it applies to. Pure. */
export function resolveDecisionTargets(
  findings: readonly Finding[],
  d: SecondOpinionDelta,
): TargetResolution {
  const snapshot = d.finding;
  const key = snapshot ? matchKey(snapshot) : norm(d.title);
  const byId = snapshot ? findings.find((f) => f.id === snapshot.id) : undefined;
  if (byId && snapshot && sameClaim(snapshot, byId)) return { ids: new Set([byId.id]) };
  const keyed = findings.filter((f) => matchKey(f) === key);
  if (keyed.length > 0) return { ids: new Set(keyed.map((f) => f.id)) };
  return { ids: new Set(), problem: byId ? "changed" : "missing" };
}

/** Only these kinds can fail to land: B-only adds its finding, ATT&CK edits need no finding. */
const TARGETED_KINDS: ReadonlySet<SecondOpinionDelta["kind"]> = new Set(["a_only", "severity"]);

export interface UnappliedDecision {
  deltaId: string;
  reason: UnappliedReason;
}

/** Accepted decisions that match no finding in `findings`, in record order. Pure. */
export function unappliedSecondOpinionDeltas(
  findings: readonly Finding[],
  so: SecondOpinion | null,
): UnappliedDecision[] {
  const out: UnappliedDecision[] = [];
  for (const d of so?.deltas ?? []) {
    if (d.status !== "accepted" || !TARGETED_KINDS.has(d.kind)) continue;
    const { problem } = resolveDecisionTargets(findings, d);
    if (problem) out.push({ deltaId: d.id, reason: problem });
  }
  return out;
}

/** A copy of the record whose unapplied accepted decisions carry `unapplied`, for the panel. Pure. */
export function markUnappliedDecisions(so: SecondOpinion, findings: readonly Finding[]): SecondOpinion {
  const byId = new Map(unappliedSecondOpinionDeltas(findings, so).map((u) => [u.deltaId, u.reason]));
  return {
    ...so,
    deltas: so.deltas.map((d) => {
      const { unapplied: _stale, ...rest } = d;
      const reason = byId.get(d.id);
      return reason ? { ...rest, unapplied: reason } : rest;
    }),
  };
}

/** Same point, same call: the analyst already decided it, so the fresh copy is noise. */
function repeats(carried: SecondOpinionDelta, fresh: SecondOpinionDelta): boolean {
  if (carried.id === fresh.id) return true;
  return (
    carried.kind === fresh.kind &&
    !!carried.finding &&
    carried.finding.id === fresh.finding?.id &&
    carried.bSeverity === fresh.bSeverity
  );
}

/**
 * A new run ADDS to the decisions already accepted instead of replacing them (#1590). Every accepted
 * delta of `prev` is kept, stamped with the run it was first accepted in. A fresh delta that repeats
 * one is dropped; a fresh delta that proposes something different for the same finding stays, and
 * because carried decisions come first, accepting it later wins on apply. Rejected and pending
 * deltas of `prev` are not carried — they changed nothing. Pure.
 */
export function carryAcceptedDecisions(prev: SecondOpinion | null, next: SecondOpinion): SecondOpinion {
  const carried = (prev?.deltas ?? [])
    .filter((d) => d.status === "accepted")
    // A flag holds a PENDING dismissal for the analyst (#1596); an accepted decision has settled it.
    .map(({ unapplied: _u, refereeFlags: _f, ...d }) => ({
      ...d,
      carriedFrom: d.carriedFrom || prev?.generatedAt || "",
    }));
  if (carried.length === 0) return next;
  const fresh = next.deltas.filter((n) => !carried.some((c) => repeats(c, n)));
  return { ...next, deltas: [...carried, ...fresh] };
}

/** Deltas this run found, without the decisions carried in from earlier runs. */
export const freshDeltas = (so: SecondOpinion): SecondOpinionDelta[] =>
  so.deltas.filter((d) => !d.carriedFrom);
