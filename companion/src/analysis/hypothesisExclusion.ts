import type { Hypothesis, HypothesisSeed } from "./hypothesis.js";
import {
  assessHypothesisEvidence,
  activeExclusionIds,
  type AssessmentEligibility,
  type HypothesisAssessment,
} from "./hypothesisDiagnostics.js";

// Analyst exclusions and the material-change flag (#933 item 22).
//
// An exclusion says "this observation does not bear on THIS question" — for one hypothesis, with a
// reason, dated, signed. It removes nothing: the event stays in the timeline, the link stays in the
// hypothesis, every other hypothesis reads the observation as before. The reading
// (hypothesisDiagnostics.ts) skips an ACTIVE entry; a restore closes it and the entry stays as
// history. Excluding does NOT freeze the hypothesis (`analystTouched`): freezing for one exclusion
// would stop every later refresh of its links, which is exactly what the review flag needs to see.
//
// The review flag: a frozen judgment is never rewritten by the machine, so when what it rests on
// changes, the analyst is told WHY — an excluded observation now distinguishes, the observations a
// conclusion rested on stopped distinguishing, a contradiction now supports an alternative, or the
// latest synthesis withdrew a support / added a contradiction the frozen copy does not carry.
//
// Pure — no I/O; the store passes `now`.

const MAX_REASON_LEN = 500;

export function excludeEvidence(
  h: Hypothesis,
  eventId: string,
  reason: string,
  by: string,
  now: string,
): Hypothesis | null {
  const id = String(eventId ?? "").trim();
  const why = String(reason ?? "")
    .trim()
    .slice(0, MAX_REASON_LEN);
  if (!id || !why) return null;
  if (!h.relatedEventIds.includes(id) && !h.contradictingEventIds.includes(id)) return null;
  if (activeExclusionIds(h).has(id)) return h; // already excluded — nothing to write
  return {
    ...h,
    excludedEvidence: [
      ...h.excludedEvidence,
      { eventId: id, reason: why, by: String(by ?? "").trim() || "analyst", excludedAt: now },
    ],
    updatedAt: now,
  };
}

export function restoreEvidence(h: Hypothesis, eventId: string, by: string, now: string): Hypothesis | null {
  const id = String(eventId ?? "").trim();
  if (!activeExclusionIds(h).has(id)) return null;
  return {
    ...h,
    excludedEvidence: h.excludedEvidence.map((x) =>
      x.eventId === id && !x.restoredAt
        ? { ...x, restoredAt: now, restoredBy: String(by ?? "").trim() || "analyst" }
        : x,
    ),
    updatedAt: now,
  };
}

// Close every active exclusion whose observation is no longer linked (a PATCH or a refresh removed
// it). Relinking later does not revive a closed entry — a new exclusion needs a new action. Returns
// the same object when nothing changed, so the store can skip the write.
export function closeUnlinkedExclusions(h: Hypothesis, now: string): Hypothesis {
  const linked = new Set([...h.relatedEventIds, ...h.contradictingEventIds]);
  if (!h.excludedEvidence.some((x) => !x.restoredAt && !linked.has(x.eventId))) return h;
  return {
    ...h,
    excludedEvidence: h.excludedEvidence.map((x) =>
      !x.restoredAt && !linked.has(x.eventId) ? { ...x, restoredAt: now, restoredBy: "unlinked" } : x,
    ),
    updatedAt: now,
  };
}

export interface FlagMaterialChangesResult {
  hypotheses: Hypothesis[];
  changed: boolean;
}

const MAX_REVIEW_REASON_LEN = 1000;

// Reasons for one hypothesis, compared before → after. Only the hypotheses the analyst owns a
// judgment on are read: touched ones, and ones carrying an active exclusion.
function distinguishingRefs(a: HypothesisAssessment | undefined, id: string) {
  const sup = a?.support.distinguishing.find((d) => d.eventId === id);
  const con = a?.contradiction.distinguishing.find((d) => d.eventId === id);
  return sup?.separatesFrom ?? con?.supports ?? [];
}

function materialReasons(
  h: Hypothesis,
  before: HypothesisAssessment | undefined,
  after: HypothesisAssessment,
  bare: { before: HypothesisAssessment | undefined; after: HypothesisAssessment | undefined },
  seed: HypothesisSeed | undefined,
): string[] {
  const reasons: string[] = [];
  // An excluded observation that BECAME distinguishing — a transition, not a state. One the analyst
  // excluded while it already distinguished was their call; it is not raised again on every merge.
  for (const id of activeExclusionIds(h)) {
    const now = distinguishingRefs(bare.after, id);
    const was = new Set(distinguishingRefs(bare.before, id).map((x) => x.id));
    const fresh = now.filter((x) => !was.has(x.id));
    if (fresh.length)
      reasons.push(
        `an observation you excluded (${id}) now separates this from ${fresh.map((x) => `'${x.title}'`).join(", ")}`,
      );
  }
  if (before) {
    if (
      h.status === "supported" &&
      before.support.distinguishing.length &&
      !after.support.distinguishing.length
    )
      reasons.push(
        "the observation(s) this conclusion rested on no longer separate it from the alternatives",
      );
    const known = new Set(before.contradiction.distinguishing.map((d) => d.eventId));
    for (const d of after.contradiction.distinguishing) {
      if (!known.has(d.eventId))
        reasons.push(`${d.eventId} now supports ${d.supports.map((x) => `'${x.title}'`).join(", ")}`);
    }
  }
  if (seed && h.analystTouched) {
    const seedSupport = new Set(seed.relatedEventIds);
    for (const d of after.support.distinguishing) {
      if (!seedSupport.has(d.eventId))
        reasons.push(`the latest synthesis no longer cites ${d.eventId} as support for this`);
    }
    const mine = new Set(h.contradictingEventIds);
    for (const id of seed.contradictingEventIds ?? []) {
      if (!mine.has(id)) reasons.push(`the latest synthesis cites ${id} against this`);
    }
  }
  return reasons;
}

// The reading of one hypothesis with its own exclusions lifted — what its excluded observations
// WOULD bear if counted.
function bareAssessment(
  all: readonly Hypothesis[],
  id: string,
  e: AssessmentEligibility,
): HypothesisAssessment | undefined {
  const h = all.find((o) => o.id === id);
  if (!h || !activeExclusionIds(h).size) return h ? assessHypothesisEvidence(all, e).get(id) : undefined;
  return assessHypothesisEvidence(
    all.map((o) => (o.id === id ? { ...o, excludedEvidence: [] } : o)),
    e,
  ).get(id);
}

// Add reasons to a review flag without losing the ones already shown: the false-positive cascade
// and a material change can both apply, and the analyst must see every cause before acknowledging.
export function mergeReviewReasons(existing: string, incoming: readonly string[]): string {
  const parts = existing ? existing.split("; ") : [];
  const seen = new Set(parts);
  for (const r of incoming) {
    if (!seen.has(r)) {
      seen.add(r);
      parts.push(r);
    }
  }
  return parts.join("; ").slice(0, MAX_REVIEW_REASON_LEN);
}

// Compare the readings before and after a synthesis merge and flag the analyst-owned hypotheses
// whose footing changed. Status, text, links, notes and exclusions are never touched — only
// `needsReview` / `reviewReason` / `updatedAt`. Idempotent: an already-flagged hypothesis whose
// reasons are all already shown is left alone.
export function flagMaterialChanges(
  before: readonly Hypothesis[],
  after: readonly Hypothesis[],
  seedsByKey: ReadonlyMap<string, HypothesisSeed>,
  elig: AssessmentEligibility | undefined,
  now: string,
): FlagMaterialChangesResult {
  const e = elig ?? {};
  const beforeA = assessHypothesisEvidence(before, e);
  const afterA = assessHypothesisEvidence(after, e);
  let changed = false;
  const hypotheses = after.map((h) => {
    const owned = h.analystTouched || activeExclusionIds(h).size > 0;
    if (!owned) return h;
    const bare = activeExclusionIds(h).size
      ? { before: bareAssessment(before, h.id, e), after: bareAssessment(after, h.id, e) }
      : { before: undefined, after: undefined };
    const seed = h.sourceKey ? seedsByKey.get(h.sourceKey) : undefined;
    const reasons = materialReasons(h, beforeA.get(h.id), afterA.get(h.id)!, bare, seed);
    if (!reasons.length) return h;
    const reviewReason = mergeReviewReasons(h.needsReview ? h.reviewReason : "", reasons);
    if (h.needsReview && h.reviewReason === reviewReason) return h;
    changed = true;
    return { ...h, needsReview: true, reviewReason, updatedAt: now };
  });
  return { hypotheses, changed };
}
