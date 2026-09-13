import type { ForensicEvent } from "./stateTypes.js";
import type { Hypothesis, HypothesisStatus } from "./hypothesis.js";

// Diagnostic evidence (#933 item 22) — does an observation DISTINGUISH the explanations?
//
// A hypothesis carries the observations that support it and the ones that contradict it (ACH,
// #14). Read one hypothesis at a time, ten observations that fit every explanation look like ten
// points for each. Read across the set, each observation has a bearing that the lists alone
// establish — no wording, no severity, no model number:
//
//   distinguishing         supports this hypothesis AND contradicts an alternative (or the other
//                          way round). The only bearing that argues for one explanation over
//                          another — and it always NAMES the alternative it separates this from.
//   consistent             supports this and every alternative that assessed it. Fits them all,
//                          chooses none.
//   against every assessed contradicts this and every alternative that assessed it. None of THOSE
//                          accounts for it; it still counts as a contradiction of each.
//   not assessed elsewhere only this hypothesis assessed it. Silence about the others is not a
//                          judgment about them, so it is never called distinguishing.
//   assessed both ways     the same hypothesis lists it as support and as contradiction. Counted
//                          for nothing there; named so the analyst can settle it.
//
// The competing set is the analyst's `alternativeIds` when set, else every live (not refuted, not
// exhausted) hypothesis. Synthesis emits claims across kill-chain phases, not a mutually exclusive
// set, so nothing is ever called "decisive" in the abstract — the reading names the hypothesis it
// separates this one from, and the analyst narrows the set when that title is not a competitor.
//
// Eligibility comes first: a linked id that is not in the timeline or is marked false positive
// takes no part in any bearing, count or ranking. An active exclusion (hypothesisExclusion.ts) is
// read as "not assessed" on that hypothesis only. Everything here is a count of observations or a
// category word. Nothing here is a probability, and nothing must be turned into one.
//
// Pure and deterministic, NO AI call, no clock.

export interface AlternativeRef {
  id: string;
  title: string;
  status: HypothesisStatus;
}

// A support that contradicts at least one alternative — and which.
export interface DistinguishingSupport {
  eventId: string;
  separatesFrom: AlternativeRef[];
}

// A contradiction that supports at least one alternative — and which.
export interface DistinguishingContradiction {
  eventId: string;
  supports: AlternativeRef[];
}

// An observation the alternatives read the same way this hypothesis does: how many of them assessed
// it (this hypothesis included) and how many never did. Quantifiers are exact, never "every".
export interface SharedReading {
  eventId: string;
  assessedBy: number;
  notAssessedBy: number;
}

export interface ExcludedReading {
  eventId: string;
  reason: string;
  by: string;
  excludedAt: string;
}

export type NotCountedReason = "marked false positive" | "not in the timeline";

export interface HypothesisAssessment {
  hypothesisId: string;
  alternatives: AlternativeRef[];
  alternativesSource: "analyst" | "live";
  support: {
    distinguishing: DistinguishingSupport[];
    consistentWithAlternatives: SharedReading[];
    notAssessedElsewhere: string[];
  };
  contradiction: {
    distinguishing: DistinguishingContradiction[];
    againstEveryAssessed: SharedReading[];
    notAssessedElsewhere: string[];
  };
  assessedBothWays: string[];
  excluded: ExcludedReading[];
  notCounted: { eventId: string; reason: NotCountedReason }[];
  // Every eligible, non-excluded, one-sided contradiction — the ACH ranking's first key, unchanged
  // from #14: how the alternatives read a contradiction never lowers this count.
  activeContradictions: number;
  // Status `supported` resting on exactly one distinguishing observation.
  restsOnSingleObservation: boolean;
  reading: string;
}

export interface AssessmentEligibility {
  eligibleEventIds?: ReadonlySet<string>; // ids present in the timeline; absent = every id is present
  falsePositiveEventIds?: ReadonlySet<string>; // lowercased, as the FalsePositiveStore keeps them
}

const isDead = (h: Hypothesis): boolean => h.exhausted || h.status === "refuted";
const ref = (h: Hypothesis): AlternativeRef => ({ id: h.id, title: h.title, status: h.status });

export function activeExclusionIds(h: Hypothesis): Set<string> {
  return new Set((h.excludedEvidence ?? []).filter((x) => !x.restoredAt).map((x) => x.eventId));
}

// One hypothesis's usable links: exclusions and ineligible ids removed, both-ways ids set aside.
interface Links {
  support: Set<string>;
  contra: Set<string>;
  both: string[];
  notCounted: { eventId: string; reason: NotCountedReason }[];
}

function linksOf(h: Hypothesis, elig: AssessmentEligibility): Links {
  const excluded = activeExclusionIds(h);
  const notCounted: Links["notCounted"] = [];
  const seenNotCounted = new Set<string>();
  const usable = (id: string): boolean => {
    if (excluded.has(id)) return false;
    let reason: NotCountedReason | null = null;
    if (elig.eligibleEventIds && !elig.eligibleEventIds.has(id)) reason = "not in the timeline";
    else if (elig.falsePositiveEventIds?.has(id.trim().toLowerCase())) reason = "marked false positive";
    if (!reason) return true;
    if (!seenNotCounted.has(id)) {
      seenNotCounted.add(id);
      notCounted.push({ eventId: id, reason });
    }
    return false;
  };
  const support = new Set(h.relatedEventIds.filter(usable));
  const contra = new Set(h.contradictingEventIds.filter(usable));
  const both = [...support].filter((id) => contra.has(id));
  for (const id of both) {
    support.delete(id);
    contra.delete(id);
  }
  return { support, contra, both, notCounted };
}

function competingSet(
  h: Hypothesis,
  all: readonly Hypothesis[],
): { alternatives: Hypothesis[]; source: "analyst" | "live" } {
  const named = (h.alternativeIds ?? []).filter((id) => id !== h.id);
  if (named.length) {
    const byId = new Map(all.map((o) => [o.id, o] as const));
    return {
      alternatives: named.map((id) => byId.get(id)).filter((o): o is Hypothesis => !!o),
      source: "analyst",
    };
  }
  return { alternatives: all.filter((o) => o.id !== h.id && !isDead(o)), source: "live" };
}

const plural = (n: number, word: string): string => `${n} ${word}${n === 1 ? "" : "s"}`;
const quote = (t: string): string => `'${t}'`;

function readingOf(a: Omit<HypothesisAssessment, "reading">): string {
  const parts: string[] = [];
  const s = a.support;
  const nSupport =
    s.distinguishing.length + s.consistentWithAlternatives.length + s.notAssessedElsewhere.length;
  if (!a.alternatives.length) {
    parts.push("No alternative was offered, so no observation can separate this from one.");
  }
  if (nSupport) {
    const bits = [
      `${s.distinguishing.length} ${s.distinguishing.length === 1 ? "separates" : "separate"} this from an alternative` +
        (s.distinguishing.length
          ? ` (${[...new Set(s.distinguishing.flatMap((d) => d.separatesFrom.map((x) => quote(x.title))))].join(", ")})`
          : ""),
      `${s.consistentWithAlternatives.length} consistent with the alternatives that assessed them`,
      `${s.notAssessedElsewhere.length} not assessed against the alternatives`,
    ];
    parts.push(`${plural(nSupport, "supporting observation")}: ${bits.join(", ")}.`);
  } else {
    parts.push("No supporting observation counted.");
  }
  const c = a.contradiction;
  const nContra = c.distinguishing.length + c.againstEveryAssessed.length + c.notAssessedElsewhere.length;
  if (nContra) {
    const bits: string[] = [];
    if (c.distinguishing.length)
      bits.push(
        `${c.distinguishing.length} ${c.distinguishing.length === 1 ? "supports" : "support"} an alternative (${[...new Set(c.distinguishing.flatMap((d) => d.supports.map((x) => quote(x.title))))].join(", ")})`,
      );
    for (const r of c.againstEveryAssessed)
      bits.push(
        `${r.eventId} contradicts every one of the ${r.assessedBy} explanations that assessed it; ${r.notAssessedBy} did not assess it`,
      );
    if (c.notAssessedElsewhere.length)
      bits.push(`${c.notAssessedElsewhere.length} not assessed against the alternatives`);
    parts.push(`${plural(nContra, "contradiction")}: ${bits.join("; ")}.`);
  }
  if (a.assessedBothWays.length)
    parts.push(
      `${plural(a.assessedBothWays.length, "observation")} assessed both ways, counted for nothing: ${a.assessedBothWays.join(", ")}.`,
    );
  if (a.excluded.length) parts.push(`${plural(a.excluded.length, "observation")} excluded by the analyst.`);
  if (a.notCounted.length)
    parts.push(
      `${plural(a.notCounted.length, "observation")} not counted: ${a.notCounted.map((n) => `${n.eventId} (${n.reason})`).join(", ")}.`,
    );
  return parts.join(" ");
}

// Assess every hypothesis of a case against its competing set. Map keyed by hypothesis id.
export function assessHypothesisEvidence(
  hypotheses: readonly Hypothesis[],
  elig: AssessmentEligibility = {},
): Map<string, HypothesisAssessment> {
  const links = new Map(hypotheses.map((h) => [h.id, linksOf(h, elig)] as const));
  const out = new Map<string, HypothesisAssessment>();
  for (const h of hypotheses) {
    const mine = links.get(h.id)!;
    const { alternatives, source } = competingSet(h, hypotheses);
    const alt = alternatives.map((o) => ({ h: o, l: links.get(o.id)! }));
    const support: HypothesisAssessment["support"] = {
      distinguishing: [],
      consistentWithAlternatives: [],
      notAssessedElsewhere: [],
    };
    for (const id of mine.support) {
      const contraBy = alt.filter((x) => x.l.contra.has(id));
      if (contraBy.length)
        support.distinguishing.push({ eventId: id, separatesFrom: contraBy.map((x) => ref(x.h)) });
      else {
        const assessedBy = alt.filter((x) => x.l.support.has(id)).length;
        if (assessedBy)
          support.consistentWithAlternatives.push({
            eventId: id,
            assessedBy: assessedBy + 1,
            notAssessedBy: alt.length - assessedBy,
          });
        else support.notAssessedElsewhere.push(id);
      }
    }
    const contradiction: HypothesisAssessment["contradiction"] = {
      distinguishing: [],
      againstEveryAssessed: [],
      notAssessedElsewhere: [],
    };
    for (const id of mine.contra) {
      const supportedBy = alt.filter((x) => x.l.support.has(id));
      if (supportedBy.length)
        contradiction.distinguishing.push({ eventId: id, supports: supportedBy.map((x) => ref(x.h)) });
      else {
        const assessedBy = alt.filter((x) => x.l.contra.has(id)).length;
        if (assessedBy)
          contradiction.againstEveryAssessed.push({
            eventId: id,
            assessedBy: assessedBy + 1,
            notAssessedBy: alt.length - assessedBy,
          });
        else contradiction.notAssessedElsewhere.push(id);
      }
    }
    const excluded = (h.excludedEvidence ?? [])
      .filter((x) => !x.restoredAt)
      .map((x) => ({ eventId: x.eventId, reason: x.reason, by: x.by, excludedAt: x.excludedAt }));
    const partial: Omit<HypothesisAssessment, "reading"> = {
      hypothesisId: h.id,
      alternatives: alternatives.map(ref),
      alternativesSource: source,
      support,
      contradiction,
      assessedBothWays: mine.both,
      excluded,
      notCounted: mine.notCounted,
      activeContradictions: mine.contra.size,
      restsOnSingleObservation: h.status === "supported" && support.distinguishing.length === 1,
    };
    out.set(h.id, { ...partial, reading: readingOf(partial) });
  }
  return out;
}

// The words that sit on the status line — never only inside a collapsed block. Empty when nothing
// qualifies the analyst's status word.
export function hypothesisQualifier(h: Hypothesis, a: HypothesisAssessment): string {
  const bits: string[] = [];
  if (h.status === "supported") {
    if (!a.alternatives.length) bits.push("no alternative offered");
    else if (!a.support.distinguishing.length) bits.push("no observation separates it from an alternative");
  }
  if (h.needsReview) bits.push(`review required${h.reviewReason ? `: ${h.reviewReason}` : ""}`);
  return bits.join(" — ");
}

// ACH ranking (investigation-guidance #14, diagnosticity added by #933 item 22). Ordinal keys only:
// dead last; fewer active contradictions (the #14 invariant); more DISTINGUISHING support; more
// support not assessed against the alternatives; title. Support that is consistent with the
// alternatives is not a key — it cannot choose between them. Pure; returns a sorted COPY.
export function rankHypothesesAch(
  hypotheses: readonly Hypothesis[],
  assessments: ReadonlyMap<string, HypothesisAssessment> = assessHypothesisEvidence(hypotheses),
): Hypothesis[] {
  const dead = (h: Hypothesis): number => (isDead(h) ? 1 : 0);
  const a = (h: Hypothesis): HypothesisAssessment | undefined => assessments.get(h.id);
  return hypotheses
    .slice()
    .sort(
      (x, y) =>
        dead(x) - dead(y) ||
        (a(x)?.activeContradictions ?? 0) - (a(y)?.activeContradictions ?? 0) ||
        (a(y)?.support.distinguishing.length ?? 0) - (a(x)?.support.distinguishing.length ?? 0) ||
        (a(y)?.support.notAssessedElsewhere.length ?? 0) - (a(x)?.support.notAssessedElsewhere.length ?? 0) ||
        x.title.localeCompare(y.title),
    );
}

// The uncertainties an observation's OWN record carries — read from the event, never invented.
// A conclusion that rests on one observation names these; nothing else is said about it.
export function eventUncertainty(e: ForensicEvent): string[] {
  const out: string[] = [];
  if (e.yearInferred) out.push("year inferred, not read from the record");
  if (e.yearClampedFrom) out.push(`year re-anchored from ${e.yearClampedFrom}`);
  if (e.skewOffsetMs) out.push("time adjusted for clock skew");
  if (!(e.sources ?? []).length && !e.artifactName) out.push("no named source artifact");
  const clock = e.canonical?.time?.clockConfidence;
  if (clock && clock !== "recorded") out.push(`clock: ${clock}`);
  for (const [path, p] of Object.entries(e.canonical?.fieldProvenance ?? {})) {
    if (p?.confidence === "low") out.push(`${path} read with low confidence`);
  }
  return out;
}

export interface EvidenceRow {
  eventId: string;
  present: boolean;
  timestamp: string;
  description: string;
  uncertainty: string[];
}

const MISSING_NOTE = "observation no longer in the timeline";

// Resolve every id an assessment names to the event's time, description and uncertainty, for the
// report and the card. An id with no event is marked absent rather than dropped.
export function describeHypothesisEvidence(
  a: HypothesisAssessment,
  events: readonly ForensicEvent[],
): Map<string, EvidenceRow> {
  const ids = [
    ...a.support.distinguishing.map((d) => d.eventId),
    ...a.support.consistentWithAlternatives.map((d) => d.eventId),
    ...a.support.notAssessedElsewhere,
    ...a.contradiction.distinguishing.map((d) => d.eventId),
    ...a.contradiction.againstEveryAssessed.map((d) => d.eventId),
    ...a.contradiction.notAssessedElsewhere,
    ...a.assessedBothWays,
    ...a.excluded.map((x) => x.eventId),
    ...a.notCounted.map((x) => x.eventId),
  ];
  const byId = new Map(events.map((e) => [e.id, e] as const));
  const out = new Map<string, EvidenceRow>();
  for (const id of ids) {
    if (out.has(id)) continue;
    const e = byId.get(id);
    out.set(
      id,
      e
        ? {
            eventId: id,
            present: true,
            timestamp: e.timestamp,
            description: e.description,
            uncertainty: eventUncertainty(e),
          }
        : { eventId: id, present: false, timestamp: "", description: "", uncertainty: [MISSING_NOTE] },
    );
  }
  return out;
}
