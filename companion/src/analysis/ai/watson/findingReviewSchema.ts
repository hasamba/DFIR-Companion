import { z } from "zod";
import { SEVERITY_RANK, type Finding, type Severity } from "../../stateTypes.js";
import type { WatsonReviewAction } from "../../watsonItemTypes.js";

// #2682: Watson proposes to demote or dismiss a finding synthesis wrote (AI or the deterministic
// rules), when the events it cites disprove it. Untrusted like the rest of the reply: parsed
// leniently, then sanitized. A target must be a synthesis finding the prompt showed (never one
// Watson wrote, never one already dismissed), a demotion must lower the severity, and at least one
// forensic-timeline event must be cited. Nothing here writes.

const MAX_REVIEWS = 3;
const MAX_CITED = 20;
const WHY_MAX = 500;
const LOWEST_DEMOTION: Severity = "Low";

export interface WatsonFindingReviewDraft {
  findingId: string;
  action: WatsonReviewAction;
  /** demote only: the lower severity. */
  severity?: Severity;
  why: string;
  eventIds: string[];
  /** The finding as Watson was shown it (set by the sanitizer): a finding changed since is not changed. */
  seen?: Finding;
}

export const findingReviewDraftSchema = z.object({
  findingId: z.string(),
  action: z.enum(["demote", "dismiss"]),
  severity: z.enum(["Critical", "High", "Medium", "Low", "Info"]).optional().catch(undefined),
  why: z.string().catch(""),
  eventIds: z
    .array(z.unknown())
    .catch([])
    .transform((ids) => ids.filter((x): x is string => typeof x === "string")),
});

/** True when `to` is a valid demotion of `from`: strictly lower, and not below Low. */
export function isDemotion(from: Severity, to: Severity | undefined): to is Severity {
  return (
    !!to && SEVERITY_RANK[to] > SEVERITY_RANK[from] && SEVERITY_RANK[to] <= SEVERITY_RANK[LOWEST_DEMOTION]
  );
}

/**
 * True when `now` cites an event that is not in `seenIds`, the citations Watson was shown: an import
 * or a delta added evidence Watson never read, so its verdict no longer covers the finding.
 */
export function gainedEvidence(now: Finding, seenIds: readonly string[]): boolean {
  const seen = new Set(seenIds);
  return (now.relatedEventIds ?? []).some((id) => !seen.has(id));
}

function sanitizeOne(
  r: WatsonFindingReviewDraft,
  knownEventIds: ReadonlySet<string>,
  finding: Finding | undefined,
): WatsonFindingReviewDraft | null {
  if (!finding || finding.status === "dismissed" || r.why.trim() === "") return null;
  if (r.action === "demote" && !isDemotion(finding.severity, r.severity)) return null;
  const eventIds = [...new Set(r.eventIds.filter((id) => knownEventIds.has(id)))].slice(0, MAX_CITED);
  if (!eventIds.length) return null;
  return {
    findingId: r.findingId,
    action: r.action,
    ...(r.action === "demote" ? { severity: r.severity } : {}),
    why: r.why.slice(0, WHY_MAX),
    eventIds,
    seen: finding,
  };
}

/** Caps and checks: one review per finding, only for a reviewable finding, with a live citation. */
export function sanitizeFindingReviews(
  drafts: readonly WatsonFindingReviewDraft[],
  knownEventIds: ReadonlySet<string>,
  reviewable: ReadonlyMap<string, Finding> | undefined,
): WatsonFindingReviewDraft[] {
  const seen = new Set<string>();
  return drafts
    .flatMap((r) => {
      if (seen.has(r.findingId)) return [];
      const out = sanitizeOne(r, knownEventIds, reviewable?.get(r.findingId));
      if (out) seen.add(r.findingId);
      return out ? [out] : [];
    })
    .slice(0, MAX_REVIEWS);
}
