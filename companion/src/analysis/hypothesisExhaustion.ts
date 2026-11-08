import type { Hypothesis } from "./hypothesis.js";

// When `exhausted` stops being true (#2415). A hypothesis is flagged exhausted once enough hunts for
// its expected outcome came back empty (markExhaustedHypotheses). The flag only makes sense on an
// OPEN hypothesis, and only for the outcome those hunts actually tested. So:
//
//  - any STATUS change clears it (a supported/refuted/unknown hypothesis is not "exhausted"), and
//  - a material change to WHAT it tests (expected outcome, techniques) clears it,
//
// and each of those moves the hypothesis's `exhaustionResetAt` to now. From then on only hunts
// DEPLOYED after that point count as misses against it — so a hypothesis an analyst re-aims or
// re-opens is re-judged on new hunts, instead of bouncing straight back to exhausted on the old ones.
// The deployment time is used, not the collection time: re-collecting an old empty hunt rewrites its
// collection time but does not make it a new test.

/** The exhaustion fields to merge into a hypothesis whose exhaustion is being reset at `now`. */
export function resetExhaustion(
  now: string,
): Pick<Hypothesis, "exhausted" | "exhaustedReason" | "exhaustionResetAt"> {
  return { exhausted: false, exhaustedReason: "", exhaustionResetAt: now };
}

const normalizeText = (s: string | undefined): string =>
  String(s ?? "")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase();

const techniqueKey = (list: readonly string[] | undefined): string =>
  [...new Set((list ?? []).map((t) => String(t).trim().toUpperCase()).filter(Boolean))].sort().join(",");

/** Did what this hypothesis tests change materially? Wording/case/whitespace in the expected outcome
 *  and the ORDER of techniques are not changes. */
export function testCriteriaChanged(
  before: Pick<Hypothesis, "expectedOutcome" | "relatedTechniques">,
  after: Pick<Hypothesis, "expectedOutcome" | "relatedTechniques">,
): boolean {
  return (
    normalizeText(before.expectedOutcome) !== normalizeText(after.expectedOutcome) ||
    techniqueKey(before.relatedTechniques) !== techniqueKey(after.relatedTechniques)
  );
}

/** Should exhaustion be reset when `before` becomes `after`? `byAnalyst` is false for a synthesis
 *  refresh: synthesis re-words a pristine hypothesis's expected outcome on every run, so comparing
 *  that prose would reset exhaustion each time and old misses would never count. A refresh resets on
 *  a status change or a changed technique set; an analyst edit also resets on a changed outcome. */
export function shouldResetExhaustion(before: Hypothesis, after: Hypothesis, byAnalyst = true): boolean {
  if (before.status !== after.status) return true;
  if (byAnalyst) return testCriteriaChanged(before, after);
  return techniqueKey(before.relatedTechniques) !== techniqueKey(after.relatedTechniques);
}

/** Does a hunt signal count toward exhausting this hypothesis? Once a reset point exists, only hunts
 *  deployed strictly after it count; a signal with no (or an unreadable) time is not counted then,
 *  since it cannot be shown to be a new test. With no reset point, every signal counts, as before. */
export function signalCountsAfterReset(
  h: Pick<Hypothesis, "exhaustionResetAt">,
  at: string | undefined,
): boolean {
  if (!h.exhaustionResetAt) return true;
  const reset = Date.parse(h.exhaustionResetAt);
  if (!Number.isFinite(reset)) return true; // an unreadable reset point must not hide every miss forever
  const when = Date.parse(at ?? "");
  return Number.isFinite(when) && when > reset;
}

/** Load-time view of a stored record: a non-open hypothesis is never exhausted. Records written
 *  before #2415 can hold supported+exhausted or refuted+exhausted; every consumer (negative
 *  knowledge, diagnostics, the report) reads through the store, so this is the one place to fix it.
 *  In memory only — the next write persists it. */
export function normalizeExhaustion(h: Hypothesis): Hypothesis {
  if (h.status === "open" || (!h.exhausted && !h.exhaustedReason)) return h;
  return { ...h, exhausted: false, exhaustedReason: "" };
}
