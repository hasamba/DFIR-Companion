import { SEVERITY_RANK, type ForensicEvent } from "../stateTypes.js";
import { byEventTime } from "../forensicSort.js";

/**
 * Promoted evidence in the synthesis prompt (#1586).
 *
 * A promoted row is one pulled back from the archive into the forensic timeline after import — by
 * the missed-evidence review, the second look, or the analyst (`promotedAt` is set). The missed-
 * evidence review promoted the AES encryptor loop of a ransomware lab case, and the next synthesis
 * still said "no encryption was observed": nothing in the prompt said the row was new, and the
 * model's existing findings — written without it — were echoed as settled.
 *
 * "New" is a SEEN-SET, not a time watermark. A row is new until a synthesis that actually showed it
 * to the model has been persisted. `lastSynthesizedAt` could not do this: it is stamped when a run
 * FINISHES, so a row promoted while the model was thinking would be older than the stamp and never
 * count as new, although that run never saw it.
 *
 * Prompt-only and derived on read, like the rest of the prompt builders: nothing here writes the case.
 */

/** The most new promoted rows that get a guaranteed seat. One review press promotes ~40. */
export const NEW_PROMOTED_PROMPT_CAP = 60;
/** The seen-set is persisted in synth-meta; bounded so a case with years of promotions stays small. */
export const PROMOTED_SEEN_MAX = 5000;

export function isPromoted(e: ForensicEvent): boolean {
  return typeof e.promotedAt === "string" && e.promotedAt.length > 0;
}

/**
 * Who promoted the row, from its provenance marker. An explain / starred-report copy carries no
 * marker: that promotion is incidental, not a verdict that the row is incident evidence, so it gets
 * no source rather than being credited to the analyst.
 */
export function promotionSource(e: ForensicEvent): string | undefined {
  const marks = e.provenance ?? [];
  if (marks.some((m) => m.startsWith("[missed-evidence"))) return "missed-evidence review";
  if (marks.some((m) => m.startsWith("[second-look"))) return "second look";
  if (marks.some((m) => m === "[promoted]")) return "analyst";
  return undefined;
}

/** The suffix a promoted row carries in the prompt. "" for a row that was never promoted. */
export function promotedTag(e: ForensicEvent, isNew: boolean): string {
  if (!isPromoted(e)) return "";
  const source = promotionSource(e);
  const body = source ? `promoted: ${source}` : "promoted";
  return ` ⟨${body}${isNew ? " · NEW since last synthesis" : ""}⟩`;
}

/**
 * A promotion's identity is `id:promotedAt`, not the id alone. Correlation keeps the representative's
 * id and the LATEST member stamp, so a later promotion that merges into a row the model already saw
 * arrives as the same id with a new stamp — and must count as new evidence again.
 */
export function promotionVersion(e: ForensicEvent): string {
  return `${e.id}:${e.promotedAt}`;
}

/** Promoted rows in scope whose promotion no persisted synthesis has shown the model yet. */
export function newPromotedIds(scoped: readonly ForensicEvent[], seen: readonly string[]): Set<string> {
  const seenSet = new Set(seen);
  return new Set(scoped.filter((e) => isPromoted(e) && !seenSet.has(promotionVersion(e))).map((e) => e.id));
}

/** Seats for new promoted rows count against the event cap, and never take more than half of it. */
export function pinCap(maxEvents: number): number {
  return Math.min(NEW_PROMOTED_PROMPT_CAP, Math.max(1, Math.floor(maxEvents / 2)));
}

/** Which new promoted rows win a seat when there are more than fit: severest, then first promoted. */
export function rankPins(events: readonly ForensicEvent[]): ForensicEvent[] {
  return [...events].sort(
    (a, b) =>
      SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] || // Critical is rank 0
      String(a.promotedAt).localeCompare(String(b.promotedAt)) ||
      byEventTime(a, b),
  );
}

/**
 * The seen-set to persist after a run: every promoted row the model was shown, plus earlier seen
 * rows that are still promoted in the case (a row the budget left out this time was still seen
 * before). A row that lost its seat stays new.
 */
export function nextPromotedSeen(
  previous: readonly string[],
  timeline: readonly ForensicEvent[],
  shownIds: ReadonlySet<string>,
): string[] {
  const current = timeline.filter(isPromoted).map(promotionVersion);
  const live = new Set(current);
  const shown = timeline.filter((e) => isPromoted(e) && shownIds.has(e.id)).map(promotionVersion);
  const kept = previous.filter((v) => live.has(v));
  return [...new Set([...shown, ...kept])].slice(0, PROMOTED_SEEN_MAX);
}

/** Stable input for the skip-if-unchanged hash: a newly stamped row must trigger a fresh run. */
export function promotedSignature(scoped: readonly ForensicEvent[]): string[] {
  return scoped.filter(isPromoted).map(promotionVersion).sort();
}

/** Legend for the ⟨promoted⟩ tag; the NEW clause only when this prompt carries new rows. */
export function promotedLegend(hasNew: boolean): string {
  return (
    " Rows tagged ⟨promoted⟩ were pulled back from the archive into the forensic timeline after import." +
    (hasNew
      ? ' "NEW" ones arrived after your last synthesis and are listed under NEWLY PROMOTED EVIDENCE.'
      : "")
  );
}

/**
 * The instruction block for the new promoted rows that are IN this prompt. Worded to fit the
 * synthesis output contract: timelineNote must stay "", so a benign row simply needs no finding.
 */
export function renderNewPromotedBlock(shown: readonly ForensicEvent[], leftOut: number): string {
  if (shown.length === 0) return "";
  const sources = [...new Set(shown.map((e) => promotionSource(e) ?? "an incidental promotion"))];
  const ids = shown.map((e) => `[${e.id}]`).join(", ");
  const more =
    leftOut > 0 ? ` (+${leftOut} more new promoted row(s) did not fit this prompt; they stay pending)` : "";
  return (
    `NEWLY PROMOTED EVIDENCE (${shown.length} row${shown.length === 1 ? "" : "s"} added to the forensic ` +
    `timeline since your last synthesis — by ${sources.join(", ")}): ${ids}${more}\n` +
    "Your existing findings were written WITHOUT these rows. For EACH row:\n" +
    "- If it contradicts a finding (e.g. the finding says an activity was not observed and the row shows it), " +
    "correct or reclassify that finding, and say in its description which row changed it.\n" +
    "- If it extends a finding (an earlier or later step of the same activity), extend that finding's description " +
    "and time span, and add the row id to its relatedEventIds.\n" +
    "- If no finding covers it, add one. If it is benign or unrelated to the intrusion, it needs no finding.\n" +
    "Also re-check the keyQuestions and the attacker path against these rows."
  );
}
