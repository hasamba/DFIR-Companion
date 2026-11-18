import type { Finding } from "../analysis/stateTypes.js";
import { cellMd, oneLineMd } from "./mdText.js";

/**
 * The line a Watson-written finding carries in the report: who approved it. `approvedBy` is the
 * analyst's name as typed in the dashboard, so it goes through oneLineMd like any other free text.
 * An older finding applied before the name was recorded still says an analyst approved it.
 */
export function watsonApprovalLine(f: Finding): string {
  const who = f.approvedBy ? oneLineMd(f.approvedBy) : "an analyst";
  return `- Added by Watson, approved by ${who}`;
}

/**
 * #2682: the line a synthesis finding carries when Watson demoted or dismissed it, with who
 * approved it, the reason and the cited events. Every model and analyst string is escaped. A
 * verdict a later run reopened (new evidence) says so, and that it no longer applies.
 */
export function watsonReviewLine(f: Finding): string | null {
  const text = watsonReviewText(f, oneLineMd, cellMd);
  return text === null ? null : `- ${text}`;
}

const plain = (s: string): string => s.replace(/\s+/g, " ").trim();

/**
 * The review sentence. `prose` and `id` escape the free text and the event ids for the target
 * format; the default is plain text for a DOM text node (interactive HTML report).
 */
export function watsonReviewText(
  f: Finding,
  prose: (s: string) => string = plain,
  id: (s: string) => string = plain,
): string | null {
  const r = f.watsonReview;
  if (!r) return null;
  // Auto is not a person: it never reads as an analyst's approval (the dashboard says the same).
  const who =
    r.approvedBy === WATSON_AUTO_NAME
      ? "applied by Watson in Auto mode, without asking"
      : `approved by ${prose(r.approvedBy || "an analyst")}`;
  const what =
    r.action === "dismiss"
      ? `Dismissed by Watson (was ${r.fromStatus})`
      : `Demoted by Watson from ${r.fromSeverity} to ${r.severity ?? r.fromSeverity}`;
  const cited = r.eventIds.map(id).join(", ");
  const base = `${what}, ${who}: ${prose(r.reason)} (cited events: ${cited || "none"})`;
  if (r.newEventIds?.length)
    return `Not applied: this synthesis cites new evidence (${r.newEventIds.map(id).join(", ")}). Earlier: ${base}`;
  if (r.autoHeld)
    return `Not applied: Auto mode never changes a High or Critical finding. Earlier, at a lower severity: ${base}`;
  return base;
}

/** The Auto actor's name as stored (ai/watson/writers/writerTypes.ts WATSON_AUTO_ACTOR). */
const WATSON_AUTO_NAME = "Watson (Auto)";

/** Every Watson line a finding carries in the report. */
export function watsonFindingLines(f: Finding): string[] {
  const review = watsonReviewLine(f);
  return [...(f.author === "watson" ? [watsonApprovalLine(f)] : []), ...(review ? [review] : [])];
}
