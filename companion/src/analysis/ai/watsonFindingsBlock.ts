import { applyFalsePositive, type FalsePositiveMarker } from "../falsePositive.js";
import type { Finding, InvestigationState } from "../stateTypes.js";
import { isWatsonItem } from "../timeline/watsonItems.js";
import { aiSpan } from "./aiSpan.js";

/**
 * The findings the analyst applied from Watson, for the synthesis prompt. Synthesis keeps them
 * itself (timeline/watsonItems.ts), so the model is told not to re-issue them and not to write a
 * duplicate under a new id. Bounded like the CURRENT KEY QUESTIONS block: a capped count, one
 * clipped line each, the cut disclosed. Empty when the case has none, so the prompt is unchanged.
 */

export const WATSON_FINDINGS_MAX = 40;
const TITLE_CHARS = 200;
const DESCRIPTION_CHARS = 300;
const CITED_EVENTS_MAX = 10;

// One line: adversary-influenced text (a description can quote an event) cannot add prompt lines.
const oneLine = (s: string, max: number): string => {
  const flat = s.replace(/\s+/g, " ").trim();
  return flat.length > max ? `${flat.slice(0, max)}…` : flat;
};

function line(f: Finding): string {
  const desc = oneLine(f.description, DESCRIPTION_CHARS);
  const cited = (f.relatedEventIds ?? []).slice(0, CITED_EVENTS_MAX).map((id) => oneLine(id, 80));
  const events = cited.length ? ` [cites: ${cited.join(", ")}]` : "";
  // Marked as model-like text (aiSpan, #1799) so Presidio still scans it: it is never a recorded answer.
  const body = desc ? ` — ${aiSpan(desc, desc.endsWith("…"))}` : "";
  return `[${oneLine(f.id, 80)}] (${f.severity}) ${aiSpan(oneLine(f.title, TITLE_CHARS))}${body}${events}`;
}

/** A Watson finding the analyst marked false positive is not listed: it is not a live finding. */
export function buildWatsonFindingsBlock(
  state: InvestigationState,
  markers: FalsePositiveMarker[] = [],
): string {
  const all = applyFalsePositive(
    { ...state, findings: state.findings.filter(isWatsonItem) },
    markers,
  ).findings;
  if (!all.length) return "";
  const shown = all.slice(0, WATSON_FINDINGS_MAX);
  const cut = all.length - shown.length;
  return (
    `WATSON FINDINGS (analyst-approved; do not re-issue, do not duplicate): the case keeps these as ` +
    `they are. Do not return a finding with one of these ids, and do not restate one under a new id; ` +
    `cite them by id where they bear on another finding, a key question or a next step:\n` +
    shown.map(line).join("\n") +
    (cut > 0 ? `\n(${cut} more Watson findings not shown)` : "") +
    "\n\n"
  );
}
