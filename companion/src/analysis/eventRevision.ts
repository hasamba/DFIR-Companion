// "Changed after first recorded" (#2141).
//
// A merge that meets an id the case already holds OVERWRITES the row's description and severity
// (stateMerge.upsertForensicEvents). That is intended: a deterministic importer's parser fix and an
// MCP agent's update must land. But a finding written against the old row would then cite a row that
// no longer says what the finding says, with nothing on screen to tell the analyst. So the merge keeps
// a short record of each change, beside the overwrite and never instead of it.
//
// The record is capped: the OLDEST entry is pinned (its `from` is what the row said when it was first
// recorded) plus the newest four, and `revisionsDropped` counts the middle entries the cap dropped. A
// row that never changes carries nothing. When correlation folds one row into another, the survivor
// keeps only its own record, as it does for `importedAt` and `originalTimestamp`.
//
// Only forensic-timeline rows carry it, and no AI prompt renders it: the model never reads prior text.
//
// A row the content tagger raised (#2182) is the exception to the overwrite: a re-import restates the
// raw import grade, which the tagger had already raised, and the demote gate would then drop the row.
// So the merge keeps the higher of the restated grade and the tagger's grade. An MCP agent's explicit
// update (the merge names a change source) still lands, and is recorded like any other change.

import {
  DERIVED_NOTE_DOWNGRADES,
  DERIVED_NOTE_NAMES,
  DESCRIPTION_BASE_MAX,
  splitDerivedNotes,
} from "./derivedNote.js";
import { SEVERITY_RANK, type ForensicEvent, type Severity } from "./stateTypes.js";
import type { EventRevision, EventRevisionFields } from "./eventRevisionTypes.js";

export type { EventRevision, EventRevisionFields } from "./eventRevisionTypes.js";

export const MAX_EVENT_REVISIONS = 5;
/** The prior description is kept to this many characters (the cut ends in "…"). */
export const REVISION_DESC_MAX = 280;
export const REVISION_LABEL = "changed after first recorded";

type Incoming = Pick<ForensicEvent, "description" | "severity">;
// labSetupTransfer.ts owns this record; read structurally, because that module sits a tier above.
type LabSetupCap = { labSetup?: { tag?: string; cappedFrom?: Severity } };

/** Who made the change: the merge's named source, the import label, the row's sources, or a placeholder. */
export function revisionSource(
  ctx: { changeSource?: string; sourceScreenshots: readonly string[] },
  incoming: Pick<ForensicEvent, "sources">,
): string {
  return ctx.changeSource || ctx.sourceScreenshots[0] || incoming.sources?.join(", ") || "unknown source";
}

function clip(text: string): string {
  return text.length > REVISION_DESC_MAX ? `${text.slice(0, REVISION_DESC_MAX - 1)}…` : text;
}

/** The grade the row carried before a build-time or lab-setup cap; those caps re-run after the merge. */
export function preCapSeverity(e: ForensicEvent): Severity {
  const lab = (e as ForensicEvent & LabSetupCap).labSetup;
  return e.buildTime?.cappedFrom ?? (lab?.tag === "lab-setup" ? lab.cappedFrom : undefined) ?? e.severity;
}

/** The severity and tagger marker a merge writes onto `existing` when `incoming` restates it (#2182). */
export function mergedSeverity(
  existing: ForensicEvent,
  incoming: Pick<ForensicEvent, "severity">,
  ctx: { changeSource?: string },
): { severity: Severity; taggerRaisedFrom?: Severity } {
  if (!existing.taggerRaisedFrom || ctx.changeSource) return { severity: incoming.severity };
  const held = preCapSeverity(existing);
  // SEVERITY_RANK: 0 = Critical. A grade at or above the tagger's one is the importer's own call.
  if (SEVERITY_RANK[incoming.severity] <= SEVERITY_RANK[held]) return { severity: incoming.severity };
  return { severity: held, taggerRaisedFrom: incoming.severity };
}

// A correlation pass appends a registered "[name: …]" note and may re-grade the row AFTER the merge.
// A re-import restates the raw text and grade, and the pass re-applies; that alone is not a change.
// Only an exact restatement qualifies: an incoming text that ADDS to the stored base is new content.
// The one exception is a base the pass clipped at its own cap (appendDerivedNote slices the base to
// `baseMax` and trims the end): the stored copy then cannot show the rest, so the full raw text is
// recognised by clipping it the same way. These are the caps the chain's passes clip at (the default
// DESCRIPTION_BASE_MAX, and jndiInjection / containerEscape at 1600).
const PASS_BASE_CLIPS: readonly number[] = [DESCRIPTION_BASE_MAX, 1600];

function restatesRawText(heldBase: string, nextBase: string): boolean {
  if (!heldBase) return false;
  if (nextBase === heldBase) return true;
  return PASS_BASE_CLIPS.some((c) => nextBase.length > c && nextBase.slice(0, c).trimEnd() === heldBase);
}

type Restatement = { sameText: boolean; raises: boolean; lowers: boolean };

/** How `incoming` relates to an annotated `existing`; undefined when the comparison is plain. */
function annotatedRestatement(existing: ForensicEvent, incoming: Incoming): Restatement | undefined {
  const held = splitDerivedNotes(existing.description);
  const next = splitDerivedNotes(incoming.description);
  if (!held.notes || next.notes) return undefined;
  const named = DERIVED_NOTE_NAMES.filter((n) => held.notes.includes(`[${n}:`));
  const lowers = named.some((n) => DERIVED_NOTE_DOWNGRADES.includes(n));
  const raises = named.some((n) => !DERIVED_NOTE_DOWNGRADES.includes(n));
  return { sameText: restatesRawText(held.base.trim(), next.base.trim()), raises, lowers };
}

// Severity is judged on its own. The grade before the passes ran is not stored, so the baseline is
// the stored grade (before a build-time or lab-setup cap), and a difference is set aside only in the
// direction a note on the row explains: a raw grade BELOW the stored one under a raising note, or
// ABOVE it under a lowering note. The pass re-applies after the merge. Any other move is recorded.
function severityMoved(baseline: Severity, to: Severity, why: Restatement | undefined): boolean {
  if (to === baseline) return false;
  if (!why) return true;
  const lower = SEVERITY_RANK[to] > SEVERITY_RANK[baseline]; // SEVERITY_RANK: 0 = Critical
  return lower ? !why.raises : !why.lowers;
}

function capped(list: EventRevision[], dropped: number): EventRevisionFields {
  if (list.length <= MAX_EVENT_REVISIONS)
    return { revisions: list, ...(dropped ? { revisionsDropped: dropped } : {}) };
  const keep = [list[0], ...list.slice(list.length - (MAX_EVENT_REVISIONS - 1))];
  return { revisions: keep, revisionsDropped: dropped + list.length - MAX_EVENT_REVISIONS };
}

/**
 * The row's revision record after `incoming` overwrites `existing`, or undefined when the merge
 * changes neither the description nor the severity. An MCP agent's update (`changeSource`) is an
 * explicit edit and is never set aside as a restatement. Returns a NEW list; `existing.revisions` is
 * never touched (copyTimeline does not deep-copy it).
 */
export function nextRevisions(
  existing: ForensicEvent,
  incoming: Incoming,
  ctx: { timestamp: string; changeSource?: string },
  source: string,
): EventRevisionFields | undefined {
  const why = ctx.changeSource ? undefined : annotatedRestatement(existing, incoming);
  const baseline = preCapSeverity(existing);
  const descChanged = incoming.description !== existing.description && !why?.sameText;
  const sevChanged = severityMoved(baseline, incoming.severity, why);
  if (!descChanged && !sevChanged) return undefined;
  const entry: EventRevision = {
    at: ctx.timestamp,
    source,
    ...(descChanged ? { description: { from: clip(existing.description ?? "") } } : {}),
    ...(sevChanged ? { severity: { from: baseline, to: incoming.severity } } : {}),
  };
  return capped([...(existing.revisions ?? []), entry], existing.revisionsDropped ?? 0);
}

/** The Event-cell suffix for a revised row: " [<summary>]", or "". */
export function revisionSuffix(e: Pick<ForensicEvent, "revisions" | "revisionsDropped">): string {
  const s = revisionSummary(e);
  return s ? ` [${s}]` : "";
}

/** One line for reports and exports, or "" for a row that was never revised. */
export function revisionSummary(e: Pick<ForensicEvent, "revisions" | "revisionsDropped">): string {
  const list = e.revisions ?? [];
  if (!list.length) return "";
  const total = list.length + (e.revisionsDropped ?? 0);
  const latest = list[list.length - 1];
  const parts = [
    `${REVISION_LABEL}: ${total} change${total === 1 ? "" : "s"}, latest ${latest.at} by ${latest.source}`,
  ];
  // The first-recorded value is known when nothing was dropped, or the pinned first entry holds it.
  const exact = !e.revisionsDropped;
  const firstDesc = exact ? list.find((r) => r.description) : list[0].description ? list[0] : undefined;
  const firstSev = exact ? list.find((r) => r.severity) : list[0].severity ? list[0] : undefined;
  if (firstDesc?.description) parts.push(`first recorded as "${firstDesc.description.from}"`);
  if (firstSev?.severity) parts.push(`first severity ${firstSev.severity.from}`);
  return parts.join("; ");
}
