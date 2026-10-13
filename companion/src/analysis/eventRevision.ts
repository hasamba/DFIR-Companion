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

import { splitDerivedNotes } from "./derivedNote.js";
import type { ForensicEvent, Severity } from "./stateTypes.js";
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
function preCapSeverity(e: ForensicEvent): Severity {
  const lab = (e as ForensicEvent & LabSetupCap).labSetup;
  return e.buildTime?.cappedFrom ?? (lab?.tag === "lab-setup" ? lab.cappedFrom : undefined) ?? e.severity;
}

// A correlation pass appends a registered "[name: …]" note and may re-grade the row AFTER the merge.
// A re-import restates the raw text and grade, and the pass re-applies; that is not a change.
function restatesAnnotatedRow(existing: ForensicEvent, incoming: Incoming): boolean {
  const held = splitDerivedNotes(existing.description);
  const next = splitDerivedNotes(incoming.description);
  if (!held.notes || next.notes) return false;
  const heldBase = held.base.trim();
  const nextBase = next.base.trim();
  // The pass clips the base before appending its note, so a long raw text extends the held base.
  return heldBase.length > 0 && nextBase.startsWith(heldBase);
}

function capped(list: EventRevision[], dropped: number): EventRevisionFields {
  if (list.length <= MAX_EVENT_REVISIONS)
    return { revisions: list, ...(dropped ? { revisionsDropped: dropped } : {}) };
  const keep = [list[0], ...list.slice(list.length - (MAX_EVENT_REVISIONS - 1))];
  return { revisions: keep, revisionsDropped: dropped + list.length - MAX_EVENT_REVISIONS };
}

/**
 * The row's revision record after `incoming` overwrites `existing`, or undefined when the merge
 * changes neither the description nor the severity. Returns a NEW list; `existing.revisions` is
 * never touched (copyTimeline does not deep-copy it).
 */
export function nextRevisions(
  existing: ForensicEvent,
  incoming: Incoming,
  at: string,
  source: string,
): EventRevisionFields | undefined {
  if (restatesAnnotatedRow(existing, incoming)) return undefined;
  const baseline = preCapSeverity(existing);
  const descChanged = incoming.description !== existing.description;
  const sevChanged = incoming.severity !== baseline;
  if (!descChanged && !sevChanged) return undefined;
  const entry: EventRevision = {
    at,
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
