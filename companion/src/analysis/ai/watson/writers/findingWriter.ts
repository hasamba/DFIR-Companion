import type { ForensicRow } from "../../../forensicRows.js";
import type { Finding, ForensicEvent, InvestigationState } from "../../../stateTypes.js";
import { isWatsonEvent, isWatsonItem } from "../../../timeline/watsonItems.js";
import { WatsonProposalConflict } from "../proposalErrors.js";
import type { WatsonFindingProposal } from "../types.js";
import { liveCitations, relink, sameFinding } from "./findingCitations.js";
import type { WatsonWriter, WriterDeps } from "./writerTypes.js";

// A finding Watson drafted, applied by the analyst. It is written with loadOverview/saveOverview and
// the row APIs, never through mergeDelta (assembleMerge keeps Watson items from the base state only).
// Every check runs before the first write, so a conflict leaves the case exactly as it was. Undo
// removes only what the apply created, and only while it is still exactly what Watson wrote; a
// created row another finding now cites stays in the timeline (recorded as `keptEventIds`).

const OUT_OF_DATE = "Watson wrote a finding";

const unchanged = (id: string): WatsonProposalConflict =>
  new WatsonProposalConflict(`Finding ${id} changed since this proposal; nothing was written`);
const gone = (id: string): WatsonProposalConflict =>
  new WatsonProposalConflict(
    `Finding ${id} or the rows it added are no longer in the case; nothing was changed`,
  );

function checkApplyTarget(p: WatsonFindingProposal, stored: Finding | undefined): void {
  if (p.kind === "finding_new") {
    // Defence in depth: a new Watson finding wears the reserved prefix and is the finding it names.
    if (!p.targetId.startsWith("f-watson-") || p.after.id !== p.targetId) {
      throw new WatsonProposalConflict(
        `Finding ${p.targetId} is not a Watson finding id; nothing was written`,
      );
    }
    if (stored) throw unchanged(p.targetId);
    return;
  }
  if (!stored || !p.before || !isWatsonItem(stored) || !sameFinding(stored, p.before))
    throw unchanged(p.targetId);
}

function written(
  p: WatsonFindingProposal,
  eventIds: string[],
  pasteLines: Finding["citedPasteLines"],
  actor?: string,
): Finding {
  const { citedPasteLines: _c, ...draft } = p.after;
  return {
    ...draft,
    id: p.targetId,
    author: "watson",
    ...(actor ? { approvedBy: actor } : {}),
    status: p.kind === "finding_new" ? "open" : p.after.status,
    relatedEventIds: [...new Set(eventIds)],
    ...(pasteLines?.length ? { citedPasteLines: pasteLines } : {}),
  };
}

const withFinding = (state: InvestigationState, f: Finding): InvestigationState => ({
  ...state,
  findings: state.findings.some((x) => x.id === f.id)
    ? state.findings.map((x) => (x.id === f.id ? f : x))
    : [...state.findings, f],
});

async function apply(deps: WriterDeps, caseId: string, p: WatsonFindingProposal, actor?: string) {
  const overview = await deps.stateStore.loadOverview(caseId);
  checkApplyTarget(
    p,
    overview.findings.find((f) => f.id === p.targetId),
  );
  const promotedAt = new Date().toISOString();
  const live = await liveCitations(deps, caseId, p, promotedAt);
  if (!live.eventIds.length && !live.pasteEvents.length) {
    throw new WatsonProposalConflict("the cited evidence is gone");
  }
  const existing = await deps.stateStore.hasForensicEventIds(
    caseId,
    live.pasteEvents.map((e) => e.id),
  );
  const recovered = await leftByFailedApply(deps, caseId, p, existing);
  // One stamp for every row this apply owns, so undo recognises the recovered rows too.
  const stamp = recovered[0]?.promotedAt ?? promotedAt;
  const pasteEvents = live.pasteEvents.map((e) => ({ ...e, promotedAt: stamp }));
  const created = pasteEvents.filter((e) => !existing.has(e.id));
  const createdIds = new Set([...created, ...recovered].map((e) => e.id));
  const finding = written(
    p,
    [...live.eventIds, ...live.pasteEvents.map((e) => e.id)],
    live.pasteLines,
    actor,
  );
  const now = new Set(finding.relatedEventIds);
  // Writes: the new rows, the links on rows that already existed, then the finding.
  await deps.stateStore.appendForensicEvents(caseId, created);
  await relink(
    deps,
    caseId,
    finding.id,
    (finding.relatedEventIds ?? []).filter((id) => !createdIds.has(id)),
    (p.before?.relatedEventIds ?? []).filter((id) => !now.has(id)),
  );
  const state = withFinding(overview, finding);
  await deps.stateStore.saveOverview(state);
  await deps.markConclusionsOutOfDate(caseId, OUT_OF_DATE);
  const proposal: WatsonFindingProposal = {
    ...p,
    after: finding,
    pasteLineEvents: pasteEvents,
    createdEventIds: [...createdIds],
    promotedAt: stamp,
  };
  return { state, proposal };
}

/**
 * Rows an earlier attempt of this apply appended before it failed: marked `[watson]`, linked to this
 * finding only, and not cited by the finding it updates. A retry counts them as created, so undo
 * still removes them. One stamp only: rows of two different attempts are left alone.
 */
async function leftByFailedApply(
  deps: WriterDeps,
  caseId: string,
  p: WatsonFindingProposal,
  existing: ReadonlySet<string>,
): Promise<ForensicEvent[]> {
  const before = new Set(p.before?.relatedEventIds ?? []);
  const ids = p.pasteLineEvents.map((e) => e.id).filter((id) => existing.has(id) && !before.has(id));
  if (!ids.length) return [];
  const ours = (await deps.stateStore.forensicRowsById(caseId, ids))
    .map((r) => r.event)
    .filter(
      (e) =>
        isWatsonEvent(e) &&
        e.relatedFindingIds.length > 0 &&
        e.relatedFindingIds.every((f) => f === p.targetId),
    );
  return new Set(ours.map((e) => e.promotedAt)).size === 1 ? ours : [];
}

/** Another finding cites the row, or the row links to one (a synthesis back-link). */
function citedElsewhere(
  p: WatsonFindingProposal,
  event: ForensicEvent,
  overview: InvestigationState,
): boolean {
  // A back-link counts only while that finding still exists: a link to a deleted finding holds nothing.
  const alive = new Set(overview.findings.map((f) => f.id));
  return (
    (event.relatedFindingIds ?? []).some((f) => f !== p.targetId && alive.has(f)) ||
    overview.findings.some((f) => f.id !== p.targetId && (f.relatedEventIds ?? []).includes(event.id))
  );
}

/**
 * What undo does with each row the apply created. A row another finding cites stays (still marked
 * Watson's; only this finding's link goes), so no citation is left dangling. Any other row goes, and
 * only while it is still exactly what Watson wrote — a changed row nobody else cites is a conflict.
 */
function planCreatedRows(
  p: WatsonFindingProposal,
  rows: ForensicRow[],
  overview: InvestigationState,
): { remove: ForensicRow[]; keep: string[] } {
  const ids = p.createdEventIds ?? [];
  if (rows.length !== new Set(ids).size) throw gone(p.targetId);
  const remove: ForensicRow[] = [];
  const keep: string[] = [];
  for (const r of rows) {
    const { event } = r;
    if (citedElsewhere(p, event, overview)) {
      keep.push(event.id);
      continue;
    }
    const drafted = p.pasteLineEvents.find((e) => e.id === event.id);
    const unchangedRow =
      !!drafted &&
      isWatsonEvent(event) &&
      event.promotedAt === p.promotedAt &&
      event.severity === drafted.severity &&
      event.description === drafted.description;
    if (!unchangedRow) {
      throw new WatsonProposalConflict(`Event ${event.id} that Watson added changed; nothing was changed`);
    }
    remove.push(r);
  }
  return { remove, keep };
}

async function undo(deps: WriterDeps, caseId: string, p: WatsonFindingProposal) {
  const overview = await deps.stateStore.loadOverview(caseId);
  const stored = overview.findings.find((f) => f.id === p.targetId);
  if (!stored) throw gone(p.targetId);
  if (!sameFinding(stored, p.after)) throw unchanged(p.targetId);
  const createdIds = new Set(p.createdEventIds ?? []);
  const rows = await deps.stateStore.forensicRowsById(caseId, [...createdIds]);
  const { remove, keep } = planCreatedRows(p, rows, overview);
  const before = new Set(p.before?.relatedEventIds ?? []);
  const after = p.after.relatedEventIds ?? [];
  // Writes: unlink and relink the rows that stay (kept created rows lose this finding's link), drop
  // the created rows nobody else cites, then the finding.
  await relink(
    deps,
    caseId,
    p.targetId,
    [...before].filter((id) => !after.includes(id)),
    [...after.filter((id) => !createdIds.has(id) && !before.has(id)), ...keep],
  );
  await deps.stateStore.deleteForensicRows(
    caseId,
    remove.map((r) => r.rowId),
  );
  const state: InvestigationState = p.before
    ? withFinding(overview, p.before)
    : { ...overview, findings: overview.findings.filter((f) => f.id !== p.targetId) };
  await deps.stateStore.saveOverview(state);
  await deps.markConclusionsOutOfDate(caseId, OUT_OF_DATE);
  return keep.length ? { state, proposal: { ...p, keptEventIds: keep } } : { state };
}

export const findingWriter: WatsonWriter<WatsonFindingProposal> = { apply, undo };
