import type { ForensicRow } from "../../../forensicRows.js";
import type { ForensicEvent, InvestigationState } from "../../../stateTypes.js";
import { isWatsonEvent, isWatsonItem, WATSON_MARKER } from "../../../timeline/watsonItems.js";
import { WatsonProposalConflict } from "../proposalErrors.js";
import type { WatsonEventPromoteProposal, WatsonLandedRow } from "../types.js";
import type { WatsonWriter, WriterDeps } from "./writerTypes.js";

// Rows of a parsed Watson paste that the content tagger graded above Info (spec §14). The paste
// ingest kept them at Info, so demote moved them to the super-timeline; applying the proposal
// promotes the raised copies into the forensic timeline through the pipeline's promotion seam,
// marked `[watson]`. Self-locking: promoteSuperTimeline takes the state lock itself (StateLock is
// not re-entrant), and undo takes it here. Undo removes only the rows this apply added, only while
// each is still as it landed and no finding cites it. The paste file stays the evidence, so
// an undone proposal keeps its rows and may be applied again.

const OUT_OF_DATE = "Watson promoted pasted rows";

// The grading records a held row may carry from the settle's corrections (build-time cap, lab-setup
// cap, Defender engine start-up). The promotion's delta schema strips them, so they are re-applied
// from the held copy: without them a later un-cap cannot restore the grade, and an engine start-up
// row would not be recognised as one by the finding-level tamper cap.
const RECORD_KEYS = ["buildTime", "labSetup", "defenderEngineBoot"] as const;

function recordsOf(events: readonly ForensicEvent[]): Record<string, Record<string, unknown>> {
  const out: Record<string, Record<string, unknown>> = {};
  for (const e of events) {
    const row = e as ForensicEvent & Record<string, unknown>;
    const kept = Object.fromEntries(RECORD_KEYS.filter((k) => row[k] !== undefined).map((k) => [k, row[k]]));
    if (Object.keys(kept).length) out[e.id] = kept;
  }
  return out;
}

async function pasteName(deps: WriterDeps, caseId: string, pasteId: string): Promise<string> {
  // A plain read: the dispatcher holds this case's chat update, which load() does not queue behind.
  const chat = await deps.chatStore.load(caseId).catch(() => undefined);
  return chat?.pastes.find((x) => x.id === pasteId)?.filename ?? pasteId;
}

async function apply(deps: WriterDeps, caseId: string, p: WatsonEventPromoteProposal) {
  if (!deps.promoteEvents) throw new WatsonProposalConflict("Watson cannot promote rows on this server");
  if (!p.events.length) throw new WatsonProposalConflict("This proposal holds no rows; nothing was written");
  const promotedAt = new Date().toISOString();
  const tagById = Object.fromEntries(p.events.map((e) => [e.id, [WATSON_MARKER]]));
  const { state, outcome } = await deps.promoteEvents(caseId, p.events, {
    intent: "watson",
    importedAt: promotedAt,
    tagById,
    records: recordsOf(p.events),
    note: `Watson paste ${await pasteName(deps, caseId, p.pasteId)}`,
  });
  // A row that took the place of an event the case already held is not ours to delete on undo.
  const replaced = new Set(outcome.replaced.map((r) => r.id));
  const created = new Set(outcome.added.filter((id) => !replaced.has(id)));
  const landedRows: WatsonLandedRow[] = state.forensicTimeline
    .filter((e) => created.has(e.id))
    .map((e) => ({ id: e.id, severity: e.severity, description: e.description }));
  await deps.markConclusionsOutOfDate(caseId, OUT_OF_DATE);
  const proposal: WatsonEventPromoteProposal = {
    ...p,
    createdEventIds: landedRows.map((r) => r.id),
    promotedAt,
    landedRows,
  };
  return { state, proposal };
}

function checkRows(p: WatsonEventPromoteProposal, rows: ForensicRow[], overview: InvestigationState): void {
  const landed = new Map((p.landedRows ?? []).map((r) => [r.id, r] as const));
  for (const { event } of rows) {
    const was = landed.get(event.id);
    const same =
      !!was &&
      isWatsonEvent(event) &&
      event.promotedAt === p.promotedAt &&
      event.severity === was.severity &&
      event.description === was.description;
    if (!same) {
      throw new WatsonProposalConflict(
        `Event ${event.id} changed since Watson promoted it; nothing was changed`,
      );
    }
    // Any finding citing the row blocks the undo: removing it would leave that citation dangling.
    const citing = overview.findings.find((f) => (f.relatedEventIds ?? []).includes(event.id));
    if (citing) {
      throw new WatsonProposalConflict(
        isWatsonItem(citing)
          ? `Event ${event.id} is cited by Watson finding ${citing.id}: undo the finding that cites it first`
          : `Event ${event.id} is cited by finding ${citing.id}; nothing was changed`,
      );
    }
  }
}

async function undo(deps: WriterDeps, caseId: string, p: WatsonEventPromoteProposal) {
  const state = await deps.stateLock.runExclusive(caseId, async () => {
    const overview = await deps.stateStore.loadOverview(caseId);
    // A row already gone from the forensic timeline has nothing left to remove.
    const rows = await deps.stateStore.forensicRowsById(caseId, p.createdEventIds ?? []);
    checkRows(p, rows, overview);
    if (rows.length) {
      await deps.stateStore.deleteForensicRows(
        caseId,
        rows.map((r) => r.rowId),
      );
      await deps.stateStore.patchStateMeta(caseId, { updatedAt: new Date().toISOString() });
    }
    return overview;
  });
  await deps.markConclusionsOutOfDate(caseId, OUT_OF_DATE);
  return { state };
}

export const eventPromoteWriter: WatsonWriter<WatsonEventPromoteProposal> = {
  selfLocking: true,
  apply,
  undo,
};
