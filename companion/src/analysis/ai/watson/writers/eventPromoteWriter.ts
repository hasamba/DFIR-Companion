import type { ForensicRow } from "../../../forensicRows.js";
import type { ForensicEvent, InvestigationState } from "../../../stateTypes.js";
import { isWatsonEvent, isWatsonItem, WATSON_MARKER } from "../../../timeline/watsonItems.js";
import { WatsonProposalConflict } from "../proposalErrors.js";
import { evidenceBlocker } from "../rawEvidence.js";
import type { WatsonEventPromoteProposal, WatsonLandedRow } from "../types.js";
import type { WatsonWriter, WriterDeps } from "./writerTypes.js";

// Rows of a parsed Watson paste that the content tagger graded above Info (spec §14). The paste
// ingest kept them at Info, so demote moved them to the super-timeline; applying the proposal
// promotes the raised copies into the forensic timeline through the pipeline's promotion seam,
// marked `[watson]`. Self-locking: promoteSuperTimeline takes the state lock itself (StateLock is
// not re-entrant), and undo takes it here. Undo removes only the rows this apply added, only while
// each is still as it landed and no finding (or applied Watson item, D9b) cites it. The paste file
// stays the evidence, so an undone proposal keeps its rows and may be applied again. A super-timeline
// promotion (`source: "supertimeline"`, phase 4) is the same record: the round saves it pending,
// promotes through promoteRows and records it applied; the raw row stays in the super-timeline.

const OUT_OF_DATE = "Watson promoted pasted rows";
const OUT_OF_DATE_SUPER = "Watson promoted super-timeline rows it cited";

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

async function pasteName(deps: WriterDeps, caseId: string, pasteId: string | undefined): Promise<string> {
  if (!pasteId) return "(unknown paste)";
  // A plain read: the dispatcher holds this case's chat update, which load() does not queue behind.
  const chat = await deps.chatStore.load(caseId).catch(() => undefined);
  return chat?.pastes.find((x) => x.id === pasteId)?.filename ?? pasteId;
}

const isSuper = (p: WatsonEventPromoteProposal): boolean => p.source === "supertimeline";
const plural = (n: number, word: string): string => `${n} ${word}${n === 1 ? "" : "s"}`;

/** The case timeline note: the paste the rows came from, or how many raw rows Watson cited (no paste read). */
async function noteFor(deps: WriterDeps, caseId: string, p: WatsonEventPromoteProposal): Promise<string> {
  if (isSuper(p)) return `Watson cited ${plural(p.events.length, "super-timeline row")}`;
  return `Watson paste ${await pasteName(deps, caseId, p.pasteId)}`;
}

/**
 * Rows a previous run of this same proposal already landed (D9 step 5): among its rows, in the
 * forensic timeline, Watson-marked and stamped with exactly its `promotedAt`. Adopted as created, so
 * a recovery that finds the rows already there still ends with one undoable operation.
 */
function adoptedRows(state: InvestigationState, p: WatsonEventPromoteProposal): Set<string> {
  const wanted = new Set(p.events.map((e) => e.id));
  return new Set(
    state.forensicTimeline
      .filter((e) => wanted.has(e.id) && isWatsonEvent(e) && e.promotedAt === p.promotedAt)
      .map((e) => e.id),
  );
}

/**
 * Promote the proposal's rows only, stamped with `p.promotedAt` (the caller chooses it, so a retry
 * can recognise its own rows): no conclusions marked, nothing recorded in the chat.
 */
export async function promoteRows(
  deps: WriterDeps,
  caseId: string,
  p: WatsonEventPromoteProposal,
): Promise<{ state: InvestigationState; proposal: WatsonEventPromoteProposal }> {
  if (!deps.promoteEvents) throw new WatsonProposalConflict("Watson cannot promote rows on this server");
  if (!p.events.length) throw new WatsonProposalConflict("This proposal holds no rows; nothing was written");
  const promotedAt = p.promotedAt ?? new Date().toISOString();
  const stamped = { ...p, promotedAt };
  const tagById = Object.fromEntries(p.events.map((e) => [e.id, [WATSON_MARKER]]));
  const { state, outcome } = await deps.promoteEvents(caseId, p.events, {
    intent: "watson",
    importedAt: promotedAt,
    tagById,
    records: recordsOf(p.events),
    note: await noteFor(deps, caseId, stamped),
  });
  // A row that took the place of an event the case already held is not ours to delete on undo.
  const replaced = new Set(outcome.replaced.map((r) => r.id));
  const created = new Set([
    ...outcome.added.filter((id) => !replaced.has(id)),
    ...adoptedRows(state, stamped),
  ]);
  const landedRows: WatsonLandedRow[] = state.forensicTimeline
    .filter((e) => created.has(e.id))
    .map((e) => ({ id: e.id, severity: e.severity, description: e.description }));
  const proposal: WatsonEventPromoteProposal = {
    ...stamped,
    createdEventIds: landedRows.map((r) => r.id),
    landedRows,
  };
  return { state, proposal };
}

const outOfDate = (p: WatsonEventPromoteProposal): string => (isSuper(p) ? OUT_OF_DATE_SUPER : OUT_OF_DATE);

async function apply(deps: WriterDeps, caseId: string, p: WatsonEventPromoteProposal) {
  // A pending record keeps the stamp it was saved with, so Apply adopts rows a stuck round landed.
  const promotedAt = p.status === "pending" && p.promotedAt ? p.promotedAt : new Date().toISOString();
  const result = await promoteRows(deps, caseId, { ...p, promotedAt });
  await deps.markConclusionsOutOfDate(caseId, outOfDate(p));
  return result;
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
  // D9b: an applied Watson item resting on one of these rows blocks the undo. A plain read: the
  // dispatcher holds this case's chat update, which load() does not queue behind.
  const chat = await deps.chatStore.load(caseId);
  const blocker = await evidenceBlocker(deps.stateStore, caseId, chat, p.createdEventIds ?? []);
  if (blocker) throw new WatsonProposalConflict(blocker);
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
  await deps.markConclusionsOutOfDate(caseId, outOfDate(p));
  return { state };
}

export const eventPromoteWriter: WatsonWriter<WatsonEventPromoteProposal> = {
  selfLocking: true,
  apply,
  undo,
};
