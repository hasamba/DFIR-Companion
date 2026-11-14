import type { StateStore } from "../../stateStore.js";
import { WatsonProposalConflict } from "./proposalErrors.js";
import { deadEvidenceIds, evidenceStanding, watsonLandedRows } from "./rawEvidence.js";
import { earlierShownIds, mentionedIds } from "./rawReferences.js";
import type { WatsonChat, WatsonTurn } from "./types.js";

// Final review H1/H2: "Add to open questions" writes Watson's answer to the case, so the answer obeys
// the evidence-first rule at the click. Every super-timeline id the answer names (its question,
// answer, pointer or citations) must be in the forensic timeline now. The ids that rest on a row a
// Watson promotion landed become the question's rawEvidenceIds, so Undo of that promotion is refused
// while the question stands. Checked again at the click, not only at the round: a promotion can be
// undone after the turn was saved, and an older turn has no stored evidence.

export const ANSWER_NOT_LIVE =
  "This answer names a super-timeline row that is not in the forensic timeline. Ask Watson again.";

/** The answer names a raw row that is not in the forensic timeline; nothing was written (route → 409). */
export class WatsonAnswerNotLive extends WatsonProposalConflict {
  constructor() {
    super(ANSWER_NOT_LIVE);
    this.name = "WatsonAnswerNotLive";
  }
}

type EvidenceStore = Pick<
  StateStore,
  "databasePath" | "loadOverview" | "hasForensicEventIds" | "forensicRowsById"
>;

/** The super-timeline ids the answer names, among `candidates`. */
function namedIds(answer: NonNullable<WatsonTurn["answer"]>, candidates: ReadonlySet<string>): string[] {
  const texts = [answer.question, answer.answer, answer.pointer];
  return [
    ...new Set([
      ...answer.relatedEventIds.filter((id) => candidates.has(id)),
      ...texts.flatMap((t) => mentionedIds(t, candidates)),
    ]),
  ];
}

/**
 * The canonical rawEvidenceIds the added question must carry. Throws WatsonAnswerNotLive when the
 * answer names a super-timeline row that is not live (withheld, failed, undone or never promoted).
 */
export async function answerRawEvidence(
  store: EvidenceStore,
  caseId: string,
  chat: Pick<WatsonChat, "turns" | "proposals">,
  turn: WatsonTurn,
): Promise<string[]> {
  if (!turn.answer) return [];
  const landed = await watsonLandedRows(store, caseId, chat);
  const stored = turn.answerRawEvidenceIds ?? [];
  const named = namedIds(turn.answer, new Set([...earlierShownIds(chat), ...landed, ...stored]));
  const standing = await evidenceStanding(store, caseId, named);
  if (named.some((id) => !standing.live.has(id) && !standing.folded.has(id))) throw new WatsonAnswerNotLive();
  // A live id is evidence only when a Watson promotion landed it; a folded id rests on its live event.
  const fresh = named.flatMap((id) =>
    standing.live.has(id) ? (landed.has(id) ? [id] : []) : [standing.folded.get(id) as string],
  );
  const evidence = [...new Set([...stored, ...fresh])];
  if ((await deadEvidenceIds(store, caseId, evidence)).length) throw new WatsonAnswerNotLive();
  return evidence;
}
