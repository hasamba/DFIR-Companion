import { storedEventResolver, type EventResolver } from "../../eventAliasLookup.js";
import { eventAliasSource } from "../../eventAliasRead.js";
import type { StateStore } from "../../stateStore.js";
import { proposalTargetId, type WatsonChat, type WatsonProposal } from "./types.js";

// D9b: a Watson item that rests on a super-timeline row Watson promoted names that row in its
// `rawEvidenceIds`. Two guards read it: an item whose rows are gone cannot be applied, and a
// promotion cannot be undone while an applied item still rests on one of its rows. Ids are compared
// alias-resolved (#1715), since correlation may have folded a row into another event since.

type EvidenceStore = Pick<StateStore, "databasePath" | "loadOverview" | "hasForensicEventIds">;

const KIND_WORDS: Partial<Record<WatsonProposal["kind"], string>> = {
  question_update: "key question answer",
  question_new: "key question",
  finding_new: "finding",
  finding_update: "finding",
  next_step_new: "next step",
  report_text: "report text",
};

export const rawEvidenceOf = (p: WatsonProposal): string[] =>
  "rawEvidenceIds" in p && Array.isArray(p.rawEvidenceIds) ? p.rawEvidenceIds : [];

async function resolverFor(
  store: EvidenceStore,
  caseId: string,
  ids: readonly string[],
): Promise<EventResolver> {
  return storedEventResolver(eventAliasSource(store), caseId, ids);
}

/** The ids among `ids` that are no longer live in the forensic timeline, alias-resolved. */
export async function deadEvidenceIds(
  store: EvidenceStore,
  caseId: string,
  ids: readonly string[],
): Promise<string[]> {
  if (!ids.length) return [];
  const resolve = await resolverFor(store, caseId, ids);
  const live = await store.hasForensicEventIds(caseId, [...new Set(ids.map(resolve))]);
  return ids.filter((id) => !live.has(resolve(id)));
}

/** Why an applied Watson item blocks removing `rows`, or null when none rests on them. */
export async function evidenceBlocker(
  store: EvidenceStore,
  caseId: string,
  chat: Pick<WatsonChat, "proposals">,
  rows: readonly string[],
): Promise<string | null> {
  const removing = new Set(rows);
  const applied = chat.proposals.filter((p) => p.status === "applied" && rawEvidenceOf(p).length);
  if (!removing.size || !applied.length) return null;
  const resolve = await resolverFor(store, caseId, applied.flatMap(rawEvidenceOf));
  for (const p of applied) {
    const hit = rawEvidenceOf(p).find((id) => removing.has(id) || removing.has(resolve(id)));
    if (hit === undefined) continue;
    const row = removing.has(hit) ? hit : resolve(hit);
    return `Event ${row} is cited by Watson's ${KIND_WORDS[p.kind] ?? p.kind} ${proposalTargetId(p)}: undo that first`;
  }
  return null;
}

/**
 * How `ids` stand in the forensic timeline now: `live` holds the ids live under their own id,
 * `folded` maps an id correlation folded away to the live event that holds it (#1715).
 */
export async function evidenceStanding(
  store: EvidenceStore,
  caseId: string,
  ids: readonly string[],
): Promise<{ live: Set<string>; folded: Map<string, string> }> {
  if (!ids.length) return { live: new Set(), folded: new Map() };
  const resolve = await resolverFor(store, caseId, ids);
  const found = await store.hasForensicEventIds(caseId, [...new Set(ids.flatMap((id) => [id, resolve(id)]))]);
  const live = new Set(ids.filter((id) => found.has(id)));
  const folded = new Map(
    ids.filter((id) => !live.has(id) && found.has(resolve(id))).map((id) => [id, resolve(id)] as const),
  );
  return { live, folded };
}
