// Readers of analyst records kept outside the case state (#1715): a tag, comment, star or hypothesis
// link names the event the analyst saw, and correlation may since have folded it into another. These
// build the live-first resolver (eventAliases.ts) from a stored case or a loaded state, and project a
// record list so each event target also carries the id it resolves to today. The records themselves
// are never rewritten — `targetId` still says what the analyst marked.

import type { InvestigationState } from "./stateTypes.js";
import { aliasCandidates, eventAliasResolver } from "./eventAliases.js";

export type EventResolver = (id: string) => string;

const identity: EventResolver = (id) => id;

/** The parts of the state store a resolver needs: the lineage, and which ids are events today. */
export interface EventAliasSource {
  loadOverview(caseId: string): Promise<Pick<InvestigationState, "eventAliases">>;
  hasForensicEventIds(caseId: string, ids: readonly string[]): Promise<Set<string>>;
}

/** A resolver for `ids` against the stored case; the identity when there is no store or no lineage. */
export async function storedEventResolver(
  store: EventAliasSource | undefined,
  caseId: string,
  ids: readonly string[],
): Promise<EventResolver> {
  if (!store || ids.length === 0) return identity;
  const aliases = (await store.loadOverview(caseId)).eventAliases;
  if (!aliases || Object.keys(aliases).length === 0) return identity;
  const live = await store.hasForensicEventIds(caseId, aliasCandidates(aliases, ids));
  return eventAliasResolver(aliases, (id) => live.has(id));
}

/** A resolver against a state already loaded with its forensic timeline. */
export function stateEventResolver(
  state: Pick<InvestigationState, "eventAliases" | "forensicTimeline">,
): EventResolver {
  if (!state.eventAliases) return identity;
  const live = new Set(state.forensicTimeline.map((e) => e.id));
  return eventAliasResolver(state.eventAliases, (id) => live.has(id));
}

interface EventTargeted {
  targetType: string;
  targetId: string;
}

/** Each event-targeted record whose event was folded away, also carrying `resolvedTargetId`. */
export function withResolvedTargets<T extends EventTargeted>(
  records: readonly T[],
  resolve: EventResolver,
): Array<T & { resolvedTargetId?: string }> {
  return records.map((r) => {
    if (r.targetType !== "event") return r;
    const resolved = resolve(r.targetId);
    return resolved === r.targetId ? r : { ...r, resolvedTargetId: resolved };
  });
}

/** The ids of every event-targeted record — what a resolver for the list must be built over. */
export function eventTargetIds(records: readonly EventTargeted[]): string[] {
  return [...new Set(records.filter((r) => r.targetType === "event").map((r) => r.targetId))];
}

/** A tag/comment list with its folded-away event targets resolved against the stored case. */
export async function resolveStoredTargets<T extends EventTargeted>(
  store: EventAliasSource | undefined,
  caseId: string,
  records: readonly T[],
): Promise<Array<T & { resolvedTargetId?: string }>> {
  const resolve = await storedEventResolver(store, caseId, eventTargetIds(records));
  return resolve === identity ? [...records] : withResolvedTargets(records, resolve);
}
