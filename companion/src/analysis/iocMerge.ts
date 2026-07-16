import type { InvestigationState, IOC } from "./stateTypes.js";

// Entity merging for duplicate IOCs (#82): folds a near-duplicate IOC (a value the automatic
// case-insensitive exact-match dedup in stateMerge.ts didn't catch, e.g. "evil.com" vs
// "www.evil.com") onto a canonical one. Unlike the asset graph (purely derived on every read),
// IOCs live directly in InvestigationState, so this is a real, one-time edit — every consumer
// (report, CSV, exports, dashboard) sees the merged result without extra plumbing. Reversibility
// comes from the caller pushing an import-undo checkpoint before applying it (see server.ts's
// pushImportCheckpoint); going-forward prevention comes from iocAlias.ts + stateMerge.ts.

function uniq<T>(values: T[]): T[] {
  return [...new Set(values)];
}

export interface IocMergeResult {
  state: InvestigationState;
  from: IOC;
  into: IOC;
}

// Fold `fromId` onto `intoId`: unions extractedFrom/enrichments/enrichedBy onto the canonical
// IOC, records the duplicate's value as an alias (so value-keyed lookups like assetGraph's
// byValue still resolve it), rewrites every finding's relatedIocs reference, and drops the
// duplicate row. Pure — returns a new state, throws on a missing id or self-merge.
export function mergeIocs(state: InvestigationState, fromId: string, intoId: string): IocMergeResult {
  if (fromId === intoId) throw new Error("cannot merge an IOC into itself");
  const from = state.iocs.find((i) => i.id === fromId);
  const into = state.iocs.find((i) => i.id === intoId);
  if (!from) throw new Error(`IOC not found: ${fromId}`);
  if (!into) throw new Error(`IOC not found: ${intoId}`);

  const extractedFrom = uniq([...(into.extractedFrom ?? []), ...(from.extractedFrom ?? [])]);
  const enrichments = [...(into.enrichments ?? []), ...(from.enrichments ?? [])];
  const enrichedBy = uniq([...(into.enrichedBy ?? []), ...(from.enrichedBy ?? [])]);
  const aliasValues = uniq([...(into.aliasValues ?? []), from.value, ...(from.aliasValues ?? [])]);

  const merged: IOC = {
    ...into,
    ...(extractedFrom.length ? { extractedFrom } : {}),
    ...(enrichments.length ? { enrichments } : {}),
    ...(enrichedBy.length ? { enrichedBy } : {}),
    aliasValues,
    firstSeen: from.firstSeen < into.firstSeen ? from.firstSeen : into.firstSeen,
  };

  const iocs = state.iocs.filter((i) => i.id !== fromId).map((i) => (i.id === intoId ? merged : i));
  const findings = state.findings.map((f) =>
    f.relatedIocs.includes(fromId)
      ? { ...f, relatedIocs: uniq(f.relatedIocs.map((id) => (id === fromId ? intoId : id))) }
      : f,
  );

  return {
    state: { ...state, iocs, findings, updatedAt: new Date().toISOString() },
    from,
    into: merged,
  };
}
