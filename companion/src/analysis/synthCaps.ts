// Deterministic ordering and disclosure for the capped lists in the synthesis prompt (#1999).
// A cap that silently drops rows by store order hides evidence from the model; every cap here
// ranks first and says "showing X of Y" when it cuts. Pure; no input is mutated.

/** "(showing 15 of 20 label)" when rows were cut; "" when nothing was. */
export function capDisclosure(shown: number, total: number, label: string): string {
  return total > shown ? `(showing ${shown} of ${total} ${label})` : "";
}

function cmp(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

export function tieBreakByValue(a: { value: string }, b: { value: string }): number {
  return cmp(a.value, b.value);
}

/** Newest first by updatedAt (createdAt when empty), then id, so the input hash stays stable. */
export function newestHypothesesFirst<T extends { id: string; createdAt: string; updatedAt: string }>(
  hypotheses: readonly T[],
): T[] {
  const stamp = (h: T): string => h.updatedAt || h.createdAt;
  return [...hypotheses].sort((a, b) => cmp(stamp(b), stamp(a)) || cmp(a.id, b.id));
}

/** IOC count desc, then name. */
export function rankCompromisedAssets<T extends { name: string; iocIds: readonly string[] }>(
  assets: readonly T[],
): T[] {
  return [...assets].sort((a, b) => b.iocIds.length - a.iocIds.length || cmp(a.name, b.name));
}

export interface VerdictRow {
  value: string;
  verdict: string;
  corroborated: boolean;
  line: string;
}

/** Malicious before suspicious, corroborated before lone-intel, then value. */
export function rankVerdictLines<T extends VerdictRow>(rows: readonly T[]): T[] {
  const verdictRank = (v: string): number => (v === "malicious" ? 0 : 1);
  return [...rows].sort(
    (a, b) =>
      verdictRank(a.verdict) - verdictRank(b.verdict) ||
      Number(b.corroborated) - Number(a.corroborated) ||
      tieBreakByValue(a, b),
  );
}
