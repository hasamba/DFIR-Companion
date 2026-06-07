import type { IOC } from "./stateTypes.js";

// What changed in the IOC set across one import — primarily what the import ADDED. mergeDelta dedupes
// IOCs by EXACT value (i.value === incoming.value) and never removes them, and synthesis preserves the
// IOCs, so the import is the only thing that grows the set. We diff by that same exact value, so a
// re-import of the same artifact shows no new IOCs. The IOC analog of timelineDiff.ts.

export interface DiffIoc {
  value: string;
  type: string;
}

export interface IocsDiff {
  added: DiffIoc[];     // IOCs present after, not before (what the import brought in)
  removed: DiffIoc[];   // IOCs present before, not after (rare — IOCs aren't normally dropped)
}

// First occurrence of each value wins. Keyed by exact value — the same identity mergeDelta dedupes on.
function byValue(iocs: readonly IOC[]): Map<string, DiffIoc> {
  const map = new Map<string, DiffIoc>();
  for (const i of iocs) {
    const key = i.value;
    if (!key || map.has(key)) continue;
    map.set(key, { value: i.value, type: i.type });
  }
  return map;
}

// Compute added / removed IOCs from `before` -> `after`.
export function diffIocs(before: readonly IOC[], after: readonly IOC[]): IocsDiff {
  const a = byValue(before);
  const b = byValue(after);
  const added: DiffIoc[] = [];
  const removed: DiffIoc[] = [];
  for (const [key, cur] of b) if (!a.has(key)) added.push(cur);
  for (const [key, prev] of a) if (!b.has(key)) removed.push(prev);
  return { added, removed };
}

// True when nothing changed — lets callers skip recording/rendering an empty diff.
export function isEmptyIocsDiff(diff: IocsDiff): boolean {
  return diff.added.length === 0 && diff.removed.length === 0;
}
