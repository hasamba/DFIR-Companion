// Pure helpers for mergeIocs (stateMerge.ts): canonical id sequencing, the first-index duplicate
// lookup, and the excluded-indicator markers a finding keeps when an IOC it cited is removed by
// the per-case IOC exclude list (#2151). Split out of stateMerge.ts to keep it under the size cap.

import type { Finding, IOC } from "./stateTypes.js";

/** Derived from Finding so this timeline-tier module never imports the findings tier. */
export type ExcludedIocRef = NonNullable<Finding["excludedIocRefs"]>[number];

export function padIocId(n: number): string {
  return `i${String(n).padStart(3, "0")}`;
}

// Highest existing IOC sequence in the canonical i### form; ids in other formats
// (legacy "i1", model-supplied junk) are ignored so we never collide with them.
export function nextIocSeq(iocs: readonly Pick<IOC, "id">[]): number {
  let max = 0;
  for (const i of iocs) {
    const m = /^i(\d+)$/.exec(i.id);
    if (m) max = Math.max(max, parseInt(m[1], 10));
  }
  return max + 1;
}

/**
 * `iocs.find((i) => i.value.toLowerCase() === lower || (alias !== undefined && i.id === alias))`,
 * answered from first-index maps built on first use and caught up with every IOC appended since
 * (the next lookup indexes them). A stored IOC whose value is not a string (corrupt data) is
 * skipped for value matching but stays reachable by its alias-target id, and never throws (#2162).
 */
export function firstMatchIndex(iocs: IOC[]): {
  find(lower: string, alias: string | undefined): IOC | undefined;
} {
  let byValue: Map<string, number> | null = null;
  let byId: Map<string, number> | null = null;
  let indexed = 0;
  const extend = (): void => {
    for (; indexed < iocs.length; indexed++) {
      const { value, id } = iocs[indexed];
      if (!byId!.has(id)) byId!.set(id, indexed);
      if (typeof value !== "string") continue;
      const lower = value.toLowerCase();
      if (!byValue!.has(lower)) byValue!.set(lower, indexed);
    }
  };
  return {
    find(lower, alias) {
      if (!byValue) {
        byValue = new Map();
        byId = new Map();
      }
      extend();
      const v = byValue.get(lower);
      const a = alias !== undefined ? byId!.get(alias) : undefined;
      const at = v === undefined ? a : a === undefined ? v : Math.min(v, a);
      return at === undefined ? undefined : iocs[at];
    },
  };
}

const refKey = (r: ExcludedIocRef): string => `${r.type}\u0000${String(r.value).toLowerCase()}`;

/** `existing` plus every marker in `added` not already present (type + case-insensitive value). */
export function unionExcludedRefs(
  existing: readonly ExcludedIocRef[] | undefined,
  added: readonly ExcludedIocRef[],
): ExcludedIocRef[] {
  const out = [...(existing ?? [])];
  const seen = new Set(out.map(refKey));
  for (const r of added) {
    const k = refKey(r);
    if (seen.has(k)) continue;
    seen.add(k);
    out.push({ ...r });
  }
  return out;
}

/**
 * Findings with every reference to a purged IOC id removed from `relatedIocs` and recorded as an
 * excluded-indicator marker instead (#2151). `purged` maps each removed canonical id to its marker.
 * Returns new finding objects (inputs untouched) and how many findings changed.
 */
export function stripPurgedIocRefs(
  findings: readonly Finding[],
  purged: ReadonlyMap<string, ExcludedIocRef>,
): { findings: Finding[]; updated: number } {
  let updated = 0;
  const next = findings.map((f) => {
    const hits = f.relatedIocs.filter((id) => purged.has(id));
    if (hits.length === 0) return f;
    updated++;
    return {
      ...f,
      relatedIocs: f.relatedIocs.filter((id) => !purged.has(id)),
      excludedIocRefs: unionExcludedRefs(
        f.excludedIocRefs,
        hits.map((id) => purged.get(id)!),
      ),
    };
  });
  return { findings: next, updated };
}
