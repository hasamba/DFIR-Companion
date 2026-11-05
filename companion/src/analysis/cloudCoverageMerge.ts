// Coverage drafts of one streamed upload, built batch by batch (#2303) and merged here into what the
// whole-file builders (cloudCoverageBuilders.ts) would have produced for the same records: one
// draft per (provider, scope), counts summed, first → last widened, categories merged by name.
// Bounded like the builders: SCOPES_PER_UPLOAD_MAX scopes, the 64 largest categories per scope.

import {
  SCOPES_PER_UPLOAD_MAX,
  type CloudCoverageCategory,
  type CloudCoverageDraft,
} from "./cloudCoverage.js";
import { sortScopesDeterministically } from "./cloudCoverageBuilders.js";

const CATEGORIES_MAX = 64;
const RECORD_TYPE_IDS_MAX = 64;

function mergeCategory(a: CloudCoverageCategory, b: CloudCoverageCategory): CloudCoverageCategory {
  const readOnly =
    a.readOnly || b.readOnly
      ? {
          true: (a.readOnly?.true ?? 0) + (b.readOnly?.true ?? 0),
          false: (a.readOnly?.false ?? 0) + (b.readOnly?.false ?? 0),
          unknown: (a.readOnly?.unknown ?? 0) + (b.readOnly?.unknown ?? 0),
        }
      : undefined;
  const ids =
    a.recordTypeIds || b.recordTypeIds
      ? [...new Set([...(a.recordTypeIds ?? []), ...(b.recordTypeIds ?? [])])].slice(0, RECORD_TYPE_IDS_MAX)
      : undefined;
  return {
    name: a.name,
    count: a.count + b.count,
    ...(readOnly ? { readOnly } : {}),
    ...(ids ? { recordTypeIds: ids } : {}),
  };
}

const earlier = (a: string, b: string): string => (!a ? b : !b ? a : a < b ? a : b);
const later = (a: string, b: string): string => (!a ? b : !b ? a : a > b ? a : b);

function mergeDraft(a: CloudCoverageDraft, b: CloudCoverageDraft): CloudCoverageDraft {
  const byName = new Map(a.categories.map((c) => [c.name, c] as const));
  for (const c of b.categories) {
    const prev = byName.get(c.name);
    byName.set(c.name, prev ? mergeCategory(prev, c) : c);
  }
  const categories = [...byName.values()].sort((x, y) => y.count - x.count).slice(0, CATEGORIES_MAX);
  return {
    ...a,
    recordCount: a.recordCount + b.recordCount,
    first: earlier(a.first, b.first),
    last: later(a.last, b.last),
    categories,
  };
}

/** `acc` with `batch`'s drafts folded in. Pure: neither input is changed. */
export function mergeCoverageDrafts(
  acc: readonly CloudCoverageDraft[],
  batch: readonly CloudCoverageDraft[],
): CloudCoverageDraft[] {
  const key = (d: CloudCoverageDraft): string => `${d.provider}\n${d.scope.kind}\n${d.scope.value}`;
  const out = new Map(acc.map((d) => [key(d), d] as const));
  for (const d of batch) {
    const prev = out.get(key(d));
    out.set(key(d), prev ? mergeDraft(prev, d) : d);
  }
  return sortScopesDeterministically([...out.values()]).slice(0, SCOPES_PER_UPLOAD_MAX);
}
