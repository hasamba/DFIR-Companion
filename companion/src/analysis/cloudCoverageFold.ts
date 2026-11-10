// A live cloud collection's coverage (#2538): ONE Cloud Coverage row per (provider, scope) for the
// whole collection, grown as each page lands — never one row per page. Per-page rows filled the
// store's UPLOADS_TRACKED_PER_CASE_MAX slots and evicted every manually uploaded export, then the
// collection's own early pages. Same ruling as #2482's whole-export summaries: a collection is one
// big export, so it is one upload slot, keyed `collection:<id>`.
//
// Replay safety: a page's coverage is written only after its import committed, and the collection
// engine never imports a landed page again, so no page folds twice. Record counts are a page total:
// a record fetched on two pages is counted on both (categories and first → last are unaffected).

import {
  IMPORT_DISCLOSURE_MAX,
  IMPORT_DISCLOSURE_TEXT_MAX,
  persistCloudCoverage,
  type CloudCoverageDraft,
  type CloudCoverageRecord,
  type CloudCoverageStore,
} from "./cloudCoverage.js";
import { mergeCoverageDrafts } from "./cloudCoverageMerge.js";

/** The coverage group of a live collection — the same id form as its whole-export summaries. */
export function collectionCoverageGroup(collectionId: string): string {
  return `collection:${collectionId}`;
}

/** Only the coverage facts: no stamps, page count or disclosure (those are set per group). */
function toDraft(r: CloudCoverageDraft): CloudCoverageDraft {
  return {
    provider: r.provider,
    scope: r.scope,
    uploadId: r.uploadId,
    recordCount: r.recordCount,
    first: r.first,
    last: r.last,
    categories: r.categories,
  };
}

function unionDisclosure(
  previous: readonly CloudCoverageRecord[],
  drafts: readonly CloudCoverageDraft[],
): string[] {
  const all = [
    ...previous.flatMap((r) => r.importDisclosure ?? []),
    ...drafts.flatMap((d) => d.importDisclosure ?? []),
  ];
  return [...new Set(all.map((s) => s.slice(0, IMPORT_DISCLOSURE_TEXT_MAX)))].slice(0, IMPORT_DISCLOSURE_MAX);
}

/**
 * One page's drafts folded into a collection group's existing records. Pure: neither input changes.
 * Every output record carries the group's earliest `uploadFirstSeenAt`, `importedAt = at`, the page
 * count so far and the union of the pages' disclosures.
 */
export function foldCollectionRecords(
  existing: readonly CloudCoverageRecord[],
  groupId: string,
  drafts: readonly CloudCoverageDraft[],
  at: string,
): CloudCoverageRecord[] {
  const firstSeenAt = existing.reduce(
    (min, r) => (r.uploadFirstSeenAt < min ? r.uploadFirstSeenAt : min),
    existing[0]?.uploadFirstSeenAt ?? at,
  );
  const pages = existing.reduce((max, r) => Math.max(max, r.pages ?? 0), 0) + 1;
  const importDisclosure = unionDisclosure(existing, drafts);
  const merged = mergeCoverageDrafts(
    existing.map(toDraft),
    drafts.map((d) => ({ ...toDraft(d), uploadId: groupId })),
  );
  return merged.map((d) => ({
    ...toDraft(d),
    uploadId: groupId,
    uploadFirstSeenAt: firstSeenAt,
    importedAt: at,
    pages,
    ...(importDisclosure.length ? { importDisclosure } : {}),
  }));
}

/** Best-effort, like persistCloudCoverage: the page has already committed, so a failure here never throws. */
export async function persistCollectionCoverage(
  store: CloudCoverageStore | undefined,
  caseId: string,
  groupId: string,
  coverage: readonly CloudCoverageDraft[],
  at: string = new Date().toISOString(),
): Promise<void> {
  if (!coverage.length || !store) return;
  try {
    await store.replaceGroup(
      caseId,
      groupId,
      (existing) => foldCollectionRecords(existing, groupId, coverage, at),
      coverage,
    );
  } catch {
    /* best-effort */
  }
}

/** A streamed import's coverage: folded into its collection group when it has one, else recorded as its own upload. */
export function persistImportCoverage(
  store: CloudCoverageStore | undefined,
  caseId: string,
  coverage: readonly CloudCoverageDraft[],
  group?: string,
): Promise<void> {
  return group
    ? persistCollectionCoverage(store, caseId, group, coverage)
    : persistCloudCoverage(store, caseId, coverage);
}
