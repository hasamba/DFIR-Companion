// A live cloud collection's coverage (#2538): ONE Cloud Coverage row per (provider, scope) for the
// whole collection, grown as each page lands — never one row per page. Per-page rows filled the
// store's UPLOADS_TRACKED_PER_CASE_MAX slots and evicted every manually uploaded export, then the
// collection's own early pages. Same ruling as #2482's whole-export summaries: a collection is one
// big export, so it is one upload slot, keyed `collection:<id>`.
//
// Replay safety: a page's coverage is written only after its import committed, and the collection
// engine never imports a landed page again, so no page folds twice. Record counts are a page total:
// a record fetched on two pages is counted on both (categories and first → last are unaffected).
//
// Disclosure (#2546): the row's sentences are the pages' disclosures SUMMED as numbers, then worded
// once — never a union of per-page sentences, which showed the first few pages' counts beside the
// whole-collection total and silently dropped a later page's cap.

import {
  IMPORT_DISCLOSURE_MAX,
  IMPORT_DISCLOSURE_TEXT_MAX,
  persistCloudCoverage,
  type CloudCoverageDraft,
  type CloudCoverageRecord,
  type CloudCoverageStore,
} from "./cloudCoverage.js";
import { mergeCoverageDrafts } from "./cloudCoverageMerge.js";
import {
  describeCloudStreamDisclosure,
  sumCloudStreamDisclosure,
  type CloudStreamDisclosure,
} from "./cloudStreamDisclosure.js";
import { persistWeaknesses } from "./cloudWeaknessStore.js";
import type { WeaknessFile } from "./awsAccountWeakness.js";
import type { CloudBatchHooks } from "./ingest/cloudStreamImport.js";

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

/**
 * The collection's running disclosure (#2546): the stored sum plus this page's, summed as numbers so
 * the row's wording states collection totals and every cap any page reached. Every scope's draft of
 * one page carries the SAME page disclosure, so it is taken once, never once per scope. A row stored
 * before #2546 has strings but no sum: its next page replaces them with the post-upgrade sum.
 */
function sumDisclosure(
  previous: readonly CloudCoverageRecord[],
  drafts: readonly CloudCoverageDraft[],
): CloudStreamDisclosure | undefined {
  const before = previous.find((r) => r.streamDisclosure)?.streamDisclosure;
  const page = drafts.find((d) => d.streamDisclosure)?.streamDisclosure;
  return before && page ? sumCloudStreamDisclosure(before, page) : (page ?? before);
}

/** The wording of the sum; with no structured disclosure at all, the pages' own sentences, unioned. */
function describeDisclosure(
  sum: CloudStreamDisclosure | undefined,
  previous: readonly CloudCoverageRecord[],
  drafts: readonly CloudCoverageDraft[],
): string[] {
  const all = sum
    ? describeCloudStreamDisclosure(sum)
    : [...previous, ...drafts].flatMap((r) => r.importDisclosure ?? []);
  return [...new Set(all.map((s) => s.slice(0, IMPORT_DISCLOSURE_TEXT_MAX)))].slice(0, IMPORT_DISCLOSURE_MAX);
}

/**
 * One page's drafts folded into a collection group's existing records. Pure: neither input changes.
 * Every output record carries the group's earliest `uploadFirstSeenAt`, `importedAt = at`, the page
 * count so far and the pages' disclosures summed into one (#2546).
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
  const streamDisclosure = sumDisclosure(existing, drafts);
  const importDisclosure = describeDisclosure(streamDisclosure, existing, drafts);
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
    ...(streamDisclosure ? { streamDisclosure } : {}),
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
    : persistCloudCoverage(store, caseId, coverage.map(withoutSum));
}

/**
 * A streamed import's coverage and weakness drafts, persisted after its import committed. A
 * drop-folder batch (#2540) takes them instead, exactly as `record()` would receive them, and
 * folds the whole batch once (composition/importIngestBatch.ts).
 */
export async function persistCloudImportFolds(
  store: CloudCoverageStore | undefined,
  caseId: string,
  coverage: readonly CloudCoverageDraft[],
  weaknesses: WeaknessFile | undefined,
  opts: { coverageGroup?: string; batch?: Pick<CloudBatchHooks, "folds"> },
): Promise<void> {
  if (opts.batch && !opts.coverageGroup) return opts.batch.folds(coverage.map(withoutSum), weaknesses, store);
  await persistImportCoverage(store, caseId, coverage, opts.coverageGroup);
  await persistWeaknesses(store?.weaknesses(), caseId, weaknesses);
}

/** A manual upload's row keeps its own sentences only: the running sum is a collection row's field (#2546). */
function withoutSum(d: CloudCoverageDraft): CloudCoverageDraft {
  const { streamDisclosure: _sum, ...rest } = d;
  return rest;
}
