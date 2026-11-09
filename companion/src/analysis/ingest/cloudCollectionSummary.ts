// The whole-export summaries of ONE live cloud collection run, built once at the end of its import
// step (#2482). A collection saves its evidence as many pages, and each page is imported on its own;
// a summary built per page (the AWS credential lineage and compute lifecycles) gave one row per
// credential PER PAGE and said "no issuance record in this upload" on every page that lacked the
// issuance. This step reads every imported page of one kind, in page order, into one summary window
// — the same SUMMARY_RECORDS_MAX bound a large export file gets — and builds the provider's
// `collectionSummaries` over it, as if the collection were one big export file.
//
// PROVIDER-GENERIC. Which kinds summarize per collection is the provider table's business
// (cloudStreamProviders.ts `collectionSummaries`); a kind added there (#2493) needs nothing here.
//
// THE LEDGER IS NOT CONSULTED. Every record on disk is already in the cloud-record ledger — its page
// import put it there — so the dedup gate would blank the whole window. The records are read raw;
// the overlap between sub-windows is folded by the summary builders themselves, which group records
// on their own event ids (awsLineage.ts / awsCompute.ts `scan`). The step writes no ledger batch.
//
// REPLAY-SAFE BY ID. Row ids are fixed per collection, kind and row identity (the row's aggKey), not
// positional. A rebuild — Resume of a run that imported more pages after its summary landed, or a
// replay after a crash — upserts the same rows in place (the merge keeps their revision history),
// and rewrites any super-timeline copy an earlier build's settle wrote, by id. A row the earlier
// build emitted and the rebuild does not (a capped, ranked builder — 256 lineages, the compute
// bound — can displace one, and an "omitted" row can disappear) is then dropped from BOTH timelines
// in one transaction, so no row survives with stale coverage. The drop runs after the merge, not
// inside it; a crash between the two leaves the checkpoint behind, and the replay converges (same
// upsert, same drop). Only ids of this collection+kind's exact summary shape are dropped: page rows
// are never touched.

import { createHash } from "node:crypto";
import { deltaSchema } from "../responseSchema.js";
import type { InvestigationState, Severity } from "../stateTypes.js";
import type { SiemEvent } from "../siemImport.js";
import { applySeverityFloor } from "../severityFloor.js";
import { openCloudRecordStream } from "../cloudStreamReader.js";
import { SUMMARY_RECORDS_MAX } from "../cloudStreamLimits.js";
import type { SummaryScope } from "../summaryScope.js";
import { commitDelta, noteEmptyImport } from "./importState.js";
import type { ImportContext } from "./importContext.js";
import {
  streamProvider,
  type Preliminary,
  type StreamKind,
  type StreamProvider,
} from "./cloudStreamProviders.js";

type Row = Record<string, unknown>;

export interface CollectionSummaryPage {
  /** The saved page file on disk. */
  path: string;
  /** Its record count from the manifest — the truncation disclosure's total. */
  records: number;
}

export interface CollectionSummaryOptions {
  collectionId: string;
  /** The step's fixed label: the "did it land?" check and every row's source. */
  label: string;
  /** The step's fixed id prefix; the row ids add the row's identity. */
  idPrefix: string;
  importedAt: string;
  minSeverity?: Severity;
  signal?: AbortSignal;
  /** Test seam; production uses SUMMARY_RECORDS_MAX. */
  summaryRecords?: number;
}

export interface CollectionSummaryResult {
  state: InvestigationState;
  /** Summary rows built (after the severity floor). */
  rows: number;
  pages: number;
  /** Records the pages hold (the manifest's counts) and records the window read. */
  records: number;
  windowRecords: number;
  truncated: boolean;
  /** The ids of the summary rows this build kept — the settle hands exactly these on (#2482). */
  ids: string[];
}

function abortIfCancelled(signal?: AbortSignal): void {
  if (!signal?.aborted) return;
  throw Object.assign(new Error("import cancelled"), { name: "AbortError" });
}

/** The pages' records in page order, up to `max`: the collection's summary window. */
async function readWindow(
  provider: StreamProvider,
  pages: readonly CollectionSummaryPage[],
  max: number,
  pre: Preliminary,
  signal?: AbortSignal,
): Promise<Row[]> {
  const window: Row[] = [];
  for (const page of pages) {
    if (window.length >= max) break;
    abortIfCancelled(signal);
    const stream = await openCloudRecordStream(page.path, { adapt: provider.csvAdapt });
    for await (const raw of stream.records) {
      for (const rec of provider.prepare([raw], pre)) if (window.length < max) window.push(rec);
      if (window.length >= max) break;
    }
  }
  return window;
}

/** A provider's whole-file lookups (M365 only today), learned over every page. */
async function preliminary(
  provider: StreamProvider,
  pages: readonly CollectionSummaryPage[],
  signal?: AbortSignal,
): Promise<Preliminary> {
  if (!provider.preliminary) return {};
  const learner = provider.preliminary();
  for (const page of pages) {
    abortIfCancelled(signal);
    const stream = await openCloudRecordStream(page.path, { adapt: provider.csvAdapt });
    for await (const raw of stream.records) learner.add([raw]);
  }
  return learner.finish();
}

/**
 * The row's fixed id: the collection's prefix and the row's identity. An "omitted" row's key carries
 * its count, which a rebuild may change — its identity is the slot, so it is rewritten, not doubled.
 */
function rowIds(events: readonly SiemEvent[], idPrefix: string): string[] {
  const seen = new Set<string>();
  return events.map((e, i) => {
    const key = e.aggKey ?? `row|${i}`;
    const slot = key.includes("|omitted") ? key.slice(0, key.indexOf("|omitted") + 8) : key;
    let id = `${idPrefix}${createHash("sha256").update(slot).digest("hex").slice(0, 16)}`;
    while (seen.has(id)) id = `${id}x`;
    seen.add(id);
    return id;
  });
}

function windowClause(
  source: string,
  r: Omit<CollectionSummaryResult, "state" | "rows" | "ids">,
  max: number,
): string {
  const base = `${source} collection summary over ${r.windowRecords} record(s) of ${r.pages} page(s)`;
  return r.truncated
    ? `${base}; whole-collection summaries built over the first ${max} of ${r.records} records — later records are not in them`
    : base;
}

/** Build and merge one collection's summaries for `kind`. The caller holds the case's import section. */
export async function importCloudCollectionSummary(
  ctx: ImportContext,
  caseId: string,
  kind: StreamKind,
  pages: readonly CollectionSummaryPage[],
  opts: CollectionSummaryOptions,
): Promise<CollectionSummaryResult> {
  const provider = streamProvider(kind);
  if (!provider.collectionSummaries) throw new Error(`${kind} has no per-collection summaries`);
  const max = opts.summaryRecords ?? SUMMARY_RECORDS_MAX;
  const pre = await preliminary(provider, pages, opts.signal);
  const window = await readWindow(provider, pages, max, pre, opts.signal);
  abortIfCancelled(opts.signal);
  const records = pages.reduce((n, p) => n + p.records, 0);
  const facts = {
    pages: pages.length,
    records,
    windowRecords: window.length,
    truncated: window.length >= max && records > window.length,
  };
  const scope: SummaryScope = {
    kind: "collection",
    pages: pages.length,
    uploadId: `collection:${opts.collectionId}`,
  };
  const events = applySeverityFloor(
    window.length ? provider.collectionSummaries(window, scope, pre) : [],
    opts.minSeverity,
  );
  const clause = windowClause(provider.source, facts, max);
  if (!events.length) {
    const state = await noteEmptyImport(
      ctx,
      caseId,
      opts,
      `${provider.source} collection summary`,
      window.length,
      clause,
    );
    return { state: await dropSuperseded(ctx, caseId, state, opts.idPrefix, []), rows: 0, ids: [], ...facts };
  }
  const ids = rowIds(events, opts.idPrefix);
  const delta = deltaSchema.parse({
    findings: [],
    iocs: [],
    mitreTechniques: [],
    forensicEvents: events.map((e, i) => ({
      ...e,
      id: ids[i],
      sources: e.sources?.length ? e.sources : [provider.source],
    })),
    threadsOpened: [],
    threadsClosed: [],
    timelineNote: `${clause}: ${events.length} summary row(s), one per collection run`,
    summary: "",
  });
  const state = await commitDelta(ctx, caseId, delta, {
    label: opts.label,
    importedAt: opts.importedAt,
    signal: opts.signal,
  });
  await rewriteSuperCopies(ctx, caseId, state, new Set(ids));
  const settled = await dropSuperseded(ctx, caseId, state, opts.idPrefix, ids);
  return { state: settled, rows: events.length, ids, ...facts };
}

const SUMMARY_ID_TAIL = /^[0-9a-f]{16}x*$/;

/**
 * Drop the earlier builds' rows of this collection+kind that this build did not keep, from both
 * timelines. Returns the state as it now reads. Without a super-timeline store (minimal wirings)
 * only the forensic rows exist to drop.
 */
async function dropSuperseded(
  ctx: ImportContext,
  caseId: string,
  state: InvestigationState,
  idPrefix: string,
  keep: readonly string[],
): Promise<InvestigationState> {
  const kept = new Set(keep);
  const store = ctx.opts.superTimelineStore;
  if (store) {
    const dropped = await store.dropSummaryRows(caseId, idPrefix, keep);
    return dropped.forensic ? ctx.opts.stateStore.load(caseId) : state;
  }
  const stale = state.forensicTimeline
    .map((e) => e.id)
    .filter(
      (id) => id.startsWith(idPrefix) && SUMMARY_ID_TAIL.test(id.slice(idPrefix.length)) && !kept.has(id),
    );
  if (!stale.length) return state;
  const rows = await ctx.opts.stateStore.forensicRowsById(caseId, stale);
  await ctx.opts.stateStore.deleteForensicRows(
    caseId,
    rows.map((r) => r.rowId),
  );
  return ctx.opts.stateStore.load(caseId);
}

/**
 * An earlier build's rows the settle copied (or demoted) to the super-timeline keep their ids, and
 * the dual-write skips an id the store holds — so those copies are rewritten here, by id, to the row
 * as it now reads. A first build has no copies; the store skips ids it does not hold.
 */
async function rewriteSuperCopies(
  ctx: ImportContext,
  caseId: string,
  state: InvestigationState,
  ids: ReadonlySet<string>,
): Promise<void> {
  const store = ctx.opts.superTimelineStore;
  if (!store) return;
  const rows = state.forensicTimeline.filter((e) => ids.has(e.id));
  if (rows.length) await store.rehome(caseId, rows);
}
