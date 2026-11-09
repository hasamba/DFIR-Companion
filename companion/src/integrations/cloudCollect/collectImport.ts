// The import stage of a collection (#2311): every saved page (bar an evidence-only one, #2340), in
// sequence order, through the #2303 streaming importer, with the case's import section held per
// page (imports stay serialized).
//
// REPLAY-SAFE PER PAGE, not merely guarded by a "last imported page" checkpoint. A kill can land
// anywhere inside a page's import, so each page is made idempotent on its own:
//   - "Did this page land?" is asked of the CASE: the importer's delta commit (and its empty-import
//     note) writes one timeline entry carrying the page's label, atomically with the rows. If it is
//     there, the page is never imported again — at most its settle is re-run (dual-write, tag and
//     demote are idempotent).
//   - Otherwise, any ledger batch an earlier dead attempt of this page committed is switched off
//     first — the same switch Undo uses (cloudRecordStore.setBatchesActive). A hard kill never ran
//     the importer's own cleanup, so without this every record of that attempt would read as a
//     duplicate and the page would import as a gap.
//   - The id prefix is fixed per page, so super-timeline rows (deduped by id/content), sign-in
//     observations (deduped by observation id) and MFA-fatigue rows (fixed ids) written by the dead
//     attempt are not written twice.
// Every row carries its provenance: the label `evidence/cloud/<collectionId>/<page file>` is on
// each row's sources list, and the provider record ids ride on `sourceRecords` (#2301).
//
// After the last page, the summary step (#2482, collectSummary.ts) builds the whole-export summaries
// of each kind that summarizes per collection ONCE over every page; those pages skip their own.

import { join } from "node:path";
import type { StreamKind } from "../../analysis/ingest/cloudStreamProviders.js";
import type { ManifestPage } from "./collectTypes.js";
import { pageIdPrefix, runSummaryStep, type SummaryImporter } from "./collectSummary.js";

export { pageIdPrefix };

export interface PageImportRequest {
  kind: StreamKind;
  path: string;
  label: string;
  idPrefix: string;
  importedAt: string;
}

/**
 * How the stage reaches the case. Production: routes/cloudCollectImporter.ts; tests: a pipeline.
 * `importPage` skips the whole-export summaries of a kind that `summarizesPerCollection`; the
 * summary step's `importSummary` builds them once over the collection (#2482).
 */
export interface CollectPageImporter extends SummaryImporter {
  /** Run `fn` with the case's import section held. */
  withImportSection<T>(caseId: string, fn: () => Promise<T>): Promise<T>;
  /** True when a page's import committed in the case (a timeline entry carries its label). */
  landed(caseId: string, label: string): Promise<boolean>;
  /** Switch off the ledger batches an earlier, dead attempt of this page committed. */
  forgetAttempt(caseId: string, label: string): Promise<void>;
  /** Import one page and settle it (dual-write → tag → demote). */
  importPage(caseId: string, page: PageImportRequest, signal?: AbortSignal): Promise<void>;
  /** Settle a page whose import committed before a crash but whose settle may not have run. */
  settleLanded(caseId: string, label: string): Promise<void>;
}

export interface ImportStageInput {
  caseId: string;
  collectionId: string;
  dir: string;
  pagesDir: string;
  pages: readonly ManifestPage[];
  /**
   * Committed pages quarantined as corrupt or missing. Never imported — but a dead attempt of one
   * may have left an active ledger batch, which would make its window's re-fetch read as duplicates.
   */
  abandoned: readonly ManifestPage[];
  streamKindOf: (source: string) => StreamKind | undefined;
  /** Page files already imported (from the checkpoint). */
  imported: ReadonlySet<string>;
  signal?: AbortSignal;
  /** Called after each page lands — the caller checkpoints it. */
  onImported: (file: string) => Promise<void>;
  /** Per kind, the page count the landed collection summary covers (#2482; from the checkpoint). */
  summarized?: Readonly<Partial<Record<string, number>>>;
  /** Called after a kind's collection summary lands — the caller checkpoints it. */
  onSummarized?: (kind: StreamKind, pages: number) => Promise<void>;
}

/** The case reads the replay check needs, shared by the production importer and the tests. */
export interface TimelineReader {
  loadOverviewWithoutIocs(
    caseId: string,
  ): Promise<{ timeline: ReadonlyArray<{ sourceScreenshots: string[] }> }>;
}
export interface LedgerSwitch {
  claimBatches(caseId: string, label: string): Promise<string[]>;
  setBatchesActive(caseId: string, batches: string[], active: boolean): Promise<void>;
}

/** `landed`: the page's import wrote its timeline entry (commitDelta / noteEmptyImport). */
export function timelineLanded(store: TimelineReader): CollectPageImporter["landed"] {
  return async (caseId, label) =>
    (await store.loadOverviewWithoutIocs(caseId)).timeline.some((e) => e.sourceScreenshots.includes(label));
}

/** `forgetAttempt`: the Undo switch, on whatever ledger batches a dead attempt of the page left. */
export function ledgerForget(store: LedgerSwitch | undefined): CollectPageImporter["forgetAttempt"] {
  return async (caseId, label) => {
    if (!store) return;
    const batches = await store.claimBatches(caseId, label);
    if (batches.length) await store.setBatchesActive(caseId, batches, false);
  };
}

/** The label every row of a page carries: collection id + page file in one string. */
export function pageLabel(collectionId: string, file: string): string {
  return `evidence/cloud/${collectionId}/${file}`;
}

function abortIfCancelled(signal?: AbortSignal): void {
  if (!signal?.aborted) return;
  throw Object.assign(new Error("collection cancelled"), { name: "AbortError" });
}

/** Import one page so that running it again, after a crash anywhere inside it, changes nothing. */
export async function importPageReplaySafe(
  importer: CollectPageImporter,
  caseId: string,
  page: PageImportRequest,
  signal?: AbortSignal,
): Promise<"imported" | "already"> {
  return importer.withImportSection(caseId, async () => {
    if (await importer.landed(caseId, page.label)) {
      await importer.settleLanded(caseId, page.label);
      return "already";
    }
    await importer.forgetAttempt(caseId, page.label);
    await importer.importPage(caseId, page, signal);
    return "imported";
  });
}

async function forgetAbandoned(importer: CollectPageImporter, input: ImportStageInput): Promise<void> {
  for (const page of input.abandoned) {
    if (input.imported.has(page.file)) continue;
    const label = pageLabel(input.collectionId, page.file);
    await importer.withImportSection(input.caseId, async () => {
      if (!(await importer.landed(input.caseId, label))) await importer.forgetAttempt(input.caseId, label);
    });
  }
}

export async function runImportStage(
  importer: CollectPageImporter,
  input: ImportStageInput,
): Promise<number> {
  await forgetAbandoned(importer, input);
  let imported = 0;
  for (const page of [...input.pages].sort((a, b) => a.seq - b.seq)) {
    if (input.imported.has(page.file)) continue;
    abortIfCancelled(input.signal);
    // Evidence only (#2340): no log data to import, so nothing can have landed — checkpoint it.
    if (page.evidenceOnly) {
      await input.onImported(page.file);
      imported++;
      continue;
    }
    const kind = input.streamKindOf(page.source);
    if (!kind) throw new Error(`no importer for collected source "${page.source}"`);
    await importPageReplaySafe(
      importer,
      input.caseId,
      {
        kind,
        path: join(input.pagesDir, page.file),
        label: pageLabel(input.collectionId, page.file),
        idPrefix: pageIdPrefix(input.collectionId, page.seq),
        importedAt: page.retrievedAt,
      },
      input.signal,
    );
    await input.onImported(page.file);
    imported++;
  }
  await runSummaryStep(importer, { ...input, summarized: input.summarized ?? {} });
  return imported;
}
