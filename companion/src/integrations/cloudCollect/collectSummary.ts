// The summary step of a collection's import stage (#2482): after every page has landed, the
// whole-export summaries of each kind that summarizes per collection (the AWS credential lineage and
// compute lifecycles today; other providers in #2493) are built ONCE over all of the run's pages —
// the collection read as one big export file — instead of once per page.
//
// WHEN. At the end of the import stage, over whatever pages the run saved — a partial or stopped
// run included. Resume that adds pages rebuilds the summary over all of them.
//
// REPLAY. The checkpoint records, per kind, how many pages the landed summary covers (`summarized`).
// When that matches the kind's page count the step is skipped; otherwise it is (re)built. A rebuild
// is safe without that record too — a checkpoint rebuilt from the manifest, or a crash between the
// summary's commit and its checkpoint: the rows have fixed ids per collection, so the merge upserts
// them in place and the super-timeline copies are rewritten by id (cloudCollectionSummary.ts).

import { join } from "node:path";
import type { StreamKind } from "../../analysis/ingest/cloudStreamProviders.js";
import type { ManifestPage } from "./collectTypes.js";

/** What the importer is asked to build: one kind's summaries over the collection's pages. */
export interface CollectionSummaryRequest {
  kind: StreamKind;
  collectionId: string;
  /** Page files in page order, with their manifest record counts. */
  pages: Array<{ path: string; records: number }>;
  label: string;
  idPrefix: string;
  importedAt: string;
}

/** The slice of the import stage the summary step reads. */
export interface SummaryStepInput {
  caseId: string;
  collectionId: string;
  pagesDir: string;
  pages: readonly ManifestPage[];
  streamKindOf: (source: string) => StreamKind | undefined;
  /** Per kind, the page count the landed summary covers (from the checkpoint). */
  summarized: Readonly<Partial<Record<string, number>>>;
  signal?: AbortSignal;
  /** Called after a kind's summary lands — the caller checkpoints it. */
  onSummarized?: (kind: StreamKind, pages: number) => Promise<void>;
}

/** The case operations the step needs (CollectPageImporter carries them). */
export interface SummaryImporter {
  withImportSection<T>(caseId: string, fn: () => Promise<T>): Promise<T>;
  summarizesPerCollection(kind: StreamKind): boolean;
  importSummary(caseId: string, req: CollectionSummaryRequest, signal?: AbortSignal): Promise<void>;
}

/** The fixed label of one kind's collection summary — on every row it writes and on its note. */
export function summaryLabel(collectionId: string, kind: StreamKind): string {
  return `evidence/cloud/${collectionId}/summary-${kind}`;
}

/** The fixed id prefix of one kind's collection summary (the rows add their own identity). */
export function summaryIdPrefix(collectionId: string, kind: StreamKind): string {
  const short = collectionId.replace(/[^A-Za-z0-9]/g, "").slice(-8);
  return `cc${short}s${kind}`;
}

/** The run's importable pages of each kind that summarizes per collection, in page order. */
function pagesByKind(importer: SummaryImporter, input: SummaryStepInput): Map<StreamKind, ManifestPage[]> {
  const out = new Map<StreamKind, ManifestPage[]>();
  for (const page of [...input.pages].sort((a, b) => a.seq - b.seq)) {
    if (page.evidenceOnly) continue;
    const kind = input.streamKindOf(page.source);
    if (!kind || !importer.summarizesPerCollection(kind)) continue;
    out.set(kind, [...(out.get(kind) ?? []), page]);
  }
  return out;
}

/** Build each per-collection summary that does not yet cover every page of its kind. */
export async function runSummaryStep(importer: SummaryImporter, input: SummaryStepInput): Promise<number> {
  let built = 0;
  for (const [kind, pages] of pagesByKind(importer, input)) {
    if (input.summarized[kind] === pages.length) continue;
    if (input.signal?.aborted) throw Object.assign(new Error("collection cancelled"), { name: "AbortError" });
    const req: CollectionSummaryRequest = {
      kind,
      collectionId: input.collectionId,
      pages: pages.map((p) => ({ path: join(input.pagesDir, p.file), records: p.records })),
      label: summaryLabel(input.collectionId, kind),
      idPrefix: summaryIdPrefix(input.collectionId, kind),
      importedAt: pages[pages.length - 1].retrievedAt,
    };
    await importer.withImportSection(input.caseId, () =>
      importer.importSummary(input.caseId, req, input.signal),
    );
    await input.onSummarized?.(kind, pages.length);
    built++;
  }
  return built;
}
