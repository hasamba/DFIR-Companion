/**
 * The shared tail of a drop-folder batch (#2540, composition/importIngestBatch.ts): what each file
 * of the batch would have done on its own after its merge, done ONCE for the batch, inside the same
 * import section and against the batch's one baseline.
 *
 *   note    — the files that added nothing get one case-timeline note, not one each;
 *   folds   — coverage and weaknesses folded once (recordMany / foldMany ≡ one record / fold per file);
 *   settle  — dual-write → tagger → caps → demote, once, over every row the batch added (the
 *             deferred super-row tags ride in the same tagger call);
 *   meta    — one import-meta record; undo — one checkpoint naming the file count, covering every
 *             file's cloud-ledger batches; run — one analysis-run record listing every file + hash.
 *
 * Every step is non-fatal, as each is on the per-file path: a file is already merged when the tail
 * runs, so a tail failure is a warning on the file, never a reason to send it to `_failed`. A fold
 * that fails as a batch is retried in its per-file form (both stores' writes are idempotent per
 * upload / one atomic write); settle and the note are never retried (a repeated settle could stamp
 * twice; a duplicate note is worse than a missing one).
 */
import type { CloudCoverageDraft, CloudCoverageStore } from "../analysis/cloudCoverage.js";
import type { WeaknessFile } from "../analysis/awsAccountWeakness.js";
import type { ForensicEvent } from "../analysis/stateTypes.js";
import type { ImportBaseline } from "../analysis/importBaseline.js";
import {
  describeCloudStreamDisclosure,
  sumCloudStreamDisclosure,
  type CloudStreamDisclosure,
} from "../analysis/cloudStreamDisclosure.js";
import { getServerLogger } from "../logging/serverLogger.js";
import { settleForensicImport, type SettledImport } from "../routes/importSettle.js";
import { recordImportRun, type ImportRunContext } from "../routes/importRunRecorder.js";
import { importSettleDeps, type StreamedSettleDeps } from "./importIngestSettle.js";

/** How many file names a batch note or run record lists before "(+N more)". */
export const BATCH_NAMES_LISTED = 20;

/** What the batch collected from its files, in file order. */
export interface BatchCollect {
  /** Imported files: relpath, stored name, structured disclosure. */
  imported: { relpath: string; storedName: string; disclosure: CloudStreamDisclosure | null }[];
  /** Files that added nothing (their note was deferred). */
  empties: { relpath: string; records: number }[];
  /** Each file's coverage + weakness drafts, its moment, and the store they were bound for (the pipeline's). */
  folds: {
    coverage: CloudCoverageDraft[];
    weaknesses: WeaknessFile | undefined;
    at: string;
    coverageStore: CloudCoverageStore | undefined;
  }[];
  /** Super rows whose tagging was deferred to the settle's one tagger call. */
  superPending: ForensicEvent[];
}

export interface BatchTailDeps {
  runCtx: ImportRunContext;
  settleDeps: StreamedSettleDeps;
  pushImportCheckpoint: (
    caseId: string,
    before: ImportBaseline,
    label: string,
    afterState?: undefined,
    superRows?: undefined,
    ledgerLabels?: readonly string[],
  ) => Promise<void>;
}

export interface BatchTailArgs {
  caseId: string;
  kind: string;
  source: string;
  label: string;
  assetHost: string;
  startedAt: string;
  baseline: ImportBaseline;
  collect: BatchCollect;
}

/** "a, b, c (+N more)" — bounded, in file order. */
export function listNames(names: readonly string[]): string {
  const shown = names.slice(0, BATCH_NAMES_LISTED).join(", ");
  return names.length > BATCH_NAMES_LISTED ? `${shown} (+${names.length - BATCH_NAMES_LISTED} more)` : shown;
}

/** The one note for the batch's empty files — what each would have said, summed. */
export function batchEmptyNote(source: string, empties: BatchCollect["empties"]): string {
  const records = empties.reduce((n, e) => n + e.records, 0);
  return (
    `${source} drop batch: ${empties.length} file(s) added nothing to the case (${records} record(s)) — ` +
    `${listNames(empties.map((e) => e.relpath))}; each file's own line is in drop-log.txt`
  );
}

const warn = (caseId: string, what: string, err: unknown): string => {
  const reason = err instanceof Error ? err.message : String(err);
  getServerLogger().warn(`[drop] ${caseId}: batch ${what} failed — ${reason}`, { caseId });
  return `the batch's ${what} step failed (${reason.slice(0, 200)})`;
};

/**
 * Run the tail. `warnings`: what every imported file of the batch carries. `settleFailed`: the one
 * settle threw, so the batch's crash marker must stay for the next sweep's recovery to settle its rows.
 */
export async function runBatchTail(
  deps: BatchTailDeps,
  a: BatchTailArgs,
): Promise<{ warnings: string[]; settleFailed: boolean }> {
  const warnings: string[] = [];
  let settleFailed = false;
  const { options } = deps.runCtx;
  if (a.collect.empties.length && options.pipeline) {
    const note = batchEmptyNote(a.source, a.collect.empties);
    await options.pipeline
      .commitImportNote(a.caseId, note, { label: a.label, importedAt: new Date().toISOString() })
      .catch((e: unknown) => warnings.push(warn(a.caseId, "case-timeline note", e)));
  }
  await foldAll(deps, a);
  const settled = await settleBatch(deps, a).catch((e: unknown) => {
    warnings.push(warn(a.caseId, "settle", e) + " — the next sweep settles these rows");
    settleFailed = true;
    return null;
  });
  if (settled) await recordOutcome(deps, a, settled);
  await recordImportRun(deps.runCtx, {
    caseId: a.caseId,
    kind: a.kind,
    storedName: a.collect.imported[0]?.storedName ?? a.label,
    storedNames: a.collect.imported.map((f) => f.storedName),
    startedAt: a.startedAt,
    baseline: a.baseline,
    minSeverity: undefined,
    ...(a.assetHost ? { assetHost: a.assetHost } : {}),
    path: "deterministic",
    parameters: {
      dropBatchFiles: a.collect.imported.length,
      dropBatchFileNames: listNames(a.collect.imported.map((f) => f.relpath)),
    },
  }).catch((e: unknown) => warn(a.caseId, "analysis-run record", e));
  return { warnings, settleFailed };
}

// Coverage and weaknesses once; on failure each file's own fold (idempotent per upload / atomic).
async function foldAll(deps: BatchTailDeps, a: BatchTailArgs): Promise<void> {
  const store = a.collect.folds.find((f) => f.coverageStore)?.coverageStore;
  if (!store) return;
  const uploads = a.collect.folds
    .filter((f) => f.coverage.length)
    .map((f) => ({ drafts: f.coverage, at: f.at }));
  if (uploads.length) {
    await store.recordMany(a.caseId, uploads).catch(async (e: unknown) => {
      warn(a.caseId, "coverage fold (retrying per file)", e);
      for (const u of uploads) await store.record(a.caseId, u.drafts, u.at).catch(() => undefined);
    });
  }
  const drafts = a.collect.folds.flatMap((f) => (f.weaknesses ? [f.weaknesses] : []));
  if (drafts.length) {
    const weaknesses = store.weaknesses();
    await weaknesses.foldMany(a.caseId, drafts).catch(async (e: unknown) => {
      warn(a.caseId, "weakness fold (retrying per file)", e);
      for (const d of drafts) await weaknesses.fold(a.caseId, d).catch(() => undefined);
    });
  }
}

// The one seam, with the deferred super-row tags in the settle's own tagger call.
async function settleBatch(deps: BatchTailDeps, a: BatchTailArgs): Promise<SettledImport | null> {
  const base = importSettleDeps(deps.settleDeps);
  if (!base) return null;
  const pending = a.collect.superPending;
  const tag = async (caseId: string, rows: ForensicEvent[]): Promise<void> =>
    base.autoTagImported(caseId, [...pending.splice(0), ...rows]);
  try {
    return await settleForensicImport({ ...base, autoTagImported: tag }, a.caseId, a.baseline, a.label);
  } finally {
    // A batch that added no forensic row never reached the tagger: its super rows are tagged here.
    if (pending.length) await base.autoTagImported(a.caseId, pending.splice(0)).catch(() => undefined);
  }
}

// import-meta and the undo step, gated exactly as the Import button gates them.
async function recordOutcome(deps: BatchTailDeps, a: BatchTailArgs, s: SettledImport): Promise<void> {
  const { options } = deps.runCtx;
  const t = s.timelineDiff;
  const i = s.iocsDiff;
  const changed = t.added.length || t.removed.length || i.added.length || i.removed.length;
  if (changed && options.importMetaStore) {
    const sum = a.collect.imported.reduce<CloudStreamDisclosure | null>(
      (acc, f) => (f.disclosure ? (acc ? sumCloudStreamDisclosure(acc, f.disclosure) : f.disclosure) : acc),
      null,
    );
    await options.importMetaStore
      .record(a.caseId, {
        kind: a.kind,
        file: a.label,
        diff: t,
        superTimelineAddedCount: s.superTimelineAddedCount,
        superTimelineEvicted: s.superTimelineEvicted,
        iocsDiff: i,
        ...(sum ? { linesIn: sum.records, streamDisclosure: describeCloudStreamDisclosure(sum) } : {}),
      })
      .then(() => options.onImportMeta?.(a.caseId))
      .catch((e: unknown) => warn(a.caseId, "import-meta", e));
  }
  if (changed || s.principalNamesChanged) {
    const labels = a.collect.imported.map((f) => f.storedName);
    await deps.pushImportCheckpoint(a.caseId, a.baseline, a.label, undefined, undefined, labels);
  }
}
