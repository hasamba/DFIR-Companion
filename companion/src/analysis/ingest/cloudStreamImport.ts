// Streaming import of a large cloud export (#2303): M365 UAL / Entra, AWS CloudTrail and GCP /
// Azure Activity files of any size, read from the stored evidence file on disk — never as one
// string — in CLOUD_STREAM_BATCH_RECORDS-record batches.
//
//   pass 1 (preliminary, M365 only) — the whole-file lookups: the object-id → app-id resolver that
//            lets a later consent record name its API, and the mailbox-audit date order;
//   pass 2 — per batch: dedup → map → tagger pre-grade → output budget → write (cloudStreamBatch.ts);
//   end    — the bounded forensic delta (Critical/High individual, budgeted Medium, aggregates,
//            the whole-export summaries over the summary window, spray and MFA fatigue from the
//            sign-in store) is
//            merged once and then crosses the ordinary settle seam: dual-write → tag → demote.
//
// WHERE THE ROWS GO (ARCHITECTURE.md → "The forensic / super-timeline boundary"). Graded rows reach
// the forensic timeline — the only record the AI reads — through the delta. Info and Low rows are
// appended straight to the super-timeline (the importSandbox precedent) after the tagger's severity
// rules had their chance to raise them, so the AI never reads them and the tagger never misses
// them. Nothing here reads the super-timeline back.

import { randomUUID } from "node:crypto";
import { deltaSchema } from "../responseSchema.js";
import type { CanonicalEventEnvelope } from "../canonicalEvent.js";
import type { InvestigationState, Severity, ForensicEvent } from "../stateTypes.js";
import type { CompiledRuleset } from "../taggerRules.js";
import { applySeverityFloor } from "../severityFloor.js";
import type { ImportDebugRecorder } from "../importDebug.js";
import type { CloudCoverageDraft } from "../cloudCoverage.js";
import { openCloudRecordStream, type CloudStreamStats } from "../cloudStreamReader.js";
import { createOutputBudget, defaultBudgets } from "../cloudOutputBudget.js";
import { createPreGrader } from "../cloudStreamPreGrade.js";
import { sigmaImportNote } from "../sigmaImportGrade.js";
import { undatedRowsNote } from "../m365ExportAdapters.js";
import { DEFAULT_SUPER_MAX } from "../superTimelineStore.js";
import {
  buildCloudStreamDisclosure,
  describeCloudStreamDisclosure,
  type CloudStreamDisclosure,
} from "../cloudStreamDisclosure.js";
import {
  CLOUD_STREAM_BATCH_RECORDS,
  SUMMARY_RECORDS_MAX,
  SUPER_ROWS_PER_IMPORT_MAX,
} from "../cloudStreamLimits.js";
import { commitDelta, noteEmptyImport } from "./importState.js";
import type { ImportContext } from "./importContext.js";
import {
  memberProvenance,
  newAccumulator,
  processBatch,
  type BatchDeps,
  type StreamAccumulator,
} from "./cloudStreamBatch.js";
import {
  streamProvider,
  type Preliminary,
  type StreamKind,
  type StreamProvider,
} from "./cloudStreamProviders.js";
import { streamSprayRows } from "./cloudStreamSpray.js";
import { precursorPromotionNote, promoteCrossUploadPrecursors } from "./cloudPrecursorPromote.js";
import { mfaFatigueRows } from "./mfaFatigueRows.js";
import { fatigueEventId } from "../mfaFatigue.js";
import { resolveStreamIocLinks } from "./cloudStreamIocLinks.js";

type Row = Record<string, unknown>;

export interface CloudStreamImportOptions {
  label: string;
  idPrefix: string;
  importedAt: string;
  minSeverity?: Severity;
  debug?: ImportDebugRecorder;
  onProgress?: (done: number, total: number) => void;
  /** The tagger's ruleset when its severity rules may change the forensic grade; null otherwise. */
  preGradeRules?: CompiledRuleset | null;
  /** Tag the rows written straight to the super-timeline (the settle tagger never sees them). */
  onSuperRows?: (rows: ForensicEvent[]) => Promise<void>;
  signal?: AbortSignal;
  /**
   * Build none of the provider's whole-export summaries (#2482): a live collection's page, whose
   * summaries the collection's summary step builds once over every page (cloudCollectionSummary.ts).
   * It skips the M365 spray rows too (#2493); MFA fatigue stays per page — its ids upsert.
   */
  skipSummaries?: boolean;
  /**
   * A live collection page's coverage group (#2538), `collection:<id>`: the pipeline folds the
   * page's coverage into that collection's one Cloud Coverage row. Unread by the import itself.
   */
  coverageGroup?: string;
  /** Test seams; production uses the named constants. */
  batchRecords?: number;
  summaryRecords?: number;
  iocsMax?: number;
}

export interface CloudStreamImportResult {
  state: InvestigationState;
  coverage: CloudCoverageDraft[];
  disclosure: CloudStreamDisclosure;
}

function abortIfCancelled(signal?: AbortSignal): void {
  if (!signal?.aborted) return;
  const err = new Error("import cancelled");
  err.name = "AbortError";
  throw err;
}

/** Each batch of raw records from the file, with the file index of its first record. */
async function* batches(
  path: string,
  provider: StreamProvider,
  size: number,
  onStats: (s: () => CloudStreamStats) => void,
): AsyncGenerator<{ raw: Row[]; base: number }> {
  const stream = await openCloudRecordStream(path, { adapt: provider.csvAdapt });
  onStats(stream.stats);
  let raw: Row[] = [];
  let base = 0;
  for await (const rec of stream.records) {
    raw.push(rec);
    if (raw.length >= size) {
      yield { raw, base };
      base += raw.length;
      raw = [];
    }
  }
  if (raw.length) yield { raw, base };
}

async function preliminaryPass(
  path: string,
  provider: StreamProvider,
  size: number,
  signal?: AbortSignal,
): Promise<Preliminary> {
  if (!provider.preliminary) return {};
  const learner = provider.preliminary();
  for await (const { raw } of batches(path, provider, size, () => {})) {
    abortIfCancelled(signal);
    learner.add(raw);
  }
  return learner.finish();
}

/** Rows this import may write to the super-timeline: its budget, within the case store's room. */
async function superRoom(ctx: ImportContext, caseId: string): Promise<number> {
  const store = ctx.opts.superTimelineStore;
  if (!store) return 0;
  const cap = Number(process.env.DFIR_SUPERTIMELINE_MAX) || DEFAULT_SUPER_MAX;
  const { rows } = await store.meta(caseId);
  return Math.max(0, Math.min(SUPER_ROWS_PER_IMPORT_MAX, cap - rows));
}

export async function importCloudFile(
  ctx: ImportContext,
  caseId: string,
  kind: StreamKind,
  path: string,
  opts: CloudStreamImportOptions,
): Promise<CloudStreamImportResult> {
  const provider = streamProvider(kind);
  const size = opts.batchRecords ?? CLOUD_STREAM_BATCH_RECORDS;
  const windowMax = opts.skipSummaries ? 0 : (opts.summaryRecords ?? SUMMARY_RECORDS_MAX);
  const acc = newAccumulator(windowMax, opts.iocsMax);
  const ledgerBatch = `${opts.idPrefix}.${randomUUID().slice(0, 8)}`;
  try {
    const pre = await preliminaryPass(path, provider, size, opts.signal);
    const budget = createOutputBudget({
      budgets: defaultBudgets(await superRoom(ctx, caseId)),
      provenance: ctx.opts.cloudRecordStore ? memberProvenance(opts.idPrefix, acc) : undefined,
      minSeverity: opts.minSeverity,
    });
    const deps: BatchDeps = {
      ctx,
      caseId,
      provider,
      pre,
      budget,
      grader: createPreGrader(opts.preGradeRules ?? null),
      sigma: ctx.opts.sigmaGrader?.snapshot(),
      ledgerBatch,
      opts,
    };
    let stats: () => CloudStreamStats = () => {
      throw new Error("stream not opened");
    };
    for await (const { raw, base } of batches(path, provider, size, (s) => (stats = s))) {
      abortIfCancelled(opts.signal);
      await processBatch(raw, base, deps, acc);
      const s = stats();
      opts.onProgress?.(s.records, s.records + 1); // the total is unknown until the last record
    }
    return await finish(ctx, caseId, provider, pre, deps, acc, stats(), opts);
  } catch (err) {
    // A failed or cancelled import leaves none of its records "seen" (cloudStreamBatch.ts).
    if (acc.committed)
      await ctx.opts.cloudRecordStore?.setBatchesActive(caseId, [ledgerBatch], false).catch(() => {});
    throw err;
  }
}

/**
 * The whole-file path's sourceArtifactHash on every canonical row of the delta (#2337), so a Sigma
 * re-grade can tell a stored file that changed since the import. The reader computes it over the
 * decoded text exactly as the whole-file importers do; it also replaces the hash of "" that a
 * summary built from records (no text) carries. Info/Low rows written to the super-timeline per
 * batch are not stamped: they are written before the last record is read and the hash exists.
 */
function withArtifactHash<T extends { canonical?: CanonicalEventEnvelope }>(
  events: readonly T[],
  hash: string,
): T[] {
  if (!hash) return [...events];
  return events.map((e) =>
    e.canonical
      ? {
          ...e,
          canonical: { ...e.canonical, evidence: { ...e.canonical.evidence, sourceArtifactHash: hash } },
        }
      : e,
  );
}

async function finish(
  ctx: ImportContext,
  caseId: string,
  provider: StreamProvider,
  pre: Preliminary,
  deps: BatchDeps,
  acc: StreamAccumulator,
  stats: CloudStreamStats,
  opts: CloudStreamImportOptions,
): Promise<CloudStreamImportResult> {
  const { individual, aggregates, disclosure: output } = deps.budget.finish();
  const summaries = acc.window.length ? provider.summaries(acc.window, pre) : [];
  const spray =
    provider.kind === "m365" && acc.observations.appended && !opts.skipSummaries
      ? await streamSprayRows(ctx, caseId, opts.idPrefix, acc.observations.earliest)
      : { events: [], truncated: false };
  // MFA fatigue (#2306) across every batch of this import and earlier imports, from the same store.
  const fatigue =
    provider.kind === "m365" && acc.observations.appended
      ? await mfaFatigueRows(ctx, caseId, opts.idPrefix, [], {
          earliest: acc.observations.earliest,
          latest: acc.observations.latest,
        })
      : { events: [], truncated: false };
  const events = [
    ...individual,
    ...aggregates,
    ...applySeverityFloor([...summaries, ...spray.events, ...fatigue.events], opts.minSeverity),
  ];
  const disclosure = buildCloudStreamDisclosure({
    kind: provider.kind,
    format: stats.format,
    gzip: stats.gzip,
    bytesRead: stats.bytesRead,
    bytesDecoded: stats.bytesDecoded,
    records: stats.records,
    duplicates: acc.duplicates,
    conflicts: acc.conflicts,
    unmapped: acc.unmapped,
    repairs: stats.repairs,
    oversizeSkipped: stats.oversizeSkipped,
    preGradeRaised: acc.preGradeRaised,
    output,
    superWritten: acc.superWritten,
    superEvicted: acc.superEvicted,
    iocsDropped: acc.iocsDropped,
    iocsMax: acc.iocsMax,
    summaryWindow: {
      max: acc.windowMax,
      records: acc.window.length,
      truncated: !opts.skipSummaries && stats.records > acc.windowMax,
    },
    sprayHistoryTruncated: spray.truncated,
  });
  const coverage = acc.coverage.map((d) => ({ ...d, uploadId: stats.textHash || d.uploadId }));
  const clauses = describeCloudStreamDisclosure(disclosure);
  const undated = undatedRowsNote(provider.undated?.(pre));
  // An upload whose only output is principal names (#2490) still saves them.
  // A CloudTrail recovery check now a precursor — this import's own super rows included (#2563).
  const promoted = await promoteCrossUploadPrecursors(
    { superTimeline: ctx.opts.superTimelineStore, forensic: ctx.opts.stateStore },
    caseId,
    acc.precursors,
  );
  if (!events.length && !promoted.events.length && !acc.iocs.size && !acc.principalNames.length) {
    const detail = [...clauses, undated.slice(2)].filter(Boolean).join("; ");
    const state = await noteEmptyImport(ctx, caseId, opts, provider.source, stats.records, detail);
    return { state, coverage, disclosure };
  }
  const format = [...acc.formats].join("+") || stats.format;
  const forensicEvents = withArtifactHash(events, stats.textHash).map((e, i) => ({
    ...e,
    id: fatigueEventId(e) ?? `${opts.idPrefix}e${i + 1}`, // stable fatigue id (#2306)
    sources: e.sources?.length ? e.sources : [provider.source],
  }));
  // Each IOC links to the forensic rows that produced it, as the whole-file path does (#2543).
  const iocs = resolveStreamIocLinks([...acc.iocs.values()], forensicEvents);
  const delta = deltaSchema.parse({
    findings: [],
    iocs: iocs.map((c, i) => ({
      id: `${opts.idPrefix}i${i + 1}`,
      type: c.type,
      value: c.value,
      ...(c.note ? { note: c.note } : {}),
      ...(c.extractedFrom ? { extractedFrom: c.extractedFrom } : {}),
    })),
    mitreTechniques: [],
    forensicEvents: [...forensicEvents, ...promoted.events],
    threadsOpened: [],
    threadsClosed: [],
    timelineNote:
      `${provider.source} import (${format}): ${events.length} event(s) from ${stats.records} record(s), ${acc.iocs.size} IOC(s)` +
      sigmaImportNote(deps.sigma, acc.sigmaRows) +
      `; ${clauses.join("; ")}` +
      undated +
      precursorPromotionNote(promoted),
    summary: "",
    ...(acc.principalNames.length ? { principalNames: acc.principalNames } : {}),
  });
  // commitDelta checks the signal INSIDE the lock: a cancel that lands while the import waits for
  // the case (behind another write) merges nothing, and the caller's cleanup deactivates the ledger.
  const state = await commitDelta(ctx, caseId, delta, {
    label: opts.label,
    importedAt: opts.importedAt,
    onProgress: opts.onProgress,
    signal: opts.signal,
  });
  return { state, coverage, disclosure };
}
