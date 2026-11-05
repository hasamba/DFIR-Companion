// Streaming import of a large cloud export (#2303): M365 UAL / Entra, AWS CloudTrail and GCP /
// Azure Activity files of any size, read from the stored evidence file on disk — never as one
// string — in CLOUD_STREAM_BATCH_RECORDS-record batches.
//
//   pass 1 (preliminary, M365 only) — the whole-file lookups: the object-id → app-id resolver that
//            lets a later consent record name its API, and the mailbox-audit date order;
//   pass 2 — per batch: dedup → map → tagger pre-grade → output budget → write (cloudStreamBatch.ts);
//   end    — the bounded forensic delta (Critical/High individual, budgeted Medium, aggregates,
//            the whole-export summaries over the summary window, spray from the sign-in store) is
//            merged once and then crosses the ordinary settle seam: dual-write → tag → demote.
//
// WHERE THE ROWS GO (ARCHITECTURE.md → "The forensic / super-timeline boundary"). Graded rows reach
// the forensic timeline — the only record the AI reads — through the delta. Info and Low rows are
// appended straight to the super-timeline (the importSandbox precedent) after the tagger's severity
// rules had their chance to raise them, so the AI never reads them and the tagger never misses
// them. Nothing here reads the super-timeline back.

import { randomUUID } from "node:crypto";
import { deltaSchema } from "../responseSchema.js";
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
import { mergeAndSaveDelta, noteEmptyImport } from "./importState.js";
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
  /** Test seams; production uses the named constants. */
  batchRecords?: number;
  summaryRecords?: number;
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
  const acc = newAccumulator(opts.summaryRecords ?? SUMMARY_RECORDS_MAX);
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
    provider.kind === "m365" && acc.observations.appended
      ? await streamSprayRows(ctx, caseId, opts.idPrefix, acc.observations.earliest)
      : { events: [], truncated: false };
  const events = [
    ...individual,
    ...aggregates,
    ...applySeverityFloor([...summaries, ...spray.events], opts.minSeverity),
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
    summaryWindow: {
      max: acc.windowMax,
      records: acc.window.length,
      truncated: stats.records > acc.windowMax,
    },
    sprayHistoryTruncated: spray.truncated,
  });
  const coverage = acc.coverage.map((d) => ({ ...d, uploadId: stats.textHash || d.uploadId }));
  const clauses = describeCloudStreamDisclosure(disclosure);
  const undated = undatedRowsNote(provider.undated?.(pre));
  if (!events.length && !acc.iocs.size) {
    const detail = [...clauses, undated.slice(2)].filter(Boolean).join("; ");
    const state = await noteEmptyImport(ctx, caseId, opts, provider.source, stats.records, detail);
    return { state, coverage, disclosure };
  }
  const format = [...acc.formats].join("+") || stats.format;
  const delta = deltaSchema.parse({
    findings: [],
    iocs: [...acc.iocs.values()].map((c, i) => ({
      id: `${opts.idPrefix}i${i + 1}`,
      type: c.type,
      value: c.value,
    })),
    mitreTechniques: [],
    forensicEvents: events.map((e, i) => ({
      ...e,
      id: `${opts.idPrefix}e${i + 1}`,
      sources: e.sources?.length ? e.sources : [provider.source],
    })),
    threadsOpened: [],
    threadsClosed: [],
    timelineNote:
      `${provider.source} import (${format}): ${events.length} event(s) from ${stats.records} record(s), ${acc.iocs.size} IOC(s)` +
      sigmaImportNote(deps.sigma, acc.sigmaRows) +
      `; ${clauses.join("; ")}` +
      undated,
    summary: "",
  });
  const state = await ctx.withStateLock(caseId, async () => {
    const s = await mergeAndSaveDelta(ctx, caseId, delta, {
      windowSequence: -1,
      timestamp: opts.importedAt,
      sourceScreenshots: [opts.label],
    });
    opts.onProgress?.(1, 1);
    return s;
  });
  return { state, coverage, disclosure };
}
