import { randomUUID } from "node:crypto";
import type { ForensicEvent, InvestigationState, Severity } from "../stateTypes.js";
import { demoteBelowSeverity } from "../forensicGate.js";
import type { MappedEvent, SiemEvent } from "../siemImport.js";
import { aggregateEvents } from "../eventAggregate.js";
import type { SiemIoc } from "../iocSink.js";
import { applySeverityFloor } from "../severityFloor.js";
import { toUtcIso } from "../timeUtc.js";
import { deltaSchema } from "../responseSchema.js";
import { mergeHostRenameRecords, type HostRenameRecord } from "../hostRenameRecord.js";
import { prepareRows, vrBulkInternals, type VelociraptorImportOptions } from "../velociraptorImport.js";
import { isProcessCreateRow } from "../collectorChildren.js";
import { openVelociraptorRowStream, type Row } from "../velociraptorRowStream.js";
import type { ImportContext } from "./importContext.js";

/**
 * The bounded Velociraptor import (#1439): rows in, one batch at a time; events out, one batch at a
 * time; nothing held for the whole file.
 *
 * The whole-file driver (`importVelociraptor`) parses every row, maps every event, aggregates,
 * merges the lot into the in-memory case state and saves; the settle seam then loads, stamps, saves,
 * dual-writes, tags, saves, demotes and saves again. For a 100k-row MFT (~800k MACB events) that
 * is ten live copies of the expansion and four full-table rewrites — 17 GB, and the OOM killer.
 *
 * This driver keeps the ORDER the seam guarantees (merge-all → deterministic tagger → demote,
 * CLAUDE.md §7) but runs it per batch, and turns "write everything to the forensic table, then
 * delete what is Info" into "tag first, then write only what the gate keeps": a row the tagger
 * raises out of Info is kept, exactly as demote-after-tag would have kept it; a row still Info after
 * the tagger goes to the super-timeline only, exactly where demote would have moved it. Every row
 * reaches the super-timeline (the dual-write), so the raw record is as complete as before.
 *
 * What differs from the whole-file driver, on purpose and stated in the timeline note: repeat
 * collapsing (`aggregate`) and PowerShell script-block consolidation are per batch, so a repeat
 * straddling a batch boundary counts as two rows, and fragments more than a batch apart are not
 * re-joined. The event cap (DFIR_MAX_EVENTS) bounds what enters the FORENSIC table — graded rows —
 * not the raw record, whose own cap (DFIR_SUPERTIMELINE_MAX) the super store enforces itself.
 */

// Rows per batch when DFIR_IMPORT_BATCH_ROWS is unset or invalid.
export const DEFAULT_BULK_BATCH_ROWS = 5000;
// Inputs at or above this many bytes take the bulk path when a sink is wired (DFIR_IMPORT_BULK_MIN_MB).
export const DEFAULT_BULK_MIN_MB = 8;
// Most an IOC's extractedFrom list grows to on this path — a hash seen in 100k rows links to the
// first 200; the approximate matcher covers the rest, as it does for a capped event today.
const MAX_EXTRACTED_FROM = 200;
const DEFAULT_MAX_IOCS = 5000;

export function readBulkBatchRows(env: NodeJS.ProcessEnv = process.env): number {
  const n = Number(env.DFIR_IMPORT_BATCH_ROWS);
  return Number.isFinite(n) && n >= 1 ? Math.floor(n) : DEFAULT_BULK_BATCH_ROWS;
}

export function readBulkMinBytes(env: NodeJS.ProcessEnv = process.env): number {
  const raw = env.DFIR_IMPORT_BULK_MIN_MB;
  if (raw === undefined || raw.trim() === "") return DEFAULT_BULK_MIN_MB * 1024 * 1024;
  const n = Number(raw);
  return Number.isFinite(n) && n >= 0 ? Math.floor(n * 1024 * 1024) : DEFAULT_BULK_MIN_MB * 1024 * 1024;
}

/** One batch's tagger pass: the same events back, severity/MITRE raised where a rule matched. */
export interface BatchTagger {
  apply(caseId: string, events: ForensicEvent[]): Promise<{ events: ForensicEvent[]; matched: number }>;
  rulesHash: string;
}

export interface BulkRunSummary {
  label: string;
  path: "bulk";
  mode: "forensic" | "super-only";
  rows: number;
  events: number;
  forensicKept: number;
  superAppended: number;
  batches: number;
  tagged: number;
  rulesHash: string | null;
  startedAt: string;
  finishedAt: string;
}

/**
 * What the bulk driver needs from the composition layer, and nothing else. `appendForensic` and
 * `appendSuper` are the stores' indexed appends (no whole-state load) — `appendForensic` also owns
 * the analyst-work-log guard mergeDelta applies at the forensic door, which lives above this layer;
 * `openTagger` loads the ruleset once per import and returns null when the automatic tagger is off;
 * `forensicMinSeverity` is the case's gate as demote resolves it.
 */
export interface BulkImportSink {
  minBytes: number;
  batchRows: number;
  /** The case database's rollback fence, read before the first batch (#1480). */
  beginRun(caseId: string): Promise<number>;
  /**
   * Remove every row `run` appended above its fence — both timelines in one transaction — then
   * the tagger tags written for them (#1480). Throws only when the rows could not be removed.
   */
  rollback(caseId: string, run: BulkRunHandle): Promise<BulkRollbackSummary>;
  appendForensic(caseId: string, events: ForensicEvent[]): Promise<number>;
  appendSuper(caseId: string, events: ForensicEvent[]): Promise<number>;
  openTagger(caseId: string, mode: "forensic" | "super-only"): Promise<BatchTagger | null>;
  forensicMinSeverity(caseId: string): Promise<Severity>;
  /** With `caseId` the line also lands in the case's own log (#1438). */
  log(msg: string, caseId?: string): void;
  onSuperTimeline?(caseId: string): void;
  onTags?(caseId: string): void;
  recordRun?(caseId: string, summary: BulkRunSummary): Promise<void>;
}

/**
 * What a rollback needs to find one run's rows (#1480): the run's own `importBatchId` — stamped
 * on every event it wrote, the ownership test — and the fence (the case database's highest row id
 * before the run) that bounds the scan to rows appended after the run began. Neither alone is
 * enough: a super-only re-run reuses stable ids (its append dedups rows an earlier run owns), and
 * another run can append after the same fence.
 */
export interface BulkRunHandle {
  importBatchId: string;
  fence: number;
  mode: "forensic" | "super-only";
}

export interface BulkRollbackSummary {
  forensic: number;
  super: number;
  tags: number;
  /** The rows are gone but the tagger tags on them could not be removed — set when that step failed. */
  tagsError?: string;
}

export interface BulkImportOpts {
  label: string;
  /** Forensic ids are `${idPrefix}e${n}`; super-only ids are `${idPrefix}-e${n}` (the stable idBase). */
  idPrefix: string;
  importedAt: string;
  velociraptor?: VelociraptorImportOptions;
  minSeverity?: Severity;
  veloUrl?: string;
  onProgress?: (done: number, total: number) => void;
}

export interface BulkImportResult {
  rows: number;
  events: number;
  forensicKept: number;
  superAppended: number;
  batches: number;
  dropped: number; // rows not represented (below floor / over the forensic cap)
  hostname: string;
  format: string;
  iocs: SiemIoc[];
  eventIdByAggKey: Map<string, string>; // only keys an IOC references — bounded by the IOC sink
  detections: number;
  hostRenames: HostRenameRecord[]; // what this file taught the case (#1495), seeded from what it knew
  collectorHostnames: string[];
  /** For the caller's own commit point: what to roll back if its merge/save fails (#1480). */
  run: BulkRunHandle;
}

/**
 * A failed run leaves nothing behind (#1480). Before this, the batches already flushed stayed in
 * both stores after the FAILED line: the truncated export that is the ordinary failure input
 * throws on its last row, and a retry mints a new id prefix and lands the same rows twice. The
 * rollback removes only this run's rows (see BulkRunHandle) and the tagger tags written for them;
 * what the super cap already evicted to make room is gone before the failure and is not restored.
 * The ORIGINAL error is always the one the caller sees — a rollback failure is logged beside it.
 */
export async function rollbackBulkRun(
  sink: BulkImportSink,
  caseId: string,
  label: string,
  run: BulkRunHandle,
  err: unknown,
  where: string,
): Promise<void> {
  const reason = err instanceof Error ? err.message : String(err);
  try {
    const undone = await sink.rollback(caseId, run);
    sink.log(
      `[import] ${caseId} ${label}: bulk FAILED ${where}: ${reason} — rolled back ${undone.forensic} forensic / ${undone.super} super row(s)` +
        (undone.tags ? `, ${undone.tags} tag(s)` : "") +
        (undone.tagsError
          ? `; tag cleanup FAILED: ${undone.tagsError} — the tagger's tags on the removed rows remain (Clear tagger tags removes them)`
          : ""),
      caseId,
    );
    if (undone.super) sink.onSuperTimeline?.(caseId);
  } catch (rollbackErr) {
    const detail = rollbackErr instanceof Error ? rollbackErr.message : String(rollbackErr);
    sink.log(
      `[import] ${caseId} ${label}: bulk FAILED ${where}: ${reason}; rollback FAILED: ${detail} — the run's rows remain (importBatchId ${run.importBatchId})`,
      caseId,
    );
  }
}

/** True when the sink is wired and the input is big enough to take the bulk path. */
export function bulkPathApplies(sink: BulkImportSink | undefined, text: string): sink is BulkImportSink {
  return !!sink && text.length >= sink.minBytes;
}

// The whole-file driver's SiemEvent → ForensicEvent shape (importVelociraptor + mergeDelta's
// `created` branch), applied per event here because nothing downstream re-shapes a bulk row.
function toForensicEvent(
  e: SiemEvent,
  id: string,
  opts: BulkImportOpts,
  stamp: { importedAt: string; importBatchId: string },
): ForensicEvent {
  const { aggKey: _aggKey, ...rest } = e;
  const endTs = e.endTimestamp !== undefined ? toUtcIso(e.endTimestamp) : undefined;
  return {
    ...rest,
    id,
    timestamp: toUtcIso(e.timestamp),
    ...(endTs !== undefined ? { endTimestamp: endTs } : {}),
    mitreTechniques: [...new Set(e.mitreTechniques)],
    relatedFindingIds: [],
    sourceScreenshots: [opts.label],
    sources: e.sources?.length ? [...new Set(e.sources)] : ["Velociraptor"],
    ...(opts.veloUrl ? { veloUrl: opts.veloUrl } : {}),
    importedAt: stamp.importedAt,
    importBatchId: stamp.importBatchId,
  };
}

// Keep the first `max` entries (Map insertion order) — the same rows `finalizeVrParse`'s
// `.slice(0, maxIocs)` keeps — so the sink cannot grow with the row count.
function trimIocSink(sink: Map<string, SiemIoc>, max: number): void {
  if (sink.size <= max) return;
  let i = 0;
  for (const key of sink.keys()) {
    if (i++ >= max) sink.delete(key);
  }
}

// Resolve, for every IOC in the sink, the aggKeys THIS batch minted ids for. Batch-local lookup, so
// the id map never outlives the batch; only the resolved (aggKey → id) pairs are kept, at most
// MAX_EXTRACTED_FROM per IOC.
function resolveBatchIocLinks(
  sink: Map<string, SiemIoc>,
  batchIdByAggKey: Map<string, string>,
  resolved: Map<string, string>,
): void {
  if (!batchIdByAggKey.size) return;
  for (const ioc of sink.values()) {
    const keys = ioc.sourceAggKeys;
    if (!keys?.length) continue;
    let linked = 0;
    for (const k of keys) {
      if (resolved.has(k)) {
        if (++linked >= MAX_EXTRACTED_FROM) break;
        continue;
      }
      const id = batchIdByAggKey.get(k);
      if (id) {
        resolved.set(k, id);
        if (++linked >= MAX_EXTRACTED_FROM) break;
      }
    }
  }
}

function yieldToLoop(): Promise<void> {
  return new Promise((resolve) => setImmediate(resolve));
}

function mb(bytes: number): string {
  return (bytes / (1024 * 1024)).toFixed(0);
}

interface BatchOutcome {
  events: ForensicEvent[];
  rowsIn: number;
  detections: number;
}

// Normalize + consolidate + map + aggregate ONE batch of rows into forensic-shaped events with ids
// continuing from `nextIndex`. Pure apart from the shared parse context (IOC sink, host tally,
// rename ledger), which the whole-file driver shares across its rows the same way.
function mapBatch(
  rows: Row[],
  vrCtx: ReturnType<typeof vrBulkInternals.newVrCtx>,
  opts: BulkImportOpts,
  mode: "forensic" | "super-only",
  nextIndex: { n: number },
  stamp: { importedAt: string; importBatchId: string },
  batchIdByAggKey: Map<string, string>,
): BatchOutcome {
  const prepared = prepareRows(rows);
  const mapped: MappedEvent[] = [];
  let detections = 0;
  for (const row of prepared) {
    const r = vrBulkInternals.mapRowToEvents(row, vrCtx);
    for (const m of r.events) mapped.push(m);
    detections += r.detections;
  }
  vrCtx.lineage.resolve(); // every spawn was primed before the first batch, so per-batch resolution is complete (#1500)
  const vr = opts.velociraptor ?? {};
  const { events: grouped } = aggregateEvents(mapped, {
    aggregate: mode === "super-only" ? false : vr.aggregate,
    minSeverity: vr.minSeverity,
    maxEvents: Number.MAX_SAFE_INTEGER,
  });
  const floored = applySeverityFloor(grouped, opts.minSeverity);
  const events: ForensicEvent[] = [];
  for (const e of floored) {
    nextIndex.n++;
    const id = mode === "forensic" ? `${opts.idPrefix}e${nextIndex.n}` : `${opts.idPrefix}-e${nextIndex.n}`;
    if (e.aggKey) batchIdByAggKey.set(e.aggKey, id);
    events.push(toForensicEvent(e, id, opts, stamp));
  }
  return { events, rowsIn: rows.length, detections };
}

/**
 * Run the batched import. Returns null when the text is not a shape the row reader streams, so the
 * caller falls back to the whole-file driver. In "forensic" mode the caller must hold the case's
 * state lock for the whole run: a concurrent whole-state save truncates the forensic table to its
 * own array length and would drop rows these batches appended.
 */
export async function runVelociraptorBulk(
  sink: BulkImportSink,
  caseId: string,
  text: string,
  opts: BulkImportOpts,
  mode: "forensic" | "super-only",
): Promise<BulkImportResult | null> {
  const stream = openVelociraptorRowStream(text);
  if (!stream) return null;
  const startedAt = new Date().toISOString();
  // The file's own rename evidence must be complete BEFORE the first batch is attributed and written
  // (#1489): a batch already appended cannot be re-homed when the 6011 row turns up later, so an
  // evidence-only pass streams the rows once more, mapping nothing. This is what keeps the bulk and
  // whole-file drivers byte-for-byte identical on host identity, whatever the row order or batch size.
  const evidence = openVelociraptorRowStream(text);
  if (!evidence) return null;
  const t0 = performance.now();
  const stamp = { importedAt: opts.importedAt, importBatchId: randomUUID() };
  const run: BulkRunHandle = { importBatchId: stamp.importBatchId, fence: await sink.beginRun(caseId), mode };
  const vr = opts.velociraptor ?? {};
  const vrCtx = vrBulkInternals.newVrCtx(vr);
  const maxIocs = vr.maxIocs ?? DEFAULT_MAX_IOCS;
  const forensicBudget = mode === "forensic" ? (vr.maxEvents ?? Number.MAX_SAFE_INTEGER) : 0;
  const gate = mode === "forensic" ? await sink.forensicMinSeverity(caseId) : null;
  const tagger = await sink.openTagger(caseId, mode);
  const nextIndex = { n: 0 };
  const resolvedLinks = new Map<string, string>();
  const totals = {
    rows: 0,
    events: 0,
    forensicKept: 0,
    superAppended: 0,
    batches: 0,
    tagged: 0,
    detections: 0,
    dropped: 0,
  };

  sink.log(
    `[import] ${caseId} ${opts.label}: bulk path (${mode}), ${mb(text.length)} MB, ${stream.format}, batches of ${sink.batchRows} rows`,
    caseId,
  );

  const flush = async (rows: Row[], offset: number, extra?: ForensicEvent[]): Promise<void> => {
    const tb = performance.now();
    const batchIdByAggKey = new Map<string, string>();
    const out = mapBatch(rows, vrCtx, opts, mode, nextIndex, stamp, batchIdByAggKey);
    let events = extra ? [...out.events, ...extra] : out.events;
    totals.detections += out.detections;
    if (tagger && events.length) {
      const tagged = await tagger.apply(caseId, events);
      events = tagged.events;
      totals.tagged += tagged.matched;
    }
    let kept = 0;
    if (mode === "forensic" && events.length && gate) {
      const room = forensicBudget - totals.forensicKept;
      const { kept: graded } = demoteBelowSeverity(events, gate); // the demote pass's own cut
      const keep = room > 0 ? graded.slice(0, room) : [];
      totals.dropped += graded.length - keep.length;
      if (keep.length) kept = await sink.appendForensic(caseId, keep);
    }
    let superAdded = 0;
    if (events.length) {
      superAdded = await sink.appendSuper(caseId, events);
      sink.onSuperTimeline?.(caseId);
    }
    resolveBatchIocLinks(vrCtx.iocSink, batchIdByAggKey, resolvedLinks);
    trimIocSink(vrCtx.iocSink, maxIocs);
    const from = totals.rows + 1;
    totals.rows += out.rowsIn;
    totals.events += events.length;
    totals.forensicKept += kept;
    totals.superAppended += superAdded;
    totals.batches++;
    const rss = process.memoryUsage().rss;
    sink.log(
      `[import] ${caseId} ${opts.label}: batch ${totals.batches} rows ${from}–${totals.rows} → ${events.length} event(s); forensic +${kept}, super +${superAdded} (${Math.round(performance.now() - tb)} ms, rss ${mb(rss)} MB)`,
      caseId,
    );
    // Rows done over an estimate of rows total from the bytes consumed so far — refines each batch.
    const estimate =
      offset > 0 ? Math.max(totals.rows, Math.round((totals.rows * text.length) / offset)) : totals.rows;
    opts.onProgress?.(totals.rows, estimate);
  };

  let batch: Row[] = [];
  let lastOffset = 0;
  try {
    // Best-effort: a malformed file throws here first, but the mapping pass below hits the same row
    // and reports it with its batch context, rolling the run back as before — so this pass only
    // keeps what it learned and lets that pass be the one that fails.
    try {
      let seen = 0;
      // A scratch context for the process rows: the spawn ledger needs the MAPPED row (rule 2c reads
      // the rendered parent and command line), and mapping through the real context would count the
      // row's IOCs and host twice. Only process creations are mapped here (#1500). It shares the
      // real alias map, and the ledger also files every claim under the record's own Computer, so a
      // rename learned after a spawn was primed still lets its children meet it.
      const scratch = { ...vrBulkInternals.newVrCtx(vr), aliases: vrCtx.aliases };
      for (const item of evidence.rows) {
        const rows = prepareRows([item.row]);
        vrCtx.aliases.learn(rows);
        for (const row of rows)
          if (isProcessCreateRow(row))
            vrCtx.lineage.prime(row, vrBulkInternals.mapRowToEvents(row, scratch).events);
        if (++seen % sink.batchRows === 0) await yieldToLoop();
      }
    } catch {
      /* reported by the mapping pass */
    }
    for (const item of stream.rows) {
      batch.push(item.row);
      lastOffset = item.offset;
      if (batch.length >= sink.batchRows) {
        await flush(batch, lastOffset);
        batch = [];
        await yieldToLoop();
      }
    }
    // The rename ledger's Info markers join the tail batch, as finalizeVrParse appends them last.
    const renameEvents = vrCtx.renames.events();
    const tail: ForensicEvent[] = [];
    if (renameEvents.length) {
      const { events } = aggregateEvents(renameEvents, {
        aggregate: false,
        maxEvents: Number.MAX_SAFE_INTEGER,
      });
      for (const e of events) {
        nextIndex.n++;
        const id =
          mode === "forensic" ? `${opts.idPrefix}e${nextIndex.n}` : `${opts.idPrefix}-e${nextIndex.n}`;
        tail.push(toForensicEvent(e, id, opts, stamp));
      }
    }
    if (batch.length || tail.length) await flush(batch, text.length, tail);
  } catch (err) {
    // The batch that failed is the one after the last that flushed; `batch` holds its rows so far.
    const from = totals.rows + 1;
    const to = totals.rows + Math.max(batch.length, 1);
    await rollbackBulkRun(
      sink,
      caseId,
      opts.label,
      run,
      err,
      `at batch ${totals.batches + 1} (rows ${from}–${to})`,
    );
    throw err;
  }
  opts.onProgress?.(totals.rows, totals.rows);

  const hostname = [...vrCtx.hostTally.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] ?? "";
  const finishedAt = new Date().toISOString();
  sink.log(
    `[import] ${caseId} ${opts.label}: bulk done — ${totals.rows} row(s) → ${totals.events} event(s) in ${totals.batches} batch(es); forensic +${totals.forensicKept}, super +${totals.superAppended}, tagger matched ${totals.tagged}${totals.dropped ? `, ${totals.dropped} graded row(s) over the event cap` : ""} (${Math.round((performance.now() - t0) / 1000)} s)`,
    caseId,
  );
  if (totals.tagged > 0) sink.onTags?.(caseId);
  await sink.recordRun?.(caseId, {
    label: opts.label,
    path: "bulk",
    mode,
    rows: totals.rows,
    events: totals.events,
    forensicKept: totals.forensicKept,
    superAppended: totals.superAppended,
    batches: totals.batches,
    tagged: totals.tagged,
    rulesHash: tagger?.rulesHash ?? null,
    startedAt,
    finishedAt,
  });
  return {
    rows: totals.rows,
    events: totals.events,
    forensicKept: totals.forensicKept,
    superAppended: totals.superAppended,
    batches: totals.batches,
    dropped: totals.dropped,
    hostname,
    hostRenames: mergeHostRenameRecords(vrCtx.aliases.records(), vrCtx.renames.records()),
    collectorHostnames: vrCtx.renames.collectorHostnames(),
    format: stream.format,
    iocs: [...vrCtx.iocSink.values()].map((c) => {
      const ids = c.sourceAggKeys
        ? [...new Set(c.sourceAggKeys.map((k) => resolvedLinks.get(k)).filter((x): x is string => !!x))]
        : [];
      const { sourceAggKeys: _keys, ...rest } = c;
      return ids.length ? { ...rest, extractedFrom: ids.slice(0, MAX_EXTRACTED_FROM) } : rest;
    }),
    eventIdByAggKey: resolvedLinks,
    detections: totals.detections,
    run,
  };
}

/**
 * Forensic-mode entry, the drop-in for `importVelociraptor` on a large input. Holds the state lock
 * for the whole run (see runVelociraptorBulk), then records the import's IOCs and timeline note with
 * ONE small whole-state merge — the forensic table holds only graded rows now, so that load is small,
 * and the merge gives the appended rows the same post-merge passes (year re-anchor, correlation,
 * sort) every merged event gets.
 */
export async function importVelociraptorBulk(
  ctx: ImportContext,
  sink: BulkImportSink,
  caseId: string,
  text: string,
  opts: BulkImportOpts,
): Promise<InvestigationState | null> {
  return ctx.withStateLock(caseId, async () => {
    const result = await runVelociraptorBulk(sink, caseId, text, opts, "forensic");
    if (!result) return null;
    const delta = deltaSchema.parse({
      findings: [],
      iocs: result.iocs.map((c, i) => ({
        id: `${opts.idPrefix}i${i + 1}`,
        type: c.type,
        value: c.value,
        ...(c.extractedFrom ? { extractedFrom: c.extractedFrom } : {}),
      })),
      mitreTechniques: [],
      forensicEvents: [],
      threadsOpened: [],
      threadsClosed: [],
      // The case's rename ledger grows through the same merge as every other import's (#1495).
      ...(result.hostRenames.length ? { hostRenames: result.hostRenames } : {}),
      ...(result.collectorHostnames.length ? { collectorHostnames: result.collectorHostnames } : {}),
      timelineNote:
        `Velociraptor import (${result.format}, bulk path: ${result.batches} batch(es) of ${sink.batchRows} rows): ` +
        `${result.events} event(s) from ${result.rows} row(s); ${result.forensicKept} kept in the forensic timeline, ` +
        `${result.superAppended} in the super-timeline` +
        (result.detections > 0 ? `, ${result.detections} detection(s)` : "") +
        (result.dropped > 0 ? `, ${result.dropped} graded row(s) omitted at the event cap` : "") +
        (result.hostname ? ` (host ${result.hostname})` : ""),
      summary: "",
    });
    // The run's commit point (#1480): the appended rows are only kept once this merge has saved.
    let state: InvestigationState;
    try {
      state = await ctx.opts.stateStore.load(caseId);
      state = await ctx.mergeWithAliases(state, delta, {
        windowSequence: -1,
        timestamp: opts.importedAt,
        sourceScreenshots: [opts.label],
      });
      await ctx.opts.stateStore.save(state);
    } catch (err) {
      await rollbackBulkRun(
        sink,
        caseId,
        opts.label,
        result.run,
        err,
        "after the batches, in the final merge",
      );
      throw err;
    }
    ctx.opts.onState?.(state);
    opts.onProgress?.(1, 1);
    return state;
  });
}
