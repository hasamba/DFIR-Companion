// One batch of a streamed cloud import (#2303): dedup against the case ledger → map with the
// importer's own code → tagger pre-grade → output budget → write. The writes of a batch — its
// super-timeline rows, its sign-in observations, its ledger rows and its source-record relation —
// are made before the next batch is read, so nothing about a row outlives its batch in memory but
// the bounded output itself. The ledger is written per batch so the NEXT batch's classify sees
// these records (a record repeated across batches is a duplicate); if the import then fails, the
// orchestrator marks the import's ledger batch inactive, so a failed import never leaves its
// records "seen" (cloudRecordStore.setBatchesActive — the same switch Undo uses).

import { createHash } from "node:crypto";
import type { ForensicEvent } from "../stateTypes.js";
import type { SiemEvent, SiemIoc, MappedEvent } from "../siemImport.js";
import { createEventAggregator, type AggregateProvenance } from "../eventAggregate.js";
import type { RecordVerdict, SourceRecordMember } from "../cloudRecordStore.js";
import type { StoredAuthObservation } from "../authObservationStore.js";
import type { CloudCoverageDraft } from "../cloudCoverage.js";
import { mergeCoverageDrafts } from "../cloudCoverageMerge.js";
import type { OutputBudget } from "../cloudOutputBudget.js";
import type { PreGrader } from "../cloudStreamPreGrade.js";
import type { SigmaGradingSnapshot } from "../sigmaImportGrade.js";
import type { ImportDebugRecorder } from "../importDebug.js";
import type { ImportContext } from "./importContext.js";
import type { Preliminary, StreamProvider } from "./cloudStreamProviders.js";
import { STREAM_IOCS_MAX } from "../cloudStreamLimits.js";
import { mergePrincipalNames, type PrincipalNameRecord } from "../principalNames.js";
import { emptyPrecursorSeen, withPrecursorRows, type PrecursorSeen } from "./cloudPrecursorPromote.js";

type Row = Record<string, unknown>;

/** Everything a streamed import accumulates across batches — all of it bounded. */
export interface StreamAccumulator {
  coverage: CloudCoverageDraft[];
  iocs: Map<string, SiemIoc>;
  iocsMax: number;
  /** Distinct IOCs past `iocsMax`, counted for the disclosure (never kept). */
  iocsDropped: number;
  formats: Set<string>;
  sigmaRows: number;
  duplicates: number;
  conflicts: number;
  unmapped: number;
  preGradeRaised: number;
  superWritten: number;
  superEvicted: number;
  committed: boolean;
  window: Row[]; // the summary window: the first records of the file, duplicates blanked
  windowMax: number;
  observations: { appended: number; earliest: string; latest: string };
  members: SourceRecordMember[]; // flushed after every batch
  superSeq: number;
  principalNames: PrincipalNameRecord[]; // #2490: every batch's id → name pairs (bounded by the ledger cap)
  precursors: PrecursorSeen; // #2563: the keys on precursor change/check rows, and each key's earliest change
}

export function newAccumulator(windowMax: number, iocsMax = STREAM_IOCS_MAX): StreamAccumulator {
  return {
    coverage: [],
    iocs: new Map(),
    iocsMax,
    iocsDropped: 0,
    formats: new Set(),
    sigmaRows: 0,
    duplicates: 0,
    conflicts: 0,
    unmapped: 0,
    preGradeRaised: 0,
    superWritten: 0,
    superEvicted: 0,
    committed: false,
    window: [],
    windowMax,
    observations: { appended: 0, earliest: "", latest: "" },
    members: [],
    superSeq: 0,
    principalNames: [],
    precursors: emptyPrecursorSeen(),
  };
}

/** The provenance sink the budget's aggregators report to; members wait for the batch's flush. */
export function memberProvenance(idPrefix: string, acc: StreamAccumulator): AggregateProvenance {
  return {
    groupOf: (key) => `${idPrefix}:${createHash("sha256").update(key).digest("hex").slice(0, 24)}`,
    onMember: (group, ref, locator, payloadHash) =>
      acc.members.push({
        group,
        ref,
        ...(payloadHash ? { payloadHash } : {}),
        ...(locator ? { locator } : {}),
      }),
  };
}

export interface BatchDeps {
  ctx: ImportContext;
  caseId: string;
  provider: StreamProvider;
  pre: Preliminary;
  budget: OutputBudget;
  grader: PreGrader;
  sigma?: SigmaGradingSnapshot;
  /**
   * This attempt's ledger batch: the import's id prefix plus an attempt suffix, so a resumed import
   * (same id prefix) never writes into the batch its failed attempt was marked inactive under. Undo
   * claims every attempt's batch by the stored file name.
   */
  ledgerBatch: string;
  opts: {
    label: string;
    idPrefix: string;
    debug?: ImportDebugRecorder;
    onSuperRows?: (rows: ForensicEvent[]) => Promise<void>;
  };
}

/** Rows routed to the super-timeline, in the shape the store keeps (the sandbox precedent). */
function superEvents(rows: MappedEvent[], deps: BatchDeps, acc: StreamAccumulator): ForensicEvent[] {
  const agg = createEventAggregator({ aggregate: false, maxEvents: Infinity });
  for (const r of rows) agg.add(r);
  return agg.finish().events.map((e: SiemEvent) => {
    const { aggKey: _k, count: _c, ...rest } = e;
    return {
      ...rest,
      id: `${deps.opts.idPrefix}s${++acc.superSeq}`,
      relatedFindingIds: [],
      sourceScreenshots: [deps.opts.label],
      sources: e.sources?.length ? e.sources : [deps.provider.source],
    };
  });
}

async function writeSuper(rows: MappedEvent[], deps: BatchDeps, acc: StreamAccumulator): Promise<void> {
  const store = deps.ctx.opts.superTimelineStore;
  if (!store || !rows.length) return;
  const events = superEvents(rows, deps, acc);
  const { retained, evicted } = await store.appendReporting(deps.caseId, events);
  acc.superWritten += retained;
  acc.superEvicted += evicted.count;
  try {
    await deps.opts.onSuperRows?.(events); // their tags (tag-only rules) — best effort, like the settle tagger
  } catch {
    /* tagging never fails an import */
  }
}

async function appendObservations(
  rows: Array<Omit<StoredAuthObservation, "importBatch">>,
  deps: BatchDeps,
  acc: StreamAccumulator,
): Promise<void> {
  const store = deps.ctx.opts.authObservationStore;
  if (!store || !rows.length) return;
  await store.append(
    deps.caseId,
    rows.map((o) => ({ ...o, importBatch: deps.opts.idPrefix })),
  );
  acc.observations.appended += rows.length;
  for (const o of rows) {
    if (!acc.observations.earliest || o.timestamp < acc.observations.earliest)
      acc.observations.earliest = o.timestamp;
    if (o.timestamp > acc.observations.latest) acc.observations.latest = o.timestamp;
  }
}

function noteWindow(
  records: Row[],
  verdicts: readonly RecordVerdict[] | undefined,
  acc: StreamAccumulator,
): void {
  for (let i = 0; i < records.length && acc.window.length < acc.windowMax; i++)
    acc.window.push(verdicts?.[i] === "duplicate" ? {} : records[i]);
}

function noteMapping(m: ReturnType<StreamProvider["map"]>, acc: StreamAccumulator): void {
  acc.coverage = mergeCoverageDrafts(acc.coverage, m.coverage);
  if (m.format !== "empty") acc.formats.add(m.format);
  acc.sigmaRows += m.sigmaRows;
  if (m.principalNames?.length)
    acc.principalNames = mergePrincipalNames(acc.principalNames, m.principalNames);
  for (const ioc of m.iocs) {
    const k = `${ioc.type}|${ioc.value}`;
    if (acc.iocs.has(k)) continue;
    // Over the cap, a distinct IOC is counted (a later batch may repeat it: counted once per batch).
    if (acc.iocs.size < acc.iocsMax) acc.iocs.set(k, ioc);
    else acc.iocsDropped++;
  }
}

/** Route every row; returns the super-bound rows and which records reached the case. */
function routeRows(
  rows: MappedEvent[],
  rowRecords: number[],
  records: Row[],
  deps: BatchDeps,
): { superRows: MappedEvent[]; kept: Set<number> } {
  const superRows: MappedEvent[] = [];
  const kept = new Set<number>();
  rows.forEach((row, i) => {
    const at = rowRecords[i] ?? 0;
    const decision = deps.budget.route(row, deps.provider.facts(records[at] ?? {}));
    if (decision === "below-floor") return;
    kept.add(at);
    if (decision === "super" || decision === "super+aggregate") superRows.push(row);
  });
  return { superRows, kept };
}

/** Process one batch of raw records starting at file index `base`. */
export async function processBatch(
  raw: Row[],
  base: number,
  deps: BatchDeps,
  acc: StreamAccumulator,
): Promise<void> {
  const { ctx, caseId, provider } = deps;
  const records = provider.prepare(raw, deps.pre);
  const ledger = ctx.opts.cloudRecordStore;
  const identities = ledger ? provider.identities(records) : [];
  const verdicts = ledger ? await ledger.classify(caseId, identities) : undefined;
  if (verdicts) {
    acc.duplicates += verdicts.duplicates;
    acc.conflicts += verdicts.conflicts;
  }
  const gate = verdicts ? { identities, verdicts: verdicts.verdicts } : undefined;
  noteWindow(records, verdicts?.verdicts, acc);
  const mapping = provider.map(records, { gate, base, sigma: deps.sigma, debug: deps.opts.debug }, deps.pre);
  noteMapping(mapping, acc);
  const graded = deps.grader.grade(mapping.mapped);
  acc.preGradeRaised += graded.raised;
  acc.precursors = withPrecursorRows(acc.precursors, graded.rows);
  const { superRows, kept } = routeRows(graded.rows, mapping.rowRecords, records, deps);
  const mappedRecords = new Set(mapping.rowRecords);
  acc.unmapped += records.filter(
    (_, i) => !mappedRecords.has(i) && verdicts?.verdicts[i] !== "duplicate",
  ).length;
  await writeSuper(superRows, deps, acc);
  await appendObservations(mapping.signInObservations, deps, acc);
  if (ledger && verdicts) {
    // Seen = a row of the record reached the case (individually, or in an aggregate with its relation).
    const seen = verdicts.verdicts.map((v, i): RecordVerdict => (kept.has(i) ? v : "duplicate"));
    await ledger.commit(caseId, identities, seen, deps.ledgerBatch, deps.opts.label);
    acc.committed = true;
    await ledger.recordMembers(caseId, acc.members);
  }
  acc.members = [];
}
