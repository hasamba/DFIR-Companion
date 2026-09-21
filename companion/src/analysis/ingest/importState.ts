import type { PlasoParseResult } from "../plasoImport.js";
import { deltaSchema } from "../responseSchema.js";
import { applySeverityFloor } from "../severityFloor.js";
import { describeFloor } from "./floorNote.js";
import type { InvestigationState, IocProvenance, Severity } from "../stateTypes.js";
import type { HostRenameRecord } from "../hostRenameRecord.js";
import type { SiemEvent } from "../siemImport.js";
import type { SiemIoc } from "../iocSink.js";
import { aggregateEvents } from "../eventAggregate.js";
import {
  passwordSprayPatterns,
  sprayLowSlowHours,
  sprayPatternToMappedEvent,
  sprayThreshold,
  SPRAY_PATTERNS_MAX,
  type SprayCandidate,
} from "../passwordSprayFanout.js";
import type { StoredAuthObservation } from "../authObservationStore.js";
import type { ImportContext } from "./importContext.js";

/**
 * The two shared tails every deterministic importer ends in (#418).
 *
 * They were methods on AnalysisPipeline and members of ImportContext, which meant the AI-tier file
 * carried a hundred lines of pure ingest bookkeeping and every importer's interface advertised two
 * operations it mostly did not use. As free functions over the same ImportContext they read the
 * same at the call site — `noteEmptyImport(ctx, …)` instead of `ctx.noteEmptyImport(…)` — and the
 * code lives where the callers do.
 */

/**
 * The load → merge → save → announce tail all deterministic imports share.
 *
 * Exported because it was not actually being shared: every wrapper in platformImports.ts had this
 * same block pasted into it, so the one sequence that must stay consistent across importers — take
 * the lock, merge under the import's timestamp, save, announce — existed in a dozen copies free to
 * drift apart (#517).
 *
 * `signal` is checked inside the lock: an import cancelled while queued behind another write to the
 * same case must not merge its delta after the analyst gave up on it.
 */
export async function commitDelta(
  ctx: ImportContext,
  caseId: string,
  delta: ReturnType<typeof deltaSchema.parse>,
  opts: {
    label: string;
    importedAt: string;
    onProgress?: (done: number, total: number) => void | Promise<void>;
    signal?: AbortSignal;
    /**
     * Wait for the progress callback before returning. Only the EVTX importer does, because its
     * callback checkpoints the job and the import is not really finished until that lands. Everyone
     * else fires and forgets, and must keep doing so: awaiting would let a rejected checkpoint mark
     * an import failed AFTER its state was already saved, so the retry would re-import it.
     */
    awaitProgress?: boolean;
  },
): Promise<InvestigationState> {
  return ctx.withStateLock(caseId, async () => {
    if (opts.signal?.aborted) {
      throw Object.assign(new Error("import processing cancelled; stored evidence retained"), {
        name: "AbortError",
      });
    }
    let state = await ctx.opts.stateStore.load(caseId);
    state = await ctx.mergeWithAliases(state, delta, {
      windowSequence: -1,
      timestamp: opts.importedAt,
      sourceScreenshots: [opts.label],
    });
    await ctx.opts.stateStore.save(state);
    ctx.opts.onState?.(state);
    const progress = opts.onProgress?.(1, 1);
    if (opts.awaitProgress) await progress;
    return state;
  });
}

/**
 * The IOC rows of a delta from a parser's sink: a stable id per import, and the sink's provenance
 * marker (#1266 client-reported, #1459/#1461 mentioned) carried across. This field whitelist is the
 * only seam between a parser and mergeDelta, and the pasted one-liner it replaces dropped the marker
 * silently (#1471): every Cyber Triage / Plaso / Hayabusa value reached the case unmarked while the
 * parser tests stayed green. platformImports.ts fixed its own copies for #1266; this is the shared one.
 */
export function deltaIocs(
  iocs: readonly SiemIoc[],
  idPrefix: string,
): { id: string; type: SiemIoc["type"]; value: string; provenance?: IocProvenance }[] {
  return iocs.map((c, i) => ({
    id: `${idPrefix}i${i + 1}`,
    type: c.type,
    value: c.value,
    ...(c.provenance ? { provenance: c.provenance } : {}),
  }));
}

// Record an import that parsed cleanly but contributed nothing.
//
// Every deterministic importer guards on "no events (and no IOCs) → return the state unchanged".
// That guard is correct — an empty delta must not be merged — but returning silently meant the
// file was 202-accepted, stored under `imports/`, and left NO trace in the case: the analyst had
// no way to tell "ingested and understood" from "silently dropped". On the northpeak benchmark
// that hid Zeek conn.json contributing zero events out of 75,951 records, the largest artifact in
// the case. A note costs one small timeline row and makes the outcome legible.
//
// `total` is the importer's own parsed-record count, so the note says how much was READ, not just
// that nothing came out — "0 events from 0 records" (wrong format) and "0 events from 75,951
// records" (understood but uninteresting) are very different problems.
/**
 * What the case already knows about its hosts (#1495), for a Windows-log parser to seed its rename
 * map with: the renames earlier imports learned and the collector identities seen. Read before the
 * parse — every import path holds the per-case import lock, so no other import can move the ledger
 * between this read and the merge. A missing case or state yields nothing, never an error here.
 */
export async function knownHostIdentity(
  ctx: ImportContext,
  caseId: string,
): Promise<{ knownRenames: HostRenameRecord[]; collectorHostnames: string[] }> {
  try {
    const state = await ctx.opts.stateStore.load(caseId);
    return { knownRenames: state.hostRenames ?? [], collectorHostnames: state.collectorHostnames ?? [] };
  } catch {
    return { knownRenames: [], collectorHostnames: [] };
  }
}

/** The ledger fields a Windows-log parse result hands to its delta (#1495); absent when empty. */
export function hostIdentityDelta(parsed: {
  hostRenames: readonly HostRenameRecord[];
  collectorHostnames: readonly string[];
}): { hostRenames?: HostRenameRecord[]; collectorHostnames?: string[] } {
  return {
    ...(parsed.hostRenames.length ? { hostRenames: [...parsed.hostRenames] } : {}),
    ...(parsed.collectorHostnames.length ? { collectorHostnames: [...parsed.collectorHostnames] } : {}),
  };
}

export async function noteEmptyImport(
  ctx: ImportContext,
  caseId: string,
  opts: { label: string; importedAt: string; onProgress?: (done: number, total: number) => void },
  kind: string,
  total: number,
  // What the importer could still say about the upload's shape (a memory export that holds zero
  // rows, a layout not read) — the analyst sees it even when a severity floor left no event.
  // Rendered as a "; "-joined clause after the base sentence, the same shape the non-empty
  // notes use for the same text (#1300) — never a parenthetical, which nested a second em-dash
  // and read as an aside rather than the cause.
  detail?: string,
): Promise<InvestigationState> {
  const delta = deltaSchema.parse({
    findings: [],
    iocs: [],
    mitreTechniques: [],
    forensicEvents: [],
    threadsOpened: [],
    threadsClosed: [],
    timelineNote:
      `${kind} import: no events from ${total} record(s) — nothing added to the case` +
      (detail ? `; ${detail}` : ""),
    summary: "",
  });
  return commitDelta(ctx, caseId, delta, opts);
}

// Shared tail of both Plaso entry points: apply the severity floor, build the delta and merge it
// into the case state. (Keeping this in one place means the in-memory and streaming importers
// produce identical timeline rows / IOCs / notes.)
export async function persistPlasoParsed(
  ctx: ImportContext,
  caseId: string,
  parsedRaw: PlasoParseResult,
  opts: {
    label: string;
    idPrefix: string;
    importedAt: string;
    minSeverity?: Severity;
    onProgress?: (done: number, total: number) => void;
  },
): Promise<InvestigationState> {
  const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
  if (parsed.events.length === 0 && parsed.iocs.length === 0)
    return noteEmptyImport(ctx, caseId, opts, "Plaso", parsed.total);

  const raw = {
    findings: [],
    iocs: deltaIocs(parsed.iocs, opts.idPrefix),
    mitreTechniques: [],
    forensicEvents: parsed.events.map((e, i) => ({
      ...e,
      id: `${opts.idPrefix}e${i + 1}`,
      sources: e.sources?.length ? e.sources : ["Plaso"],
    })),
    threadsOpened: [],
    threadsClosed: [],
    timelineNote:
      `Plaso import (${parsed.format}): ${parsed.events.length} event(s) from ${parsed.total} row(s)` +
      describeFloor(parsedRaw.events.length, parsed.events.length) +
      (parsed.groups > parsed.kept ? `, ${parsed.groups - parsed.kept} group(s) over the cap` : "") +
      `, ${parsed.iocs.length} IOC(s)`,
    summary: "",
  };

  return commitDelta(ctx, caseId, deltaSchema.parse(raw), opts);
}

// Cross-upload password-spray detection (#1104, second half of 930.5 / 931.3). Shared by
// importEcar and importM365 so the query-window bound, the per-batch dominance filter (never
// double-report an episode a within-upload row already explains), and the truncation-disclosure
// rule live in exactly one place.
//
// Returns [] whenever ctx.opts.authObservationStore is absent (minimal/test wirings) or this
// upload's own parse produced no spray candidates at all — today's within-upload-only behavior,
// unchanged.
export interface CrossUploadSprayResult {
  events: SiemEvent[];
  // Set when this batch's own earliest event already predates the store's retention window at
  // upload time (#1286). `AuthObservationStore.pruneIfDue` deletes by WALL-CLOCK age
  // (`Date.now() - retentionHours`), not by any batch's own anchor, so observations this stale
  // are pruned within the next throttled prune (≤1h) regardless of when they were written —
  // they cannot be cross-matched now, and this batch's own append() below cannot survive to be
  // cross-matched by a LATER upload either. Non-empty only when that condition holds, so a caller
  // can fold it into the timeline note it already emits; empty string otherwise.
  retentionNote: string;
}

export async function crossUploadSprayRows(
  ctx: ImportContext,
  caseId: string,
  opts: { idPrefix: string; importedAt: string },
  sprayCandidates: SprayCandidate[],
  meta: { source: string; importer: string; mappingVersion: string },
): Promise<CrossUploadSprayResult> {
  const store = ctx.opts.authObservationStore;
  if (!store || !sprayCandidates.length) return { events: [], retentionNote: "" };

  const withBatch: SprayCandidate[] = sprayCandidates.map((c) => ({ ...c, importBatch: opts.idPrefix }));

  // The bound is the SMALLER of the detector's own slow-spray window and the store's retention —
  // never the larger. A wider bound would load the whole retention window into every import for a
  // detector whose own episodes never span more than sprayLowSlowHours() anyway.
  const windowHours = Math.min(sprayLowSlowHours(), store.retentionHours());
  // Anchored on this BATCH's OWN earliest event time, never on `opts.importedAt` (server wall-clock
  // at request time) or `Date.now()` (#1237): `store.queryWindow` filters stored observations by
  // their own event timestamp, so anchoring on import time silently misses every prior observation
  // once an upload's events are older than `windowHours` relative to NOW — the common case in DFIR,
  // where uploads are almost always of past activity with arbitrary lag (a 3-day-old export, a
  // re-upload, any batch processed days after capture). Anchoring on the batch's own earliest event
  // time keeps the window centered on the evidence, exactly the case the store's own header sells:
  // a low-and-slow spray uploaded in daily batches is still detected however stale the upload is.
  const batchTimestampsMs = withBatch.map((c) => Date.parse(c.timestamp)).filter((ms) => Number.isFinite(ms));
  const importedAtMs = Date.parse(opts.importedAt);
  const anchorMs = batchTimestampsMs.length
    ? Math.min(...batchTimestampsMs)
    : Number.isFinite(importedAtMs)
      ? importedAtMs
      : Date.now();
  const sinceIso = new Date(anchorMs - windowHours * 3_600_000).toISOString();

  // Retention-age disclosure (#1286): if this batch's own earliest event already predates the
  // retention horizon, cross-upload matching for it is effectively dead — see CrossUploadSprayResult.
  // The wording is one-directional on purpose (#1299): the query below still RUNS for this batch
  // and can match prior observations of the same age that survived the throttled prune, so the
  // note must not say it "could not run". What is lost is the other direction — a LATER upload
  // cannot reach this batch once the wall-clock prune removes it.
  const retentionHoursValue = store.retentionHours();
  const retentionExceeded = anchorMs < Date.now() - retentionHoursValue * 3_600_000;
  const retentionNote = retentionExceeded
    ? `cross-upload spray matching for this batch is limited — its evidence predates the ${retentionHoursValue}h auth-observation retention window, so later uploads cannot be correlated with it`
    : "";

  // Query BEFORE appending this upload's own observations, so `combined` is built by hand instead
  // of writing then reading the same rows back (no round trip, and no risk of the query cap
  // dropping the candidates this very call is about to write).
  const { observations, truncated } = await store.queryWindow(caseId, sinceIso);
  const priorCandidates: SprayCandidate[] = observations.map((o) => ({
    timestamp: o.timestamp,
    account: o.account,
    sourceIp: o.sourceIp,
    hostOrTenant: o.hostOrTenant,
    outcome: o.outcome,
    locator: o.locator,
    importBatch: o.importBatch,
  }));

  const threshold = sprayThreshold();
  const crossPatterns = passwordSprayPatterns([...priorCandidates, ...withBatch])
    // A combined episode is reported ONLY when no single batch's own count already meets the
    // threshold — otherwise the within-upload pass (unchanged, runs separately) already emitted a
    // row for it, and this one would be a duplicate with a different aggKey (an earlier `start`
    // pulled back by the older stored observations).
    .filter((p) => p.importBatches.length > 1 && Math.max(...Object.values(p.accountsByBatch)) < threshold)
    .slice(0, SPRAY_PATTERNS_MAX)
    .map((p) => sprayPatternToMappedEvent(p, { ...meta, crossUpload: true, truncatedHistory: truncated }));
  // aggregateEvents does the MappedEvent -> SiemEvent conversion (mitre -> mitreTechniques,
  // sourceRecordId bookkeeping) every other importer output goes through before it can enter a
  // delta — sprayPatternToMappedEvent alone is not that shape. No minSeverity here: the caller
  // applies the floor once, to the combined [...sourceEvents, ...crossRows] array.
  const crossRows = aggregateEvents(crossPatterns, { maxEvents: SPRAY_PATTERNS_MAX + 1 }).events;

  const toStore: StoredAuthObservation[] = withBatch.map((c) => ({
    timestamp: c.timestamp,
    account: c.account,
    sourceIp: c.sourceIp,
    hostOrTenant: c.hostOrTenant,
    outcome: c.outcome,
    locator: c.locator,
    importer: meta.importer,
    importBatch: c.importBatch ?? opts.idPrefix,
  }));
  await store.append(caseId, toStore);

  return { events: crossRows, retentionNote };
}
