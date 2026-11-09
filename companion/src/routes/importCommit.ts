import type { RouteContext } from "./context.js";
import type { CaseStore } from "../storage/caseStore.js";
import type { Severity } from "../analysis/stateTypes.js";
import { logActivity } from "../analysis/activityLog.js";
import { beginImportSection, type ImportSection } from "./importSection.js";
import type { ImportBaseline } from "../analysis/importBaseline.js";
import { settleForensicImport, type SettleDeps } from "./importSettle.js";
import { ImportJournalLostError } from "./importSettleDiff.js";
import { recordImportRun } from "./importRunRecorder.js";
import { FalsePositiveStore } from "../analysis/falsePositive.js";
import { matchFpPropagation } from "../analysis/fpPropagation.js";
import type { ManifestValue } from "../analysis/analysisRunTypes.js";
import { formatImportCancelled, formatImportMerged, formatImportStart } from "../logging/importLog.js";
import { abortIfCancelled, ImportCancelledError } from "../analysis/ingest/importState.js";
import { safeKind, createImportDebugRecorder, type ImportDebugRecorder } from "../analysis/importDebug.js";
import { emitImportDebug } from "./importDebugEmit.js";
import { admitDedicatedImport, type DedicatedImportJob } from "./importCommitJob.js";

/**
 * The commit spine every dedicated `import-*` route runs after it has answered 202 (#956).
 *
 * The generic `/import` route always did this: take the case's import section (lock + pre-import
 * snapshot, routes/importSection.ts), run the importer, cross the forensic / super-timeline seam
 * (routes/importSettle.ts — dual-write, tag, demote), then the import record, the activity line,
 * the undo checkpoint and the analysis-run record, then resynthesis. The 22 dedicated routes did
 * NOT: each called its importer and resynthesized, so an Info row imported through `/import-siem`
 * stayed in the forensic timeline where the model reads it, never reached the super-timeline,
 * left no import record, and ran unlocked beside whatever else the case was importing. #962 moved
 * `/import-leapp` onto the spine by copying the generic route's tail; this is that tail, once, so
 * a route cannot half-run it.
 *
 * What stays with the route: the body/option parsing, the preview parse and its 400s, the
 * evidence-first persist (persistImportEvidence below) and the 202 body — those are per format.
 *
 * Not on this spine (the generic route runs them, best-effort, after the record): whitelist and
 * NSRL auto-marking and command-line deobfuscation. They are post-import enrichments, not part of
 * the seam, and a dedicated route never ran them either.
 */
export interface DedicatedImportCommit {
  caseId: string;
  /** The import kind, as `dispatchImport` names it — stamped on import-meta and the run record. */
  kind: string;
  storedName: string;
  importedAt: string;
  /** Line count of the artifact as stored (import-meta `linesIn`). */
  linesIn: number;
  /** "ai" when the importer is an LLM call (CSV / log), "deterministic" otherwise. */
  path: "ai" | "deterministic";
  minSeverity?: Severity;
  /** Appended to the activity line after the counts, e.g. ", 3 undated". */
  activitySuffix?: string;
  /**
   * The route's own importer options, keyed by importer (`{ thor: thorOpts }`), for the run
   * manifest. Build the value with `importerParameter` so an `undefined` option reads as null.
   */
  parameters?: Record<string, ManifestValue>;
  /**
   * The importer call. Runs inside the section; a throw is recorded as an import failure. It gets
   * this attempt's debug recorder (#1736) and the job's Cancel (#2425) as `{ debug, signal }`, to
   * spread into the importer's options. A spread, not named properties, so an importer that does not
   * read one of them still type-checks. An AbortError thrown by the importer is a cancel, not a failure.
   */
  run: (withDebug: { debug: ImportDebugRecorder; signal?: AbortSignal }) => Promise<unknown>;
}

/**
 * Persist the raw artifact as evidence and append the audit line — the evidence-first step every
 * route takes BEFORE it answers 202, so a crash in the importer never loses what the analyst sent.
 * The stored name keeps the original extension (.log / .txt / .json …) so the artifact round-trips
 * through the evidence endpoint with the right content-type.
 */
export async function persistImportEvidence(
  store: CaseStore,
  caseId: string,
  input: { text: string; originalName: string; fallbackName: string; rows: number },
): Promise<{ seq: number; storedName: string; importedAt: string }> {
  const seq = await store.nextImportSeq(caseId);
  const safeName = input.originalName.replace(/[^\w.\-]+/g, "_").slice(0, 80) || input.fallbackName;
  const storedName = `${String(seq).padStart(4, "0")}_${safeName}`;
  const importedAt = new Date().toISOString();
  await store.saveImport(caseId, storedName, input.text);
  await store.appendImport(caseId, {
    caseId,
    sequenceNumber: seq,
    importedAt,
    filename: storedName,
    originalName: input.originalName,
    rows: input.rows,
    bytes: Buffer.byteLength(input.text, "utf8"),
  });
  return { seq, storedName, importedAt };
}

/**
 * An importer options object as a manifest value: a JSON round-trip drops `undefined` fields and
 * anything that is not data, and an absent options object records as null, never as omitted.
 */
export function importerParameter(opts: object | undefined): ManifestValue {
  return opts === undefined ? null : (JSON.parse(JSON.stringify(opts)) as ManifestValue);
}

/** Fire-and-forget: the route has already answered 202. Every outcome is reported through status. */
export function commitDedicatedImport(
  ctx: RouteContext,
  settleDeps: SettleDeps | null,
  commit: DedicatedImportCommit,
): void {
  const {
    store,
    options,
    importLock,
    recordImportFailure,
    recordAiError,
    pushImportCheckpoint,
    resynthesizeInBackground,
  } = ctx;
  const { caseId, kind, storedName } = commit;
  const label = `${kind} (${storedName})`;
  // One recorder per attempt (#1736). A dedicated route names its format, so nothing was sniffed.
  const debug = createImportDebugRecorder();
  debug.detected(kind, { confident: true, decision: "explicit_route" });

  // Both assigned by run(), once this import owns the case. The section is taken INSIDE the
  // background task so the 202 never waited on another import, and released in the `finally`.
  let baseline: ImportBaseline | null = null;
  let section: ImportSection | null = null;
  // #2407: a job row, so the import is visible in the Jobs panel and counted as "the case is
  // busy". Admission comes BEFORE the section, as on the generic route: with the durable ledger's
  // one-job-per-case slot the import queues behind other case work instead of running beside it.
  const job: DedicatedImportJob = admitDedicatedImport(ctx, commit);
  const signal = job.signal;
  // #2425: set when a cancel landed while the importer ran. Whatever it had already saved (CSV / log
  // batches) is settled below like any import — so no row skips the tagger — and recorded, so Undo
  // removes it. When nothing landed, the import is reported as cancelled instead.
  let partial = false;
  let runStarted = Date.now();
  // The analyst's decision, not a failure: one "cancelled" line, no failure-ring entry. fail() is a
  // no-op on the cancelled row, and settles the row of a case deleted mid-import (#1831).
  const reportCancelled = async (err: unknown): Promise<void> => {
    await job.fail(err);
    ctx.serverLogger.info(formatImportCancelled(caseId, storedName, Date.now() - runStarted), { caseId });
    emitImportDebug(caseId, debug, "cancelled");
    options.onAiStatus?.(caseId, {
      status: "idle",
      at: new Date().toISOString(),
      detail: "import processing cancelled; stored evidence retained",
    });
  };
  const run = async (): Promise<void> => {
    if (!(await job.admitted())) throw job.stopped();
    runStarted = Date.now();
    section = await beginImportSection(importLock, caseId, options.stateStore, {
      incomingEvents: commit.linesIn,
    });
    baseline = section.baseline;
    abortIfCancelled(signal); // cancelled while it waited for the section: nothing ran
    // #1438: the start line is the last thing in the log before a crash mid-parse; the merged line
    // carries the wall time. The FAILED line is recordImportFailure's (the `.catch` below), once.
    ctx.serverLogger.info(formatImportStart({ caseId, label: storedName, kind, lines: commit.linesIn }), {
      caseId,
    });
    // #1735: counts and kinds only, never file or row content — the always-on debug log keeps it.
    ctx.serverLogger.debug(
      `[import-debug] ${caseId}: commit kind=${safeKind(kind)} path=${commit.path} linesIn=${commit.linesIn} ` +
        `forensicBefore=${section.baseline?.outline.ids.length ?? "unknown"} minSeverity=${commit.minSeverity ?? "none"}`,
      { caseId },
    );
    const startedAt = Date.now();
    try {
      await commit.run({ debug, ...(signal ? { signal } : {}) });
    } catch (err) {
      // A cancel can surface as a throw mid-import (an aborted model call) after earlier batches
      // were saved. Not a failure: what landed is settled below. An importer that stopped before
      // merging anything (ImportCancelledError) has nothing to settle; anything else still fails.
      if (!signal?.aborted || err instanceof ImportCancelledError) throw err;
    }
    partial = job.closeCancel();
    ctx.serverLogger.info(formatImportMerged(caseId, storedName, Date.now() - startedAt), { caseId });
  };

  void run()
    .then(async () => {
      if (settleDeps && baseline) {
        // The seam is REQUIRED processing, not bookkeeping: a failure here leaves Info rows in the
        // forensic timeline and none in the super-timeline — the defect these routes existed with.
        // So it is not caught; it reaches the failure handler below. Only the record, the activity
        // line and the checkpoint after it are best-effort.
        const settled = await settleForensicImport(settleDeps, caseId, baseline, storedName);
        const { timelineDiff: tDiff, iocsDiff: iDiff } = settled;
        ctx.serverLogger.debug(
          `[import-debug] ${caseId}: commit kind=${safeKind(kind)} settled forensicNow=${settled.forensicCount} ` +
            `superRetained=${settled.superTimelineAddedCount} superEvicted=${settled.superTimelineEvicted?.count ?? 0}`,
          { caseId },
        );
        const changed =
          tDiff.added.length || tDiff.removed.length || iDiff.added.length || iDiff.removed.length;
        if (partial && !changed && !settled.superTimelineAddedCount)
          return reportCancelled(new Error("import cancelled before it wrote anything"));
        options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() });
        try {
          // Proactive FP-pattern propagation (#15b), as the generic route does it: do the NEW
          // forensic events repeat a pattern the analyst already marked a false positive? Surface a
          // one-click bulk-mark suggestion on the import banner; never auto-mark.
          let fpPropagation: Awaited<ReturnType<typeof matchFpPropagation>> = [];
          try {
            // #1874: this import's rows are read only when there is a marker to match them against.
            const markers = await new FalsePositiveStore(store).load(caseId);
            if (markers.length) fpPropagation = matchFpPropagation(await settled.addedEvents(), markers);
          } catch {
            /* non-fatal — propagation is a suggestion, never blocks the import */
          }
          if (options.importMetaStore) {
            // Cap-hit truncation (#10 trigger b): consume what the log importer stashed for this
            // case (null for every other kind). Consuming here, not only on the generic route, is
            // what keeps a capped `/import-log` from billing its truncation to the next import.
            const truncation = options.pipeline?.consumeImportTruncation?.(caseId) ?? null;
            await options.importMetaStore.record(caseId, {
              kind,
              file: storedName,
              diff: tDiff,
              superTimelineAddedCount: settled.superTimelineAddedCount,
              superTimelineEvicted: settled.superTimelineEvicted,
              iocsDiff: iDiff,
              linesIn: commit.linesIn,
              path: commit.path,
              fpPropagation,
              truncation,
            });
            options.onImportMeta?.(caseId);
          }
          void logActivity(options.activityLogStore, options.onActivity, caseId, {
            category: "import",
            action: "import",
            detail:
              `${label} — +${tDiff.added.length} event(s), +${iDiff.added.length} IOC(s)` +
              (commit.activitySuffix ?? "") +
              (partial ? " — cancelled; kept what was imported before the cancel" : ""),
          });
          // #76: snapshot the pre-import state for undo — only when the import changed something,
          // so a no-op re-import does not pile up dead levels.
          if (changed) {
            await pushImportCheckpoint(caseId, baseline, label);
          }
        } catch {
          /* non-fatal — the import is merged and settled; only its bookkeeping failed */
        }
      } else {
        if (partial) return reportCancelled(new Error("import cancelled"));
        ctx.serverLogger.debug(
          `[import-debug] ${caseId}: commit kind=${safeKind(kind)} not settled (no settle deps)`,
          {
            caseId,
          },
        );
        options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() });
      }
      await recordImportRun(ctx, {
        caseId,
        kind,
        storedName,
        startedAt: commit.importedAt,
        baseline,
        minSeverity: commit.minSeverity,
        path: commit.path,
        parameters: commit.parameters,
      });
      await job.finish();
      resynthesizeInBackground(caseId);
      // Last, so a settle or record failure above reports this attempt as failed, not succeeded.
      emitImportDebug(caseId, debug, "succeeded");
    })
    .catch(async (err) => {
      // Never admitted (its case was deleted while it queued): nothing ran, so nothing failed.
      if (job.isStopped(err)) return;
      // #2425: cancelled before anything of it reached the case (while it waited for the section, or
      // the importer stopped before its merge / rolled its batches back). Only when the job's own
      // signal fired: an AbortError from elsewhere (a provider timeout) is a real failure.
      if ((err as Error)?.name === "AbortError" && signal?.aborted) return reportCancelled(err);
      // A batched importer cancelled before its first batch, into a case that had no state yet:
      // nothing was written, so the settle finds no journal to read. Still a cancel, not a failure.
      if (partial && err instanceof ImportJournalLostError && baseline?.empty) return reportCancelled(err);
      await job.fail(err);
      recordImportFailure(caseId, kind, storedName, err, debug);
      recordAiError(caseId, "import", err);
      options.onAiStatus?.(caseId, {
        status: "error",
        at: new Date().toISOString(),
        detail: (err as Error).message,
      });
    })
    .finally(() => {
      // Unconditional: a section left held would wedge every later import for this case.
      section?.release();
      section = null;
      job.release(); // after the section: no other case work starts before this import is done
    });
}
