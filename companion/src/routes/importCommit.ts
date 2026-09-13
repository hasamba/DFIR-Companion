import type { RouteContext } from "./context.js";
import type { CaseStore } from "../storage/caseStore.js";
import type { InvestigationState, Severity } from "../analysis/stateTypes.js";
import { logActivity } from "../analysis/activityLog.js";
import { beginImportSection, type ImportSection } from "./importSection.js";
import { settleForensicImport, type SettleDeps } from "./importSettle.js";
import { recordImportRun } from "./importRunRecorder.js";
import { FalsePositiveStore } from "../analysis/falsePositive.js";
import { matchFpPropagation } from "../analysis/fpPropagation.js";
import type { ManifestValue } from "../analysis/analysisRunTypes.js";

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
  /** The importer call. Runs inside the section; a throw is recorded as an import failure. */
  run: () => Promise<unknown>;
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

  // Both assigned by run(), once this import owns the case. The section is taken INSIDE the
  // background task so the 202 never waited on another import, and released in the `finally`.
  let stateBefore: InvestigationState | null = null;
  let section: ImportSection | null = null;
  const run = async (): Promise<void> => {
    section = await beginImportSection(importLock, caseId, options.stateStore);
    stateBefore = section.stateBefore;
    await commit.run();
  };

  void run()
    .then(async () => {
      if (settleDeps && stateBefore) {
        // The seam is REQUIRED processing, not bookkeeping: a failure here leaves Info rows in the
        // forensic timeline and none in the super-timeline — the defect these routes existed with.
        // So it is not caught; it reaches the failure handler below. Only the record, the activity
        // line and the checkpoint after it are best-effort.
        const settled = await settleForensicImport(settleDeps, caseId, stateBefore);
        const { timelineDiff: tDiff, iocsDiff: iDiff } = settled;
        options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() });
        try {
          // Proactive FP-pattern propagation (#15b), as the generic route does it: do the NEW
          // forensic events repeat a pattern the analyst already marked a false positive? Surface a
          // one-click bulk-mark suggestion on the import banner; never auto-mark.
          let fpPropagation: Awaited<ReturnType<typeof matchFpPropagation>> = [];
          try {
            const beforeIds = new Set(stateBefore.forensicTimeline.map((e) => e.id));
            const newEvents = settled.state.forensicTimeline.filter((e) => !beforeIds.has(e.id));
            if (newEvents.length) {
              const markers = await new FalsePositiveStore(store).load(caseId);
              fpPropagation = matchFpPropagation(newEvents, markers);
            }
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
              (commit.activitySuffix ?? ""),
          });
          // #76: snapshot the pre-import state for undo — only when the import changed something,
          // so a no-op re-import does not pile up dead levels.
          if (tDiff.added.length || tDiff.removed.length || iDiff.added.length || iDiff.removed.length) {
            await pushImportCheckpoint(caseId, stateBefore, label);
          }
        } catch {
          /* non-fatal — the import is merged and settled; only its bookkeeping failed */
        }
      } else {
        options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() });
      }
      await recordImportRun(ctx, {
        caseId,
        kind,
        storedName,
        startedAt: commit.importedAt,
        stateBefore,
        minSeverity: commit.minSeverity,
        path: commit.path,
        parameters: commit.parameters,
      });
      resynthesizeInBackground(caseId);
    })
    .catch((err) => {
      recordImportFailure(caseId, kind, storedName, err);
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
    });
}
