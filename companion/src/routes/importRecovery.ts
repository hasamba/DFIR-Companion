import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import { autoTagNewEvents } from "../analysis/taggerAuto.js";
import { gradedIdsOf, isHeldGrade, withoutGradePending } from "../analysis/gradeMark.js";
import { clearGradePending } from "./importSettlePaged.js";
import { runUnlocked } from "./importSettleRows.js";
import { diffIocs } from "../analysis/iocsDiff.js";
import { lastCommittedImportBatch } from "../analysis/importResume.js";
import { parseMinSeverity } from "../analysis/severityFloor.js";
import { addedForensicEvents, diffTimeline } from "../analysis/timelineDiff.js";
import type { ImportBase, RouteContext } from "./context.js";
import { cancellableByParse, isAiDependent } from "./importKinds.js";
import { parseAssetHost } from "../analysis/assetHost.js";
import { runDiskImport } from "./importCloudStream.js";
import { isStreamKind } from "../analysis/ingest/cloudStreamProviders.js";
import { isWindowsLogStreamKind } from "./importWindowsLogStream.js";
import { recordImportRun } from "./importRunRecorder.js";
import { logImportSettled } from "./importSettle.js";
import { createSuperEvictionTally, type SuperEviction } from "../analysis/superTimelineStore.js";
import { evictedInImport } from "./importBase.js";
import { safeKind, createImportDebugRecorder } from "../analysis/importDebug.js";
import { aiExtractionFromDebug } from "../analysis/importMeta.js";
import { decodeImportedText } from "../ingest/decodeText.js";
import { trackRouteImport } from "./importNotify.js";

// The kinds whose streamed first run read the stored file from disk: a resume reads it the same way.
const readsStoredFile = (kind: string): boolean =>
  kind === "plaso" || kind === "velociraptor" || isStreamKind(kind) || isWindowsLogStreamKind(kind); // #2823

const importParametersSchema = z.object({
  kind: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/),
  storedName: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$/),
  sequence: z.number().int().positive(),
  importedAt: z.string().datetime(),
  minSeverity: z.enum(["Critical", "High", "Medium", "Low", "Info"]).nullable(),
  streaming: z.boolean(),
  // The analyst-declared host (#1496); absent on jobs saved before it existed. Re-validated on
  // resume: the saved file is data, and a malformed value is dropped, never applied.
  assetHost: z.string().nullable().optional(),
});

export function registerImportResumeHandler(ctx: RouteContext): void {
  const { store, options } = ctx;
  options.jobManager?.registerResumeHandler(
    "import",
    async (job, signal) => {
      if (!job.caseId || !options.pipeline || !options.stateStore) {
        throw new Error("saved import can no longer reach its case pipeline");
      }
      const caseId = job.caseId;
      const parameters = importParametersSchema.parse(job.parameters);
      // A CSV/log resume is itself an LLM call: AI off = nothing sent to the model (#1806).
      if (isAiDependent(parameters.kind) && !(await ctx.getControl(caseId)).enabled)
        throw new Error("AI is off for this case — turn AI on, then resume this CSV/log import");
      const minSeverity = parseMinSeverity(parameters.minSeverity);
      const declared = parseAssetHost(parameters.assetHost ?? undefined);
      const assetHost = declared.ok ? declared.host : "";
      const warn = async (action: string, error: unknown): Promise<void> => {
        const message = error instanceof Error ? error.message : String(error);
        await options.jobManager?.warn(job.id, `${action}: ${message}`);
      };
      const artifactPath = join(store.importsDir(job.caseId), parameters.storedName);
      // #2144: the case's import section, held from the baseline load through the import-meta and
      // run records. Without it a live import (/import, /push, a Velociraptor ingest) could write
      // between `before` and the diff, and its rows were credited to this resumed file. Taken after
      // the job slot (analysis/importLock.ts order). Released before the case-wide appliers and the
      // re-synthesis, as the live routes do, and in the finally on every failure and cancel path.
      const releaseLock = await ctx.importLock.acquire(caseId);
      let held = true;
      const releaseSection = (): void => {
        if (!held) return;
        held = false;
        releaseLock();
      };
      try {
        const before = await options.stateStore.load(job.caseId);
        const startBatch = Math.max(
          job.lastCheckpoint?.progress.done ?? 0,
          lastCommittedImportBatch(before.timeline, parameters.storedName),
        );
        // This attempt's own recorder (#1736): the kind is the saved one, so nothing was sniffed.
        const recorder = createImportDebugRecorder();
        recorder.detected(parameters.kind, { confident: true, decision: "resumed_job" });
        const base: ImportBase = {
          label: parameters.storedName,
          debug: recorder,
          superEvictions: createSuperEvictionTally(), // this attempt's own (#2816)
          idPrefix: String(parameters.sequence),
          importedAt: parameters.importedAt,
          ...(minSeverity ? { minSeverity } : {}),
          ...(assetHost ? { assetHost } : {}), // the same declaration the interrupted import ran with (#1496)
          ...(signal ? { signal } : {}),
          startBatch,
          onProgress: async (done, total) => {
            // The same status every live import route emits, so a resumed import gets the throttled
            // `[import]` progress line through the shared onAiStatus handler (#1438).
            options.onAiStatus?.(caseId, {
              status: "analyzing",
              phase: "extracting",
              at: new Date().toISOString(),
              detail: `${parameters.kind} import — ${done}/${total}`,
            });
            await options.jobManager?.checkpoint(job.id, {
              done,
              total,
              detail: `${parameters.kind} import — committed batch ${done}/${total}`,
            });
          },
          onParseProgress: (done, total, detail = "reading Windows events") => {
            options.jobManager?.progress(job.id, done, total, detail);
          },
        };

        options.onAiStatus?.(job.caseId, {
          status: "analyzing",
          phase: "extracting",
          at: new Date().toISOString(),
          detail: `resuming ${parameters.kind} import after committed batch ${startBatch}`,
        });
        // #1735: counts and kinds only — the always-on debug log keeps these at any live level.
        const debug = (step: string): void =>
          ctx.serverLogger.debug(
            `[import-debug] ${caseId}: resume kind=${safeKind(parameters.kind)} ${step}`,
            {
              caseId,
            },
          );
        debug(
          `start startBatch=${startBatch} streaming=${parameters.streaming} ` +
            `forensicBefore=${before.forensicTimeline.length}`,
        );
        const outcome = trackRouteImport(ctx, job.caseId, parameters.storedName); // #2978
        try {
          let text: string | undefined;
          // Plaso, a streamed cloud export (#2303) and a streamed Velociraptor JSON Lines file (#2705)
          // re-read the stored file from disk, as the first run did.
          if (parameters.streaming && readsStoredFile(parameters.kind)) {
            await runDiskImport(ctx, parameters.kind, job.caseId, artifactPath, parameters.storedName, base);
          } else {
            text = decodeImportedText(await readFile(artifactPath)); // BOM-aware, as the first run read it
            await ctx.dispatchImport(parameters.kind, job.caseId, text, base);
          }

          const imported = await options.stateStore.load(job.caseId);
          // #2909: the super-timeline copy and the tagger never see the grade mark; a row marked "held"
          // (a Watson paste's) is never offered to this plain tagger.
          const artifactRows = imported.forensicTimeline.filter((event) =>
            event.sourceScreenshots.includes(parameters.storedName),
          );
          const allArtifactEvents = artifactRows.map(withoutGradePending);
          const plainEvents = allArtifactEvents.filter((_e, i) => !isHeldGrade(artifactRows[i]));
          let graded: string[] = [];
          debug(
            `parsed artifactEvents=${allArtifactEvents.length} forensicNow=${imported.forensicTimeline.length}`,
          );
          let superTimelineAddedCount = 0;
          let superTimelineEvicted: SuperEviction | undefined;
          if (options.superTimelineStore) {
            if (allArtifactEvents.length) {
              try {
                const appended = await options.superTimelineStore.appendReporting(
                  job.caseId,
                  allArtifactEvents,
                );
                superTimelineAddedCount = appended.retained;
                superTimelineEvicted = appended.evicted;
                options.onSuperTimeline?.(job.caseId);
              } catch (error) {
                await warn("super-timeline copy failed", error);
              }
            }
          }
          if (plainEvents.length) {
            try {
              const outcome = await autoTagNewEvents(
                {
                  taggerStore: options.taggerStore,
                  tagsStore: options.tagsStore,
                  stateStore: options.stateStore,
                  analysisRunStore: options.analysisRunStore,
                  onTags: options.onTags,
                  onState: options.onState,
                  runStateExclusive: ctx.runStateExclusive,
                  logLine: (message) => ctx.serverLogger.info(message),
                },
                job.caseId,
                plainEvents,
              );
              graded = gradedIdsOf(plainEvents, outcome);
            } catch (error) {
              await warn("automatic tagging failed", error);
            }
          }
          // Only rows the tagger finished on may leave among marked rows; they lose the mark after.
          const finalState = await ctx.demoteForensicForCase(job.caseId, { graded: new Set(graded) });
          await clearGradePending(
            options.stateStore,
            ctx.runStateExclusive ?? runUnlocked,
            job.caseId,
            graded,
          );
          debug(
            `settled superRetained=${superTimelineAddedCount} superEvicted=${superTimelineEvicted?.count ?? 0} ` +
              `forensicAfterDemote=${finalState.forensicTimeline.length}`,
          );
          const timelineDiff = diffTimeline(before.forensicTimeline, finalState.forensicTimeline);
          const iocDiff = diffIocs(before.iocs, finalState.iocs);
          outcome.settled({ timelineDiff, superTimelineAddedCount });
          // This handler settles inline, inside the case's import section, rather than through
          // settleForensicImport: it re-selects the pre-crash batches by stored name, because those
          // rows are already in the forensic timeline but were never settled. The done line is the
          // same one (#1438).
          logImportSettled(job.caseId, parameters.storedName, {
            forensicAdded: timelineDiff.added.length,
            forensicRemoved: timelineDiff.removed.length,
            superAdded: superTimelineAddedCount,
            superEvicted: superTimelineEvicted?.count ?? 0,
            iocsAdded: iocDiff.added.length,
            iocsRemoved: iocDiff.removed.length,
          });
          if (options.importMetaStore) {
            try {
              await options.importMetaStore.record(job.caseId, {
                kind: parameters.kind,
                file: parameters.storedName,
                diff: timelineDiff,
                superTimelineAddedCount,
                superTimelineEvicted: evictedInImport(base, superTimelineEvicted),
                iocsDiff: iocDiff,
                linesIn: text ? text.split(/\r?\n/).length : 0,
                path: parameters.kind === "csv" || parameters.kind === "log" ? "ai" : "deterministic",
                fpPropagation: [],
                truncation: null,
                // #2460: a resume past batch 0 counts only the batches it re-ran, so "kept 0" there
                // would not mean the file yielded nothing — leave the count out rather than mislead.
                ...(startBatch === 0
                  ? {
                      aiExtraction: aiExtractionFromDebug(
                        parameters.kind === "csv" || parameters.kind === "log" ? "ai" : "deterministic",
                        recorder,
                      ),
                    }
                  : {}),
              });
              options.onImportMeta?.(job.caseId);
            } catch (error) {
              await warn("import summary recording failed", error);
            }
          }
          await recordImportRun(ctx, {
            caseId: job.caseId,
            kind: parameters.kind,
            storedName: parameters.storedName,
            startedAt: parameters.importedAt,
            baseline: before,
            minSeverity,
            ...(assetHost ? { assetHost } : {}),
            path: parameters.kind === "csv" || parameters.kind === "log" ? "ai" : "deterministic",
          });
          releaseSection(); // the appliers and re-synthesis run outside the section, as on the live routes
          try {
            await ctx.applyWhitelistToCase(job.caseId);
          } catch (error) {
            await warn("whitelist pass failed", error);
          }
          try {
            await ctx.applyNsrlToCase(job.caseId);
          } catch (error) {
            await warn("known-good hash pass failed", error);
          }
          try {
            await ctx.applyDeobfuscationToCase(job.caseId);
          } catch (error) {
            await warn("deobfuscation pass failed", error);
          }
          ctx.resynthesizeInBackground(job.caseId);
          outcome.finished();
          options.onAiStatus?.(job.caseId, {
            status: "idle",
            at: new Date().toISOString(),
            detail:
              `resumed ${parameters.kind} import committed ` +
              `${addedForensicEvents(finalState.forensicTimeline, timelineDiff).length} new event(s)`,
          });
        } catch (error) {
          const cancelled = signal?.aborted || (error as Error).name === "AbortError";
          // A resumed import fails the way a live one does: the FAILED line and the diagnostics ring
          // entry come from recordImportFailure, once (#1438). A cancel already logged its own line
          // inside dispatchImport / importPlasoFileLogged, so it is not repeated here.
          if (!cancelled) {
            outcome.failed(error);
            ctx.recordImportFailure(job.caseId, parameters.kind, parameters.storedName, error, recorder);
          }
          options.onAiStatus?.(
            job.caseId,
            cancelled
              ? {
                  status: "idle",
                  at: new Date().toISOString(),
                  detail: "import processing cancelled; stored evidence retained",
                }
              : {
                  status: "error",
                  at: new Date().toISOString(),
                  detail: (error as Error).message,
                },
          );
          throw error;
        }
      } finally {
        releaseSection();
      }
    },
    {
      cancellable: (job) => cancellableByParse(job.parameters?.kind, job.parameters?.streaming),
    },
  );
}
