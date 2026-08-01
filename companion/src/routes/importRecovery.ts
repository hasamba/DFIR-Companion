import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import { autoTagNewEvents } from "../analysis/taggerAuto.js";
import { diffIocs } from "../analysis/iocsDiff.js";
import { lastCommittedImportBatch } from "../analysis/importResume.js";
import { parseMinSeverity } from "../analysis/severityFloor.js";
import { addedForensicEvents, diffTimeline } from "../analysis/timelineDiff.js";
import type { ImportBase, RouteContext } from "./context.js";
import { recordImportRun } from "./importRunRecorder.js";

const importParametersSchema = z.object({
  kind: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/),
  storedName: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$/),
  sequence: z.number().int().positive(),
  importedAt: z.string().datetime(),
  minSeverity: z.enum(["Critical", "High", "Medium", "Low", "Info"]).nullable(),
  streaming: z.boolean(),
});

export function registerImportResumeHandler(ctx: RouteContext): void {
  const { store, options } = ctx;
  options.jobManager?.registerResumeHandler(
    "import",
    async (job, signal) => {
      if (!job.caseId || !options.pipeline || !options.stateStore) {
        throw new Error("saved import can no longer reach its case pipeline");
      }
      const parameters = importParametersSchema.parse(job.parameters);
      const minSeverity = parseMinSeverity(parameters.minSeverity);
      const warn = async (action: string, error: unknown): Promise<void> => {
        const message = error instanceof Error ? error.message : String(error);
        await options.jobManager?.warn(job.id, `${action}: ${message}`);
      };
      const artifactPath = join(store.importsDir(job.caseId), parameters.storedName);
      const before = await options.stateStore.load(job.caseId);
      const startBatch = Math.max(
        job.lastCheckpoint?.progress.done ?? 0,
        lastCommittedImportBatch(before.timeline, parameters.storedName),
      );
      const base: ImportBase = {
        label: parameters.storedName,
        idPrefix: String(parameters.sequence),
        importedAt: parameters.importedAt,
        ...(minSeverity ? { minSeverity } : {}),
        ...(signal ? { signal } : {}),
        startBatch,
        onProgress: async (done, total) => {
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
      try {
        let text: string | undefined;
        if (parameters.streaming && parameters.kind === "plaso") {
          await options.pipeline.importPlasoFile(job.caseId, artifactPath, base);
        } else {
          text = await readFile(artifactPath, "utf8");
          await ctx.dispatchImport(parameters.kind, job.caseId, text, base);
        }

        const imported = await options.stateStore.load(job.caseId);
        const allArtifactEvents = imported.forensicTimeline.filter((event) =>
          event.sourceScreenshots.includes(parameters.storedName),
        );
        let superTimelineAddedCount = 0;
        if (options.superTimelineStore) {
          if (allArtifactEvents.length) {
            try {
              superTimelineAddedCount = await options.superTimelineStore.append(job.caseId, allArtifactEvents);
              options.onSuperTimeline?.(job.caseId);
            } catch (error) {
              await warn("super-timeline copy failed", error);
            }
          }
        }
        if (allArtifactEvents.length) {
          try {
            await autoTagNewEvents(
              {
                taggerStore: options.taggerStore,
                tagsStore: options.tagsStore,
                stateStore: options.stateStore,
                analysisRunStore: options.analysisRunStore,
                onTags: options.onTags,
                onState: options.onState,
                logLine: (message) => ctx.serverLogger.info(message),
              },
              job.caseId,
              allArtifactEvents,
            );
          } catch (error) {
            await warn("automatic tagging failed", error);
          }
        }
        const finalState = await ctx.demoteForensicForCase(job.caseId);
        const timelineDiff = diffTimeline(before.forensicTimeline, finalState.forensicTimeline);
        const iocDiff = diffIocs(before.iocs, finalState.iocs);
        if (options.importMetaStore) {
          try {
            await options.importMetaStore.record(job.caseId, {
              kind: parameters.kind,
              file: parameters.storedName,
              diff: timelineDiff,
              superTimelineAddedCount,
              iocsDiff: iocDiff,
              linesIn: text ? text.split(/\r?\n/).length : 0,
              path: parameters.kind === "csv" || parameters.kind === "log" ? "ai" : "deterministic",
              fpPropagation: [],
              truncation: null,
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
          stateBefore: before,
          minSeverity,
          path: parameters.kind === "csv" || parameters.kind === "log" ? "ai" : "deterministic",
        });
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
        options.onAiStatus?.(job.caseId, {
          status: "idle",
          at: new Date().toISOString(),
          detail:
            `resumed ${parameters.kind} import committed ` +
            `${addedForensicEvents(finalState.forensicTimeline, timelineDiff).length} new event(s)`,
        });
      } catch (error) {
        const cancelled = signal?.aborted || (error as Error).name === "AbortError";
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
    },
    {
      cancellable: (job) => job.parameters?.kind === "evtxxml",
    },
  );
}
