import type { Express, Request, Response } from "express";
import { logActivity } from "../analysis/activityLog.js";
import { deepPassCheckpointSchema, type DeepPassCheckpoint } from "../analysis/deepPass.js";
import type { Job } from "../analysis/jobRegistry.js";
import { parseMinSeverity } from "../analysis/severityFloor.js";
import type { Severity } from "../analysis/stateTypes.js";
import { sendPipelineError } from "./presidioApproval.js";
import type { RouteContext } from "./context.js";

export function registerDeepPassRoutes(app: Express, ctx: RouteContext): void {
  const { store, options } = ctx;

  const aiStatus = (caseId: string, status: "analyzing" | "idle" | "error", detail?: string): void => {
    options.onAiStatus?.(caseId, {
      status,
      ...(status === "analyzing" ? { phase: "deep-pass" as const } : {}),
      at: new Date().toISOString(),
      ...(detail ? { detail } : {}),
    });
  };

  const recordResult = (
    caseId: string,
    minSeverity: Severity,
    result: {
      events: number;
      batches: number;
      observations: number;
      batchesFailed: number;
      aborted: boolean;
    },
  ): void => {
    void logActivity(options.activityLogStore, options.onActivity, caseId, {
      category: "ai",
      action: "deep-pass",
      detail:
        `deep pass (${minSeverity}+) read ${result.events} event(s) in ${result.batches} batch(es), ` +
        `${result.observations} observation(s)` +
        (result.batchesFailed ? ` — ${result.batchesFailed} batch(es) FAILED (partial coverage)` : "") +
        (result.aborted ? " — CANCELLED, nothing was written" : ""),
    });
  };

  const execute = async (
    job: Pick<Job, "id" | "caseId" | "lastCheckpoint">,
    minSeverity: Severity,
    signal?: AbortSignal,
  ) => {
    if (!options.pipeline || !job.caseId) {
      throw new Error("deep-pass pipeline or case is unavailable");
    }
    const caseId = job.caseId;
    const resumeFrom = job.lastCheckpoint?.cursor
      ? deepPassCheckpointSchema.parse(job.lastCheckpoint.cursor)
      : undefined;
    return options.pipeline.deepPass(caseId, {
      minSeverity,
      ...(signal ? { signal } : {}),
      ...(resumeFrom ? { resumeFrom } : {}),
      onProgress: (done, total, detail) => {
        options.jobManager?.progress(job.id, done, total, detail);
        aiStatus(caseId, "analyzing", `deep pass (${minSeverity}+) — ${detail}`);
      },
      onCheckpoint: async (checkpoint: DeepPassCheckpoint) => {
        await options.jobManager?.checkpoint(job.id, {
          done: checkpoint.nextBatch,
          total: checkpoint.totalBatches,
          detail: `committed observation batch ${checkpoint.nextBatch}/${checkpoint.totalBatches}`,
          cursor: checkpoint,
        });
      },
    });
  };

  options.jobManager?.registerResumeHandler("deep-pass", async (job, signal) => {
    const minSeverity = parseMinSeverity(job.parameters?.minSeverity);
    if (!minSeverity || minSeverity === "Info" || !job.caseId) {
      throw new Error("saved deep-pass parameters are invalid");
    }
    aiStatus(job.caseId, "analyzing", `resuming deep pass (${minSeverity}+)`);
    const result = await execute(job, minSeverity, signal);
    if (result.batchesFailed) {
      await options.jobManager?.warn(
        job.id,
        `${result.batchesFailed} batch(es) failed; the result has partial coverage`,
      );
    }
    aiStatus(job.caseId, "idle", result.aborted ? "deep pass cancelled — nothing was written" : undefined);
    recordResult(job.caseId, minSeverity, result);
  });

  app.get("/cases/:id/deep-pass/preview", async (req: Request, res: Response) => {
    if (!options.pipeline) {
      return res.status(501).json({ error: "pipeline not configured" });
    }
    const caseId = req.params.id;
    if (!(await store.getCaseMeta(caseId).catch(() => null))) {
      return res.status(404).json({ error: "case not found" });
    }
    try {
      return res.status(200).json(await options.pipeline.deepPassPreview(caseId));
    } catch (error) {
      return res.status(500).json({ error: String((error as Error).message) });
    }
  });

  app.post("/cases/:id/deep-pass", async (req: Request, res: Response) => {
    if (!options.pipeline || !options.pipeline.hasSynthesisProvider()) {
      return res.status(501).json({ error: "AI provider not configured for synthesis" });
    }
    const caseId = req.params.id;
    const caseMeta = await store.getCaseMeta(caseId).catch(() => null);
    if (!caseMeta) return res.status(404).json({ error: "case not found" });
    if (caseMeta.status === "closed" || caseMeta.status === "archived") {
      const action = caseMeta.status === "archived" ? "restore it" : "reopen it";
      return res.status(423).json({
        error: `Case "${caseId}" is ${caseMeta.status} — ${action} before running a deep pass`,
      });
    }
    const minSeverity = parseMinSeverity((req.body as { minSeverity?: unknown })?.minSeverity);
    if (!minSeverity || minSeverity === "Info") {
      return res.status(400).json({
        error: "minSeverity must be one of Critical, High, Medium, Low",
      });
    }

    await options.jobManager?.ready();
    const registered = options.jobManager?.register({
      caseId,
      kind: "deep-pass",
      label: `deep pass (${minSeverity}+)`,
      cancellable: true,
      exclusive: true,
      priority: "high",
      resumable: true,
      maxRetries: 2,
      parameters: { minSeverity },
    });
    try {
      await registered?.ready;
      const job = registered ? options.jobManager!.get(registered.jobId)! : { id: "untracked", caseId };
      aiStatus(caseId, "analyzing", `deep pass (${minSeverity}+) — starting`);
      const result = await execute(job, minSeverity, registered?.signal);
      if (registered && result.batchesFailed) {
        await options.jobManager?.warn(
          registered.jobId,
          `${result.batchesFailed} batch(es) failed; the result has partial coverage`,
        );
      }
      if (registered) await options.jobManager?.finish(registered.jobId);
      aiStatus(caseId, "idle", result.aborted ? "deep pass cancelled — nothing was written" : undefined);
      recordResult(caseId, minSeverity, result);
      return res.status(200).json(result);
    } catch (error) {
      const message = String((error as Error).message ?? "");
      if (registered) {
        await options.jobManager?.fail(registered.jobId, error, {
          code: /batches/i.test(message) ? "budget_exceeded" : "deep_pass_failed",
          retryable: !/batches/i.test(message),
        });
      }
      if (/batches/i.test(message)) {
        aiStatus(caseId, "idle", "deep pass not started — raise the severity floor");
        return res.status(400).json({ error: message });
      }
      aiStatus(caseId, "error", message);
      return sendPipelineError(res, error);
    }
  });
}
