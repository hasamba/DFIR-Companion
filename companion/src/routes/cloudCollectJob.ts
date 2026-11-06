// The `cloud-collect` background job (#2311): one job per collection run, start or resume.
//
// It holds the case's JOB slot like every other job (admission is per case), but takes the case's
// IMPORT section only per page in the import stage — the network stage, which can wait ten minutes
// on a Graph query, never blocks another import into the case. Other jobs of the case do queue
// behind a long collection while DFIR_JOBS_PER_CASE is 1; that is the operator's setting to raise.
//
// RESUME needs the account's credential again, and a resume handler gets no request to check it
// with. So the collection's own route (routes/cloudCollect.ts) opens the account through
// openCloudAccountForCollect — attachment, case write, demo refusal, audit entry — opens the
// provider session, parks it here under the job id, and only then asks the job manager to resume.
// The handler takes the parked session; with none (the generic /api/jobs/:id/resume, refused there
// anyway) it fails, still resumable, and says where to resume from.

import { join } from "node:path";
import type { JobManager } from "../analysis/jobManager.js";
import type { ManifestValue } from "../analysis/analysisRunTypes.js";
import { nodeCollectFs } from "../integrations/cloudCollect/collectFs.js";
import {
  markCollectionStopped,
  runCollection,
  type CollectProgress,
} from "../integrations/cloudCollect/collectEngine.js";
import {
  CLOUD_COLLECT_RESUME_ELSEWHERE,
  collectionsRoot,
  isCollectionId,
} from "../integrations/cloudCollect/collectStore.js";
import type {
  CloudCollectProvider,
  CloudCollectSession,
  CollectionCheckpoint,
} from "../integrations/cloudCollect/collectTypes.js";
import type { QueryBudget } from "../integrations/cloudCollect/collectBudget.js";
import { redactedErrorMessage } from "../analysis/redactPaths.js";
import { caseCollectImporter } from "./cloudCollectImporter.js";
import type { RouteContext } from "./context.js";

/**
 * The job's warning for a run that did not fail: the stop reason when the network stage stopped
 * early (budget used, disk full — #2339), else the missing-window count. Always reads "partial", the
 * collection's own status. Pure.
 */
export function collectionJobWarning(cp: CollectionCheckpoint): string | undefined {
  if (cp.status === "complete" && !cp.missing.length) return undefined;
  if (cp.stopReason)
    return cp.stopReason.startsWith("partial") ? cp.stopReason : `partial — ${cp.stopReason}`;
  return cp.missing.length ? `partial — ${cp.missing.length} window(s) missing` : undefined;
}

/** A collection may be resumed many times (a long Graph query, a flaky link): do not run out. */
export const CLOUD_COLLECT_MAX_RETRIES = 1000;

export interface CollectSessionRef {
  provider: CloudCollectProvider;
  session: CloudCollectSession;
  /** The tenant's shared daily query budget (#2312), when the provider has one. */
  budget?: QueryBudget;
}

const parkedSessions = new Map<string, CollectSessionRef>();

/** Park a freshly opened session for the resume handler of `jobId`. */
export function parkResumeSession(jobId: string, ref: CollectSessionRef): void {
  parkedSessions.set(jobId, ref);
}

export function unparkResumeSession(jobId: string): void {
  parkedSessions.delete(jobId);
}

export function collectionDir(ctx: RouteContext, caseId: string, collectionId: string): string {
  return join(collectionsRoot(ctx.store.caseDir(caseId)), collectionId);
}

function progressLine(p: CollectProgress): { done: number; total: number; detail: string } {
  const per = p.sources
    .map((s) => `${s.source} ${s.pages} page(s) ${s.state}${s.status ? ` (${s.status})` : ""}`)
    .join(", ");
  if (p.stage === "network")
    return { done: p.pages, total: p.pages + 1, detail: `cloud collect — saving pages: ${per}` };
  return {
    done: p.imported,
    total: Math.max(p.pages, p.imported),
    detail: `cloud collect — importing ${p.imported}/${p.pages} page(s)`,
  };
}

export interface ExecuteInput {
  jobId: string;
  caseId: string;
  dir: string;
  ref: CollectSessionRef;
  resume: boolean;
  signal?: AbortSignal;
}

/** Run one collection pass inside a job. Throws on failure (the job fails, still resumable). */
export async function executeCollection(
  ctx: RouteContext,
  input: ExecuteInput,
): Promise<CollectionCheckpoint> {
  const manager = ctx.options.jobManager;
  const now = () => new Date().toISOString();
  const log = (line: string) => ctx.serverLogger.info(line, { caseId: input.caseId });
  try {
    const cp = await runCollection(
      {
        fs: nodeCollectFs,
        session: input.ref.session,
        importer: caseCollectImporter(ctx),
        sources: input.ref.provider.sources,
        now,
        ...(input.ref.budget ? { budget: input.ref.budget } : {}),
        ...(input.ref.provider.retryBudget !== undefined
          ? { retryBudget: input.ref.provider.retryBudget }
          : {}),
        ...(input.signal ? { signal: input.signal } : {}),
        onProgress: (p) => {
          const line = progressLine(p);
          manager?.progress(input.jobId, line.done, line.total, line.detail);
        },
      },
      input.dir,
      { resume: input.resume, jobId: input.jobId },
    );
    log(
      `[cloud-collect] ${cp.collectionId}: ${cp.status} — ${cp.imported.length} page(s) imported, ` +
        `${cp.missing.length} window(s) missing, ${cp.quarantined.length} file(s) quarantined`,
    );
    if (cp.status === "failed") throw new Error(cp.missing[0]?.reason ?? "nothing was collected");
    const warning = collectionJobWarning(cp);
    if (warning) await manager?.warn(input.jobId, warning);
    return cp;
  } catch (err) {
    const cancelled = (err as Error)?.name === "AbortError";
    const message = redactedErrorMessage(err);
    await markCollectionStopped(
      nodeCollectFs,
      input.dir,
      cancelled ? "interrupted" : "failed",
      message,
      now,
    ).catch(() => {});
    log(
      `[cloud-collect] ${input.dir.split(/[\\/]/).pop()}: ${cancelled ? "cancelled" : "stopped"} — ${message}`,
    );
    throw err;
  } finally {
    await Promise.resolve(input.ref.session.close?.()).catch(() => {});
  }
}

/** Register a new collect job for a collection and run it in the background. */
export async function launchCollectJob(
  ctx: RouteContext,
  manager: JobManager,
  input: Omit<ExecuteInput, "jobId" | "signal"> & {
    label: string;
    parameters: Record<string, ManifestValue>;
    before?: (jobId: string, signal?: AbortSignal) => Promise<void>;
  },
): Promise<string> {
  const job = manager.register({
    caseId: input.caseId,
    kind: "cloud-collect",
    label: input.label,
    detail: input.label,
    parameters: input.parameters,
    resumable: true,
    cancellable: true,
    maxRetries: CLOUD_COLLECT_MAX_RETRIES,
  });
  await job.durable;
  void (async () => {
    try {
      await job.ready;
      await input.before?.(job.jobId, job.signal);
      await executeCollection(ctx, {
        ...input,
        jobId: job.jobId,
        ...(job.signal ? { signal: job.signal } : {}),
      });
      await manager.finish(job.jobId);
    } catch (err) {
      if ((err as Error)?.name === "AbortError") return; // cancel already settled the row
      await manager.fail(job.jobId, err, { code: "cloud_collect_failed", retryable: true });
    }
  })();
  return job.jobId;
}

export function registerCloudCollectResumeHandler(ctx: RouteContext): void {
  ctx.options.jobManager?.registerResumeHandler(
    "cloud-collect",
    async (job, signal) => {
      const ref = parkedSessions.get(job.id);
      parkedSessions.delete(job.id);
      if (!ref) throw new Error(CLOUD_COLLECT_RESUME_ELSEWHERE);
      const collectionId = job.parameters?.collectionId;
      if (!job.caseId || !isCollectionId(collectionId))
        throw new Error("saved cloud collection job is unreadable");
      await executeCollection(ctx, {
        jobId: job.id,
        caseId: job.caseId,
        dir: collectionDir(ctx, job.caseId, collectionId),
        ref,
        resume: true,
        ...(signal ? { signal } : {}),
      });
    },
    { cancellable: () => true },
  );
}
