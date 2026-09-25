// The served model on a job row (#1601) — the pure half of JobManager.useServedModels and list().
//
// Kept out of jobManager.ts so that file stays a state machine. Three rules live here:
//
//   1. A job is stamped only by a call that carried the job's OWN cancel signal AND ran on the
//      provider and alias the job was pinned to. A second call sharing the signal on another model
//      (a referee, a fallback) is not what the row names, so it never stamps.
//   2. A job that recorded no provider is never stamped: alias-only matching across providers
//      could put one vendor's answer on another vendor's row.
//   3. "Last run" comes from this process's answers first, then from the newest restored row with
//      the same provider and alias — the ledger holds that answer across a restart, exactly.
import { isTerminal, type Job } from "./jobRegistry.js";
import { jobModelLabel } from "./modelDisplayName.js";
import type { ServedModelEvent } from "./servedModels.js";

/** A job as the API and the dashboard see it: the durable row plus its display label. */
export type JobListItem = Job & { modelLabel?: string };

/** What a model resolver may answer: an alias alone, or the alias with its provider. */
export type JobModelIdentity = string | { model: string; provider: string } | undefined;

export function modelIdentityFields(identity: JobModelIdentity): Pick<Job, "model" | "modelProvider"> {
  if (!identity) return {};
  if (typeof identity === "string") return identity ? { model: identity } : {};
  if (!identity.model) return {};
  return { model: identity.model, ...(identity.provider ? { modelProvider: identity.provider } : {}) };
}

/** The job this served call belongs to, or undefined when it cannot be told exactly. */
export function servedStampTarget(
  event: ServedModelEvent,
  controllers: ReadonlyMap<string, AbortController>,
  getJob: (jobId: string) => Job | undefined,
): Job | undefined {
  if (!event.signal) return undefined;
  for (const [jobId, controller] of controllers) {
    if (controller.signal !== event.signal) continue;
    const job = getJob(jobId);
    if (!job || isTerminal(job.status)) return undefined;
    if (job.model !== event.alias || job.modelProvider !== event.provider) return undefined;
    return job;
  }
  return undefined;
}

type LastServedLookup = (provider: string, alias: string) => string | undefined;

function lastServedFromHistory(all: readonly Job[], provider: string, alias: string): string | undefined {
  let best: Job | undefined;
  for (const job of all) {
    if (!job.servedModel || job.model !== alias || job.modelProvider !== provider) continue;
    if (!best || job.updatedAt > best.updatedAt) best = job;
  }
  return best?.servedModel;
}

/** Add the display label to each row that names a model. Rows without one are returned as they are. */
export function withModelLabels(
  jobs: readonly Job[],
  all: readonly Job[],
  lastServed?: LastServedLookup,
): JobListItem[] {
  return jobs.map((job) => {
    if (!job.model) return job;
    const terminal = isTerminal(job.status);
    const last =
      !terminal && !job.servedModel && job.modelProvider
        ? (lastServed?.(job.modelProvider, job.model) ??
          lastServedFromHistory(all, job.modelProvider, job.model))
        : undefined;
    const modelLabel = jobModelLabel(
      { model: job.model, ...(job.servedModel ? { servedModel: job.servedModel } : {}), terminal },
      last,
    );
    return modelLabel ? { ...job, modelLabel } : job;
  });
}
