/**
 * "idle" only once nothing is running (#2406).
 *
 * The AI status is one channel per case, pushed from well over a hundred call sites, and the last
 * push wins. So with two imports in one case, the first to finish painted "idle" over the second's
 * progress, and the generic import route pushes "idle" before it has even settled the import or
 * finished its job. Every idle also fires the dashboard's "import settled" refreshes.
 *
 * This gate sits at the one sink every push crosses. An "idle" that arrives while the case still
 * has a queued or running job is HELD instead of broadcast. When a job change leaves the case at
 * rest, the held idle is released — but only if the job that ended last SUCCEEDED and the last
 * thing broadcast was not an error or a hold. A failed, cancelled or held run broadcasts its own
 * final status after its terminal transition; replaying the early idle first would paint "up to
 * date" a moment before the failure. Other statuses always pass straight through.
 *
 * The guarantee covers registered jobs. Work that never registers one (#2425) cannot be seen here.
 */
import type { AiStatusEvent } from "./appOptions.js";
import type { Job } from "../analysis/jobRegistry.js";

/** "active" while any job of the case is queued/running; otherwise the last-ended job's status. */
export type CaseJobRest = "active" | "succeeded" | "other";

export interface AiStatusIdleGateDeps {
  jobsAtRest: (caseId: string) => CaseJobRest;
  subscribeJobs: (listener: (caseId: string) => void) => void;
  now?: () => string;
}

export interface AiStatusIdleGate {
  /** True: broadcast the event now. False: it was held. */
  admit(caseId: string, event: AiStatusEvent): boolean;
}

export function createAiStatusIdleGate(
  deps: AiStatusIdleGateDeps,
  broadcast: (caseId: string, event: AiStatusEvent) => void,
): AiStatusIdleGate {
  const held = new Map<string, AiStatusEvent>();
  const lastBroadcast = new Map<string, AiStatusEvent["status"]>();
  const now = deps.now ?? (() => new Date().toISOString());

  deps.subscribeJobs((caseId) => {
    const pending = held.get(caseId);
    if (!pending) return;
    const rest = deps.jobsAtRest(caseId);
    if (rest === "active") return;
    held.delete(caseId);
    const last = lastBroadcast.get(caseId);
    if (rest !== "succeeded" || last === "error" || last === "blocked") return;
    lastBroadcast.set(caseId, "idle");
    broadcast(caseId, { ...pending, at: now() });
  });

  return {
    admit(caseId, event) {
      if (event.status === "idle" && deps.jobsAtRest(caseId) === "active") {
        held.set(caseId, event);
        return false;
      }
      if (event.status === "idle") held.delete(caseId);
      lastBroadcast.set(caseId, event.status);
      return true;
    },
  };
}

/** A case's job rows reduced to what the gate asks: still running, or how the last one ended. */
export function caseJobRest(jobs: readonly Pick<Job, "status" | "endedAt" | "updatedAt">[]): CaseJobRest {
  if (jobs.some((job) => job.status === "queued" || job.status === "running")) return "active";
  let last: Pick<Job, "status" | "endedAt" | "updatedAt"> | undefined;
  for (const job of jobs) {
    const at = job.endedAt ?? job.updatedAt;
    if (!last || at > (last.endedAt ?? last.updatedAt)) last = job;
  }
  return last?.status === "succeeded" ? "succeeded" : "other";
}
