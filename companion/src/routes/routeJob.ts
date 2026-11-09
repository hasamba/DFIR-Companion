// An analyst-pressed request/response run that holds a job row while it works (#2425).
//
// The Jev review and the containment check are paid model calls the analyst waits on. As jobs they
// show in the Jobs panel, count as "busy", and take the case's one-job slot: a press while another
// job runs waits for it instead of running beside it. They are NOT cancellable (a cancel would free
// the slot while the call still ran) and NOT exclusive (a second press must not supersede the first;
// each route keeps its own single-flight guard and answers 409 instead).
//
// The job is closed from what the run answered: a 2xx with no recorded error finishes it, an
// analyst-decision gate (a Presidio approval) holds it, anything else fails it. A rejected admission
// (the ledger refused the job, or the case was deleted while it queued) fails it and answers 500.

import type { Response } from "express";
import type { JobManager, RegisterInput } from "../analysis/jobManager.js";
import { getServerLogger } from "../logging/serverLogger.js";
import { isAnalystDecisionGate } from "./presidioApproval.js";

/** What the run learned while it answered, so its job row closes the right way. */
export interface RouteJobOutcome {
  /** The error that stopped the run. Unset on success. */
  error?: unknown;
  /** A failure code more specific than the route's default. */
  code?: string;
}

/** Called by the run when it stops short: the error, and optionally a more specific code. */
export type RecordRouteJobFailure = (error: unknown, code?: string) => void;

const messageOf = (err: unknown): string => (err instanceof Error ? err.message : String(err));

/** Close a job from the answer its run sent. */
export async function settleRouteJob(
  jobManager: JobManager,
  jobId: string,
  res: Response,
  outcome: RouteJobOutcome,
  failureCode: string,
): Promise<void> {
  const { error } = outcome;
  if (error !== undefined && isAnalystDecisionGate(error)) return jobManager.hold(jobId, messageOf(error));
  if (error === undefined && res.statusCode < 400) return jobManager.finish(jobId);
  const cause = error ?? new Error(`the run answered HTTP ${res.statusCode}`);
  return jobManager.fail(jobId, cause, { code: outcome.code ?? failureCode });
}

/**
 * Register `input`, wait for the case's slot, run `work`, and close the job from its answer. Any
 * throw (admission included) fails the job and, when nothing was sent yet, answers 500.
 */
export async function runAsRouteJob(
  jobManager: JobManager | undefined,
  res: Response,
  input: RegisterInput,
  failureCode: string,
  work: (recordFailure: RecordRouteJobFailure) => Promise<Response>,
): Promise<Response> {
  let outcome: RouteJobOutcome = {};
  const recordFailure: RecordRouteJobFailure = (error, code) => {
    outcome = { error, ...(code ? { code } : {}) };
  };
  let jobId: string | undefined;
  try {
    const job = jobManager?.register(input);
    jobId = job?.jobId;
    await job?.ready;
    const answered = await work(recordFailure);
    if (jobManager && jobId) await settleRouteJob(jobManager, jobId, answered, outcome, failureCode);
    return answered;
  } catch (err) {
    // A no-op on a job that is already terminal. If closing the job itself threw (the ledger refused
    // the write), the row is still open and is failed here, even when the answer was a success.
    if (jobManager && jobId) {
      await jobManager.fail(jobId, err, { code: failureCode }).catch((failErr: unknown) => {
        getServerLogger().warn(
          `[jobs] ${input.kind} job ${jobId}: could not record its failure — ${messageOf(failErr)}`,
        );
      });
    }
    if (res.headersSent) return res;
    return res.status(500).json({ error: messageOf(err) });
  }
}
