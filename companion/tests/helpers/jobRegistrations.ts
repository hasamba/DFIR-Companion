// Count job registrations of one kind, as they happen.
//
// The coalescing tests need a barrier that says "all six kicks have registered" before they can
// assert on what survived. Counting the manager's ROWS cannot answer that any more: an exclusive
// registration REMOVES the row it supersedes (jobManager.dropForExclusiveRegistration), so the
// table holds one row after the first kick and one row after the sixth. Watching the registrations
// themselves is the only observation that still distinguishes "six kicks, five superseded" from
// "one kick, five never fired" — which is the failure these tests exist to catch.
import type { JobManager } from "../../src/analysis/jobManager.js";
import type { JobKind } from "../../src/analysis/jobRegistry.js";
import { pollFor } from "./poll.js";

export interface RegistrationCounter {
  /** Job ids registered for the watched kind, oldest first. */
  ids: string[];
  /** Resolve once `count` registrations have landed, on a wall-clock budget. */
  waitFor(count: number): Promise<true>;
}

export function countRegistrations(manager: JobManager, kind: JobKind): RegistrationCounter {
  const ids: string[] = [];
  const register = manager.register.bind(manager);
  manager.register = (input: Parameters<JobManager["register"]>[0]) => {
    const job = register(input);
    if (input.kind === kind && !job.reused) ids.push(job.jobId);
    return job;
  };
  return {
    ids,
    waitFor: (count: number) =>
      pollFor(
        () => `${count} ${kind} registrations, last saw ${ids.length}`,
        async () => (ids.length >= count ? true : undefined),
      ),
  };
}
