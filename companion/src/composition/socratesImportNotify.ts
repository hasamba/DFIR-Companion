import {
  notifyImport,
  type ImportCounts,
  type ImportFailedItem,
  type ImportOutcome,
} from "../analysis/importNotification.js";
import type { NotificationEvent } from "../analysis/notifications.js";
import { isTerminalSocratesStatus, type SocratesJob } from "../integrations/socrates/socratesJobStore.js";
import { logLine } from "../logging/serverLogger.js";

// "Import finished" messages for SO-CRATES verdict imports (#3008, the path #2978 left out). One
// submission — a single file, or every entry of an archive (up to 25 jobs) — sends ONE message, when
// its last job reaches a final state. One message per entry would flood the channel (#2978 rejected
// per-capture messages for the same reason).
//
// A submission is OPEN while its entries are still being uploaded, so an entry that finishes before
// the next one is launched cannot close it early; the submitter seals it once the loop ends. Startup
// recovery adopts the submissions a restart left unfinished, already sealed.

type Dispatch = ((event: NotificationEvent) => void) | undefined;

interface Group {
  caseId: string;
  sourceName: string;
  sealed: boolean;
  pending: Set<string>;
  done: Map<string, { job: SocratesJob; counts?: ImportCounts }>;
  notes: ImportFailedItem[];
}

export interface SocratesSubmissionTracker {
  /** A fresh submission, before its first entry is uploaded. */
  open(caseId: string, submissionId: string, sourceName: string): void;
  /** A job launched for a submission. */
  add(caseId: string, job: SocratesJob): void;
  /** Every entry has been launched (or the upload loop stopped with `note`). */
  seal(caseId: string, submissionId: string, note?: ImportFailedItem): void;
  /** A job reached its final state. Unknown counts are left out, never zero. */
  settle(caseId: string, job: SocratesJob, counts?: ImportCounts): void;
  /** Startup recovery: adopt every submission of this case that still has an unfinished job. */
  adopt(caseId: string, jobs: readonly SocratesJob[]): void;
}

/** A job written before #3008 has no submission id: it is a submission of its own. */
export const submissionKeyOf = (job: Pick<SocratesJob, "jobId" | "submissionId">): string =>
  job.submissionId ?? job.jobId;

/** Counts for the whole submission only when every imported entry knows its own. */
function sumCounts(entries: readonly { counts?: ImportCounts }[]): ImportCounts | undefined {
  if (!entries.length || entries.some((e) => !e.counts)) return undefined;
  const known = entries.map((e) => e.counts as ImportCounts);
  const sum = (pick: (c: ImportCounts) => number): number => known.reduce((n, c) => n + pick(c), 0);
  const superKnown = known.every((c) => c.superAdded !== undefined);
  return {
    added: sum((c) => c.added),
    highCritical: sum((c) => c.highCritical),
    ...(superKnown ? { superAdded: sum((c) => c.superAdded ?? 0) } : {}),
  };
}

/** The outcome of one finished submission. Exported for tests. */
export function submissionOutcome(group: Omit<Group, "sealed" | "pending">): ImportOutcome {
  const entries = [...group.done.values()];
  const imported = entries.filter((e) => e.job.status === "imported");
  const failedJobs = entries.filter((e) => e.job.status !== "imported");
  const failed: ImportFailedItem[] = [
    ...failedJobs.map(({ job }) => ({
      name: job.zipEntry ?? job.sourceName,
      reason: job.error ?? "SO-CRATES analysis failed",
    })),
    ...group.notes,
  ];
  const ok = imported.length > 0;
  const files = entries.length + group.notes.length;
  const counts = sumCounts(imported);
  const single = files === 1;
  return {
    caseId: group.caseId,
    source: `SO-CRATES: ${group.sourceName}`,
    ok,
    ...(files > 1 ? { files } : {}),
    ...(counts ? { counts } : {}),
    // A single file that failed says why in its reason; a list would only repeat it.
    ...(failed.length && !(single && !ok) ? { failed } : {}),
    ...(ok ? {} : { reason: single ? failed[0].reason : "no entry could be analyzed and imported" }),
  };
}

export function createSocratesSubmissionTracker(dispatch: Dispatch): SocratesSubmissionTracker {
  const groups = new Map<string, Group>();
  const keyOf = (caseId: string, submission: string): string => `${caseId}\u0000${submission}`;

  const newGroup = (caseId: string, sourceName: string, sealed: boolean): Group => ({
    caseId,
    sourceName,
    sealed,
    pending: new Set(),
    done: new Map(),
    notes: [],
  });

  function flush(key: string, group: Group): void {
    if (!group.sealed || group.pending.size) return;
    groups.delete(key);
    // Nothing launched at all: the submitter's own failure path reports it.
    if (!group.done.size) return;
    notifyImport(dispatch, submissionOutcome(group), logLine);
  }

  return {
    open(caseId, submissionId, sourceName) {
      groups.set(keyOf(caseId, submissionId), newGroup(caseId, sourceName, false));
    },
    add(caseId, job) {
      const key = keyOf(caseId, submissionKeyOf(job));
      const group = groups.get(key) ?? newGroup(caseId, job.sourceName, true);
      groups.set(key, group);
      group.pending.add(job.jobId);
    },
    seal(caseId, submissionId, note) {
      const key = keyOf(caseId, submissionId);
      const group = groups.get(key);
      if (!group) return;
      group.sealed = true;
      if (note) group.notes.push(note);
      flush(key, group);
    },
    settle(caseId, job, counts) {
      const key = keyOf(caseId, submissionKeyOf(job));
      const group = groups.get(key);
      // A group already reported (or never tracked) is not reported again.
      if (!group || !group.pending.has(job.jobId)) return;
      group.pending.delete(job.jobId);
      group.done.set(job.jobId, { job, ...(counts ? { counts } : {}) });
      flush(key, group);
    },
    adopt(caseId, jobs) {
      const byKey = new Map<string, SocratesJob[]>();
      for (const job of jobs) {
        const key = keyOf(caseId, submissionKeyOf(job));
        byKey.set(key, [...(byKey.get(key) ?? []), job]);
      }
      for (const [key, members] of byKey) {
        // A submission this process already drives, or one that finished, is left alone.
        if (groups.has(key) || members.every((j) => isTerminalSocratesStatus(j.status))) continue;
        const group = newGroup(caseId, members[0].sourceName, true);
        for (const job of members) {
          // Counts from before the restart are gone: unknown, never zero.
          if (isTerminalSocratesStatus(job.status)) group.done.set(job.jobId, { job });
          else group.pending.add(job.jobId);
        }
        groups.set(key, group);
      }
    },
  };
}
