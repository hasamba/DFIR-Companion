// Drives SO-CRATES jobs in the background: the poller launch shared by a fresh submission and by
// startup recovery (#2408), the per-case ingest chain, and the drop-log closing line.

import type { CaseStore } from "../storage/caseStore.js";
import { CaseKeyedMap } from "../storage/caseKeyedState.js";
import { generationOf, runInCaseScope } from "../storage/caseIncarnation.js";
import type { ToolConfig } from "../integrations/tools/toolConfig.js";
import { checkStatus, fetchVerdicts } from "../integrations/socrates/socratesApi.js";
import {
  SocratesJobStore,
  isTerminalSocratesStatus,
  type SocratesJob,
} from "../integrations/socrates/socratesJobStore.js";
import { pollUntilImported } from "../integrations/socrates/socratesPoller.js";
import { recoverSocratesJobs } from "../integrations/socrates/socratesRecovery.js";
import {
  SocratesSettledStore,
  type SocratesSettledMarks,
} from "../integrations/socrates/socratesSettledStore.js";
import { formatDropLogLines, appendDropLog, type DropLogEntry } from "../analysis/dropLog.js";
import { createImportDebugRecorder, type ImportDebugRecorder } from "../analysis/importDebug.js";
import { logLine, warnLine } from "../logging/serverLogger.js";
import { dropDirOf } from "./dropFolder.js";
import type { ImportCounts, ImportFailedItem } from "../analysis/importNotification.js";
import type { NotificationEvent } from "../analysis/notifications.js";
import { createSocratesSubmissionTracker } from "./socratesImportNotify.js";

type SocratesIngest = (
  caseId: string,
  kind: "socrates",
  text: string,
  name: string,
  minSeverity: undefined,
  provenance: undefined,
  assetHost: undefined,
  modelCall: undefined,
  debug: ImportDebugRecorder,
) => Promise<{ addedEvents: number; addedIocs: number; counts?: ImportCounts }>;

export interface SocratesJobRunnerDeps {
  store: CaseStore;
  ingestStreamed: SocratesIngest;
  /** The live SO-CRATES config, or null when it is not configured (read at call time). */
  socratesConfig(): ToolConfig | null;
  /** The case notifier: one "Import finished/failed" message per submission (#3008). */
  dispatchNotify?: (event: NotificationEvent) => void;
}

export interface SocratesJobRunner {
  readonly jobs: SocratesJobStore;
  /** Jobs settled as failed while their row could not be written, so no restart reports them twice (#3038). */
  readonly settled: SocratesSettledStore;
  /**
   * Claim a job id BEFORE its row is written, so startup recovery running meanwhile never sees it
   * as orphaned and starts a second poller for it.
   */
  reserve(jobId: string): void;
  /** Open a submission before its first entry is uploaded, so no entry can report it early (#3008). */
  openSubmission(caseId: string, submissionId: string, sourceName: string): void;
  /** Every entry is launched (or the upload loop stopped with `note`): report once all have settled. */
  sealSubmission(caseId: string, submissionId: string, note?: ImportFailedItem): void;
  /** Poll one job in the background until it is imported or failed. At most one poller per job. */
  launch(caseId: string, job: SocratesJob, cfg: ToolConfig & { baseUrl: string }): void;
  /** Startup recovery for every non-archived case: resume or mark interrupted (#2408). */
  resumeAll(): Promise<void>;
}

const POLL_INTERVAL_MS = 5_000;

const RECOVERY_FAILED_MESSAGE =
  "Interrupted by a server restart, and the analysis could not be recovered. Check the timeline, " +
  "and re-run the file if its results are missing.";

export function createSocratesJobRunner(deps: SocratesJobRunnerDeps): SocratesJobRunner {
  const { store } = deps;
  const jobs = new SocratesJobStore(store);
  const settled = new SocratesSettledStore(store);
  // Job ids this process owns, so recovery never starts a second poller for one (#2408): `reserved`
  // covers a fresh submission between writing its row and launching, `running` a live poller.
  const reserved = new Set<string>();
  const running = new Set<string>();
  const owned = (jobId: string): boolean => reserved.has(jobId) || running.has(jobId);
  const submissions = createSocratesSubmissionTracker(deps.dispatchNotify);

  // SO-CRATES pollers finish independently, but every ingest mutates the SAME case state behind the
  // per-case state lock. Firing them concurrently — a 25-entry archive, or several files dropped at
  // once — piles them all onto that lock. Chain them per case so verdicts land one at a time, in
  // completion order. The chain never rejects (each link swallows), so one bad import cannot wedge
  // every later one behind it.
  const ingestChain = new CaseKeyedMap<Promise<unknown>>(() => store.casesRoot); // #1866
  const queueIngest = <T>(caseId: string, fn: () => Promise<T>): Promise<T> => {
    const prev = ingestChain.get(caseId) ?? Promise.resolve();
    const next = prev.then(fn, fn);
    ingestChain.set(
      caseId,
      next.catch(() => {
        /* keep the chain alive after a failure */
      }),
    );
    return next;
  };

  // Close the SUBMITTED line in drop-log.txt with what actually happened. Without this the audit
  // trail ends at "handed to socrates" and never says whether verdicts landed — and a failed
  // analysis would leave a file sitting in _processed/ with no recorded outcome.
  async function closeDropLog(caseId: string, final: SocratesJob): Promise<void> {
    if (!final.dropRelpath) return;
    const entry: DropLogEntry =
      final.status === "imported"
        ? {
            status: "IMPORTED",
            relpath: final.dropRelpath,
            reason: `via socrates — +${final.addedEvents ?? 0} event(s), +${final.addedIocs ?? 0} IOC(s)`,
          }
        : {
            status: "FAILED",
            relpath: final.dropRelpath,
            reason: final.error ?? "SO-CRATES analysis failed",
          };
    await appendDropLog(
      dropDirOf(store, caseId),
      formatDropLogLines([entry], new Date().toISOString()),
    ).catch((e) => logLine(`[drop] log append failed: ${(e as Error).message}`));
  }

  function start(
    caseId: string,
    job: SocratesJob,
    cfg: ToolConfig & { baseUrl: string },
    resumed: boolean,
  ): void {
    const { baseUrl } = cfg;
    reserved.delete(job.jobId);
    if (running.has(job.jobId)) return;
    running.add(job.jobId);
    let counts: ImportCounts | undefined; // this job's settled counts; unknown is never zero (#3008)
    void pollUntilImported(
      caseId,
      job,
      {
        store: jobs,
        checkStatus: (m) => checkStatus(baseUrl, m),
        fetchVerdicts: (m) => fetchVerdicts(baseUrl, m),
        ingest: async (cid, text, name) => {
          // Each verdict set is its own import attempt with its own recorder (#1736).
          const r = await queueIngest(cid, () =>
            deps.ingestStreamed(
              cid,
              "socrates",
              text,
              name,
              undefined,
              undefined,
              undefined,
              undefined,
              createImportDebugRecorder(),
            ),
          );
          counts = r.counts;
          return r;
        },
        warn: warnLine,
      },
      // The operator's DFIR_TOOL_SOCRATES_TIMEOUT_MS is a duration: it is the wall-clock deadline,
      // and the attempt ceiling derived from it is the second bound (#927).
      {
        maxAttempts: Math.max(1, Math.floor(cfg.timeoutMs / POLL_INTERVAL_MS)),
        totalMs: cfg.timeoutMs,
        tolerateStatusErrors: resumed,
      },
    )
      .then(
        (final) => {
          submissions.settle(caseId, final, counts);
          return closeDropLog(caseId, final);
        },
        (err) => {
          const message = `poller stopped: ${(err as Error).message}`;
          warnLine(`[socrates] job ${job.jobId}: ${message}`);
          submissions.settle(caseId, { ...job, status: "error", error: message });
        },
      )
      .finally(() => running.delete(job.jobId));
  }

  async function resumeAll(): Promise<void> {
    let cases: Awaited<ReturnType<typeof store.listCases>>;
    try {
      cases = await store.listCases();
    } catch (err) {
      warnLine(`[socrates] cannot list cases to resume analyses: ${(err as Error).message}`);
      return;
    }
    let resumed = 0;
    let interrupted = 0;
    for (const meta of cases) {
      // An archived case is read-only; its jobs are picked up on the first start after a restore.
      if (meta.status === "archived") continue;
      const { caseId } = meta;
      try {
        // #1866: as work of the incarnation just listed — the resumed poller inherits the scope.
        const counts = await runInCaseScope(
          store.casesRoot,
          caseId,
          async () => {
            // Adopt the submissions a restart left unfinished, so each still sends one message. A job
            // an earlier start already settled as failed counts as finished (#3038). When its marks
            // cannot be read, nothing is adopted: no message can be sent twice, and the next start
            // tries again.
            const marks = await settled.list(caseId);
            const { view, blocked } = await applyMarks(caseId, await jobs.list(caseId), marks);
            submissions.adopt(caseId, view);
            try {
              return await recoverCase(caseId, blocked);
            } finally {
              await settleUnrecovered(caseId, view);
            }
          },
          generationOf(meta),
        );
        resumed += counts.resumed;
        interrupted += counts.interrupted;
      } catch (err) {
        warnLine(`[socrates] ${caseId}: could not recover analyses: ${(err as Error).message}`);
      }
    }
    if (resumed || interrupted)
      logLine(`[socrates] after restart: ${resumed} analysis/es resumed, ${interrupted} marked interrupted`);
  }

  function recoverCase(caseId: string, blocked: ReadonlySet<string>): ReturnType<typeof recoverSocratesJobs> {
    return recoverSocratesJobs(caseId, {
      store: jobs,
      // A job already settled as failed whose row still cannot be written is never resumed (#3038).
      isActive: (jobId) => owned(jobId) || blocked.has(jobId),
      configured: () => Boolean(deps.socratesConfig()?.baseUrl),
      resume: (cid, job) => {
        const cfg = deps.socratesConfig();
        if (cfg?.baseUrl) start(cid, job, { ...cfg, baseUrl: cfg.baseUrl }, true);
      },
      closed: (cid, job) => {
        submissions.settle(cid, job);
        return closeDropLog(cid, job);
      },
      warn: warnLine,
    });
  }

  // A job an earlier start settled as failed while its row could not be written (#3038): write its
  // final state to the row now. The job counts as finished either way, so its submission never
  // reports it again; one whose row is still unwritable is `blocked` from being resumed.
  async function applyMarks(
    caseId: string,
    listed: readonly SocratesJob[],
    marks: SocratesSettledMarks,
  ): Promise<{ view: SocratesJob[]; blocked: Set<string> }> {
    const blocked = new Set<string>();
    const done = Object.keys(marks).filter((id) => !listed.some((j) => j.jobId === id));
    const view: SocratesJob[] = [];
    for (const job of listed) {
      const mark = marks[job.jobId];
      if (!mark || isTerminalSocratesStatus(job.status)) {
        if (mark) done.push(job.jobId);
        view.push(job);
        continue;
      }
      const failed: SocratesJob = { ...job, status: "error", error: mark.error, finishedAt: mark.settledAt };
      try {
        const stored = await jobs.upsert(caseId, failed);
        done.push(job.jobId);
        view.push(stored);
        await closeDropLog(caseId, stored);
      } catch (err) {
        warnLine(`[socrates] job ${job.jobId}: still cannot record its failure: ${(err as Error).message}`);
        blocked.add(job.jobId);
        view.push(failed);
      }
    }
    await settled
      .prune(caseId, done)
      .catch((err) =>
        warnLine(`[socrates] ${caseId}: could not prune settled marks: ${(err as Error).message}`),
      );
    return { view, blocked };
  }

  // A job recovery could not finish (its own recovery threw, or the whole case's did) and that no
  // poller now drives is settled as failed, so its submission still sends its one message (#3035).
  // The tracker ignores a job it already settled, so this never reports one twice in this process.
  // Its failure is persisted first, so a later start does not report it again (#3038).
  async function settleUnrecovered(caseId: string, listed: readonly SocratesJob[]): Promise<void> {
    for (const job of listed) {
      if (isTerminalSocratesStatus(job.status) || owned(job.jobId)) continue;
      const failed: SocratesJob = {
        ...job,
        status: "error",
        error: RECOVERY_FAILED_MESSAGE,
        finishedAt: new Date().toISOString(),
      };
      const persisted = await persistSettled(caseId, failed);
      if (persisted) submissions.settle(caseId, persisted);
    }
  }

  // The job's final row, or failing that a settled mark in the side file. When neither can be
  // written, nothing is sent: the job stays unfinished on disk and the next start reports it, so the
  // message is late rather than sent twice.
  async function persistSettled(caseId: string, failed: SocratesJob): Promise<SocratesJob | null> {
    try {
      const stored = await jobs.upsert(caseId, failed);
      await closeDropLog(caseId, stored);
      return stored;
    } catch {
      // The row is unwritable: fall back to the side file below.
    }
    try {
      await settled.mark(caseId, failed.jobId, failed.error ?? RECOVERY_FAILED_MESSAGE);
      return failed;
    } catch (err) {
      warnLine(
        `[socrates] job ${failed.jobId}: could not record its failure, so its message waits for the next ` +
          `start: ${(err as Error).message}`,
      );
      return null;
    }
  }

  return {
    jobs,
    settled,
    reserve: (jobId) => reserved.add(jobId),
    openSubmission: (caseId, submissionId, sourceName) => submissions.open(caseId, submissionId, sourceName),
    sealSubmission: (caseId, submissionId, note) => submissions.seal(caseId, submissionId, note),
    launch: (caseId, job, cfg) => {
      submissions.add(caseId, job);
      start(caseId, job, cfg, false);
    },
    resumeAll,
  };
}
