// Drives SO-CRATES jobs in the background: the poller launch shared by a fresh submission and by
// startup recovery (#2408), the per-case ingest chain, and the drop-log closing line.

import type { CaseStore } from "../storage/caseStore.js";
import { CaseKeyedMap } from "../storage/caseKeyedState.js";
import { generationOf, runInCaseScope } from "../storage/caseIncarnation.js";
import type { ToolConfig } from "../integrations/tools/toolConfig.js";
import { checkStatus, fetchVerdicts } from "../integrations/socrates/socratesApi.js";
import { SocratesJobStore, type SocratesJob } from "../integrations/socrates/socratesJobStore.js";
import { pollUntilImported } from "../integrations/socrates/socratesPoller.js";
import { recoverSocratesJobs } from "../integrations/socrates/socratesRecovery.js";
import { formatDropLogLines, appendDropLog, type DropLogEntry } from "../analysis/dropLog.js";
import { createImportDebugRecorder, type ImportDebugRecorder } from "../analysis/importDebug.js";
import { logLine, warnLine } from "../logging/serverLogger.js";
import { dropDirOf } from "./dropFolder.js";

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
) => Promise<{ addedEvents: number; addedIocs: number }>;

export interface SocratesJobRunnerDeps {
  store: CaseStore;
  ingestStreamed: SocratesIngest;
  /** The live SO-CRATES config, or null when it is not configured (read at call time). */
  socratesConfig(): ToolConfig | null;
}

export interface SocratesJobRunner {
  readonly jobs: SocratesJobStore;
  /** Poll one job in the background until it is imported or failed. */
  launch(caseId: string, job: SocratesJob, cfg: ToolConfig & { baseUrl: string }): void;
  /** Startup recovery for every non-archived case: resume or mark interrupted (#2408). */
  resumeAll(): Promise<void>;
}

const POLL_INTERVAL_MS = 5_000;

export function createSocratesJobRunner(deps: SocratesJobRunnerDeps): SocratesJobRunner {
  const { store } = deps;
  const jobs = new SocratesJobStore(store);
  // Job ids a poller in this process is driving, so recovery never starts a second one (#2408).
  const active = new Set<string>();

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
    active.add(job.jobId);
    void pollUntilImported(
      caseId,
      job,
      {
        store: jobs,
        checkStatus: (m) => checkStatus(baseUrl, m),
        fetchVerdicts: (m) => fetchVerdicts(baseUrl, m),
        ingest: (cid, text, name) =>
          // Each verdict set is its own import attempt with its own recorder (#1736).
          queueIngest(cid, () =>
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
          ),
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
      .then((final) => closeDropLog(caseId, final))
      .catch((err) => warnLine(`[socrates] job ${job.jobId}: poller stopped: ${(err as Error).message}`))
      .finally(() => active.delete(job.jobId));
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
          () =>
            recoverSocratesJobs(caseId, {
              store: jobs,
              isActive: (id) => active.has(id),
              configured: () => Boolean(deps.socratesConfig()?.baseUrl),
              resume: (cid, job) => {
                const cfg = deps.socratesConfig();
                if (cfg?.baseUrl) start(cid, job, { ...cfg, baseUrl: cfg.baseUrl }, true);
              },
              closed: closeDropLog,
              warn: warnLine,
            }),
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

  return {
    jobs,
    launch: (caseId, job, cfg) => start(caseId, job, cfg, false),
    resumeAll,
  };
}
