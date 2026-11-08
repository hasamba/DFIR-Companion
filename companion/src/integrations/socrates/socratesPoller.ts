import type { SocratesJob, SocratesJobStore } from "./socratesJobStore.js";
import type { SocratesStatus, SocratesVerdicts } from "./socratesApi.js";

// Waits for one SO-CRATES analysis to finish, then hands its verdicts to the importer. Every
// collaborator is injected so the whole loop is unit-testable without a server or real time.

export interface PollerDeps {
  store: SocratesJobStore;
  checkStatus(md5: string): Promise<SocratesStatus>;
  fetchVerdicts(md5: string): Promise<SocratesVerdicts>;
  ingest(caseId: string, text: string, name: string): Promise<{ addedEvents: number; addedIocs: number }>;
  sleep?(ms: number): Promise<void>;
  /** The clock the deadline is read from. Injected so the loop is testable without real time. */
  now?(): number;
  /** Where a bookkeeping failure the loop survives is reported. Defaults to silence. */
  warn?(line: string): void;
}

export interface PollOptions {
  maxAttempts?: number;
  intervalMs?: number;
  totalMs?: number;
  /**
   * A job resumed after a restart (#2408) keeps polling through failed status checks until the
   * deadline: the companion often starts before the SO-CRATES host does, and failing on the first
   * refused connection would turn every recovered analysis into an error. A fresh submission keeps
   * failing fast, so a wrong URL is reported at once.
   */
  tolerateStatusErrors?: boolean;
}

// The final "imported" save is retried (#2408): the verdicts are already in the case by then, so a
// transient write failure must not leave the job looking unfinished.
const SAVE_RETRY_DELAYS_MS = [1_000, 5_000];

// 5s × 240 = 20 minutes, enough for Suricata over a large PCAP. The ceiling is NOT optional:
// SO-CRATES never 404s a well-formed but unknown MD5 — it answers "processing" forever — so
// without this a typo'd or deleted analysis polls until the process dies.
//
// The ceiling counts COMPLETED checks, so it is a bound on time only when every check completes
// promptly (#927). Two things make that true: every request in socratesApi.ts carries its own
// AbortSignal deadline, so a hung check rejects instead of holding attempt 1 forever; and the
// loop also watches a wall-clock deadline, so a run of slow-but-completing checks cannot stretch
// "20 minutes" into hours. DFIR_TOOL_SOCRATES_TIMEOUT_MS is a duration the operator set; the loop
// honours it as one.
const DEFAULT_INTERVAL_MS = 5_000;
const DEFAULT_MAX_ATTEMPTS = 240;

const defaultSleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

export async function pollUntilImported(
  caseId: string,
  job: SocratesJob,
  deps: PollerDeps,
  opts: PollOptions = {},
): Promise<SocratesJob> {
  const maxAttempts = opts.maxAttempts ?? DEFAULT_MAX_ATTEMPTS;
  const intervalMs = opts.intervalMs ?? DEFAULT_INTERVAL_MS;
  const totalMs = opts.totalMs ?? maxAttempts * intervalMs;
  const sleep = deps.sleep ?? defaultSleep;
  const now = deps.now ?? Date.now;
  const warn = deps.warn ?? (() => {});
  const deadline = now() + totalMs;
  let current = job;

  // Spreads `current`, not the job passed in, so the phase recorded so far survives (#2408).
  const fail = async (message: string): Promise<SocratesJob> => {
    const failed: SocratesJob = {
      ...current,
      status: "error",
      error: message,
      finishedAt: new Date().toISOString(),
    };
    try {
      return await deps.store.upsert(caseId, failed);
    } catch (err) {
      warn(`[socrates] job ${current.jobId}: could not record failure: ${(err as Error).message}`);
      return failed;
    }
  };

  let lastStatusError: string | null = null;
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    if (now() > deadline) break;
    let status: SocratesStatus;
    try {
      status = await deps.checkStatus(current.md5);
      lastStatusError = null;
    } catch (err) {
      const message = `SO-CRATES status check failed: ${(err as Error).message}`;
      if (!opts.tolerateStatusErrors) return await fail(message);
      lastStatusError = message;
      await sleep(intervalMs);
      continue;
    }

    if (status.status === "error")
      return await fail(status.message ?? "SO-CRATES reported an analysis failure");

    if (status.status === "ready") return await importReady(caseId, current, status, deps, fail, warn);

    // Still processing — record the phase so the dashboard can say "analyzing (network)". The phase
    // is a label: a failed save of it is reported and the poll goes on.
    if (status.phase && status.phase !== current.phase) {
      current = { ...current, phase: status.phase };
      await deps.store
        .upsert(caseId, current)
        .catch((err) =>
          warn(`[socrates] job ${current.jobId}: could not record phase: ${(err as Error).message}`),
        );
    }
    await sleep(intervalMs);
  }

  if (lastStatusError) return await fail(`${lastStatusError} (kept retrying until the time limit)`);
  return await fail(
    `SO-CRATES analysis timed out (${Math.round(totalMs / 60_000)} min, at most ${maxAttempts} checks). ` +
      `The server never reported this analysis ready — note that it returns "processing" for an ` +
      `unknown MD5 rather than a 404. Raise DFIR_TOOL_SOCRATES_TIMEOUT_MS for a slow analysis host.`,
  );
}

/**
 * The analysis is ready: record "importing", fetch and ingest the verdicts, record "imported".
 * Ingest only starts once "importing" is on disk, so a restart can tell a job that may have landed
 * verdicts from one that cannot have. A failure AFTER ingest succeeded never marks the job failed
 * (#2408) — its verdicts are in the case.
 */
async function importReady(
  caseId: string,
  ready: SocratesJob,
  status: SocratesStatus,
  deps: PollerDeps,
  fail: (message: string) => Promise<SocratesJob>,
  warn: (line: string) => void,
): Promise<SocratesJob> {
  const importing: SocratesJob = { ...ready, status: "importing", phase: status.phase };
  try {
    const stored = await deps.store.upsert(caseId, importing);
    // The store refuses to move a finished job: another writer already settled it, so importing
    // again would put its verdicts in the case twice (#2408).
    if (stored.status === "imported" || stored.status === "error") return stored;
  } catch (err) {
    return await fail(
      `Could not record the import start, so nothing was imported: ${(err as Error).message}`,
    );
  }

  let added: { addedEvents: number; addedIocs: number };
  try {
    const verdicts = await deps.fetchVerdicts(importing.md5);
    added = await deps.ingest(
      caseId,
      verdicts.text,
      `${importing.zipEntry ?? importing.sourceName}.socrates.json`,
    );
  } catch (err) {
    return await fail(
      `SO-CRATES result import failed: ${(err as Error).message}. Part of the result may already be ` +
        `in the case — check the timeline before re-running.`,
    );
  }

  const done: SocratesJob = {
    ...importing,
    status: "imported",
    addedEvents: added.addedEvents,
    addedIocs: added.addedIocs,
    finishedAt: new Date().toISOString(),
  };
  return await saveImported(caseId, done, deps, warn);
}

async function saveImported(
  caseId: string,
  done: SocratesJob,
  deps: PollerDeps,
  warn: (line: string) => void,
): Promise<SocratesJob> {
  const sleep = deps.sleep ?? defaultSleep;
  for (let i = 0; ; i++) {
    try {
      return await deps.store.upsert(caseId, done);
    } catch (err) {
      if (i >= SAVE_RETRY_DELAYS_MS.length) {
        warn(
          `[socrates] job ${done.jobId}: verdicts were imported but the job record could not be ` +
            `updated: ${(err as Error).message}`,
        );
        return done;
      }
      await sleep(SAVE_RETRY_DELAYS_MS[i]);
    }
  }
}
