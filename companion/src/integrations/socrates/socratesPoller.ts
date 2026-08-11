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
}

// 5s × 240 = 20 minutes, enough for Suricata over a large PCAP. The ceiling is NOT optional:
// SO-CRATES never 404s a well-formed but unknown MD5 — it answers "processing" forever — so
// without this a typo'd or deleted analysis polls until the process dies.
const DEFAULT_INTERVAL_MS = 5_000;
const DEFAULT_MAX_ATTEMPTS = 240;

const defaultSleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

export async function pollUntilImported(
  caseId: string,
  job: SocratesJob,
  deps: PollerDeps,
  opts: { maxAttempts?: number; intervalMs?: number } = {},
): Promise<SocratesJob> {
  const maxAttempts = opts.maxAttempts ?? DEFAULT_MAX_ATTEMPTS;
  const intervalMs = opts.intervalMs ?? DEFAULT_INTERVAL_MS;
  const sleep = deps.sleep ?? defaultSleep;

  const fail = async (message: string): Promise<SocratesJob> => {
    const failed: SocratesJob = {
      ...job,
      status: "error",
      error: message,
      finishedAt: new Date().toISOString(),
    };
    await deps.store.upsert(caseId, failed);
    return failed;
  };

  let current = job;
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    let status: SocratesStatus;
    try {
      status = await deps.checkStatus(current.md5);
    } catch (err) {
      return await fail(`SO-CRATES status check failed: ${(err as Error).message}`);
    }

    if (status.status === "error")
      return await fail(status.message ?? "SO-CRATES reported an analysis failure");

    if (status.status === "ready") {
      current = { ...current, status: "importing", phase: status.phase };
      await deps.store.upsert(caseId, current);
      try {
        const verdicts = await deps.fetchVerdicts(current.md5);
        const name = `${current.zipEntry ?? current.sourceName}.socrates.json`;
        const r = await deps.ingest(caseId, verdicts.text, name);
        const done: SocratesJob = {
          ...current,
          status: "imported",
          addedEvents: r.addedEvents,
          addedIocs: r.addedIocs,
          finishedAt: new Date().toISOString(),
        };
        await deps.store.upsert(caseId, done);
        return done;
      } catch (err) {
        return await fail(`SO-CRATES result import failed: ${(err as Error).message}`);
      }
    }

    // Still processing — record the phase so the dashboard can say "analyzing (network)".
    if (status.phase && status.phase !== current.phase) {
      current = { ...current, phase: status.phase };
      await deps.store.upsert(caseId, current);
    }
    await sleep(intervalMs);
  }

  return await fail(
    `SO-CRATES analysis timed out after ${maxAttempts} checks. The server never reported this ` +
      `analysis ready — note that it returns "processing" for an unknown MD5 rather than a 404.`,
  );
}
