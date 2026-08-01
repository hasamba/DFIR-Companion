import { stat } from "node:fs/promises";
import type { CaseStore } from "../storage/caseStore.js";
import type { StateStore } from "./stateStore.js";
import { getDiskStats } from "./diskWarn.js";
import type { OperationalMetricsStore } from "./operationalMetrics.js";

const CAPACITY_SAMPLE_INTERVAL_MS = 5 * 60 * 1000;

export async function sampleOperationalCapacity(
  cases: CaseStore,
  stateStore: StateStore,
  metrics: OperationalMetricsStore,
): Promise<void> {
  if (!metrics.enabled) return;
  const listed = await cases.listCases();
  const databaseBytes = (
    await Promise.all(
      listed.map(async (item) => {
        try {
          return (await stat(stateStore.databasePath(item.caseId))).size;
        } catch {
          return 0;
        }
      }),
    )
  ).reduce((sum, bytes) => sum + bytes, 0);
  const disk = await getDiskStats(cases.casesRoot);
  const memory = process.memoryUsage();
  await metrics.record({
    type: "capacity",
    databaseBytes,
    diskFreeBytes: disk.freeBytes,
    diskTotalBytes: disk.totalBytes,
    rssBytes: memory.rss,
    heapUsedBytes: memory.heapUsed,
  });
}

export function startOperationalCapacityMonitor(
  cases: CaseStore,
  stateStore: StateStore,
  metrics: OperationalMetricsStore,
  onError: (error: Error) => void,
): NodeJS.Timeout | null {
  if (!metrics.enabled) return null;
  const sample = (): void => {
    void sampleOperationalCapacity(cases, stateStore, metrics).catch((error: unknown) =>
      onError(error instanceof Error ? error : new Error(String(error))),
    );
  };
  sample();
  const timer = setInterval(sample, CAPACITY_SAMPLE_INTERVAL_MS);
  timer.unref();
  return timer;
}
