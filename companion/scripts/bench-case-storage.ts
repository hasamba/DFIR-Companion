import { mkdtemp, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { performance } from "node:perf_hooks";
import { CaseStore } from "../src/storage/caseStore.js";
import { StateStore } from "../src/analysis/stateStore.js";
import { emptyState, type ForensicEvent } from "../src/analysis/stateTypes.js";
import { percentile } from "../src/analysis/operationalDiagnostics.js";

interface BenchResult {
  events: number;
  databaseBytes: number;
  importMs: number;
  importEventsPerSecond: number;
  coldOpenMs: number;
  filteredQueryMs: number;
  queryP50Ms: number;
  queryP95Ms: number;
  filteredMatches: number;
  exportMs: number;
  exportedBytes: number;
  rssMiB: number;
  peakRssMiB: number;
}

const arg = (name: string): string | undefined => {
  const prefix = `--${name}=`;
  return process.argv.find((value) => value.startsWith(prefix))?.slice(prefix.length);
};

const sizes = (arg("sizes") ?? "1000000,10000000")
  .split(",")
  .map(Number)
  .filter((value) => Number.isSafeInteger(value) && value > 0);
const chunkSize = Math.max(100, Number(arg("chunk")) || 10_000);
const temporaryRoot = arg("temp-root") ?? tmpdir();
const queryRuns = Math.max(3, Number(arg("query-runs")) || 20);

function eventAt(index: number): ForensicEvent {
  return {
    id: `bench-${index}`,
    timestamp: new Date(Date.UTC(2026, 0, 1) + index * 1000).toISOString(),
    description: `Process execution benchmark row ${index}`,
    severity: index % 100 === 0 ? "High" : "Info",
    mitreTechniques: index % 10 === 0 ? ["T1059.001"] : [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset: `HOST-${String(index % 100).padStart(3, "0")}`,
    sources: ["benchmark"],
    artifactName: "Synthetic.Processes",
    processName: "powershell.exe",
    dstIp: `192.0.2.${(index % 250) + 1}`,
  };
}

async function benchmark(events: number): Promise<BenchResult> {
  const root = await mkdtemp(join(temporaryRoot, `dfir-storage-${events}-`));
  try {
    const cases = new CaseStore(root);
    const caseId = `bench-${events}`;
    await cases.createCase({ caseId, name: caseId, investigator: "benchmark", aiProvider: null });
    const store = new StateStore(cases);
    await store.save(emptyState(caseId));

    const importStart = performance.now();
    let peakRssBytes = process.memoryUsage().rss;
    for (let start = 0; start < events; start += chunkSize) {
      const count = Math.min(chunkSize, events - start);
      const chunk = Array.from({ length: count }, (_, offset) => eventAt(start + offset));
      await store.appendForensicEvents(caseId, chunk);
      peakRssBytes = Math.max(peakRssBytes, process.memoryUsage().rss);
    }
    const importMs = performance.now() - importStart;

    const coldStore = new StateStore(cases);
    const coldStart = performance.now();
    await coldStore.queryForensicTimeline(caseId, { limit: 1 });
    const coldOpenMs = performance.now() - coldStart;

    const queryDurations: number[] = [];
    let filteredMatches = 0;
    for (let run = 0; run < queryRuns; run++) {
      const queryStart = performance.now();
      const filtered = await coldStore.queryForensicTimeline(caseId, {
        host: "HOST-040",
        technique: "T1059.001",
        limit: 500,
      });
      queryDurations.push(performance.now() - queryStart);
      filteredMatches = filtered.total;
      peakRssBytes = Math.max(peakRssBytes, process.memoryUsage().rss);
    }
    const queryP50Ms = percentile(queryDurations, 0.5);
    const queryP95Ms = percentile(queryDurations, 0.95);

    let exportedBytes = 0;
    const exportStart = performance.now();
    for await (const batch of coldStore.forensicTimelineBatches(caseId, { limit: chunkSize })) {
      for (const event of batch) exportedBytes += Buffer.byteLength(`${JSON.stringify(event)}\n`);
      peakRssBytes = Math.max(peakRssBytes, process.memoryUsage().rss);
    }
    const exportMs = performance.now() - exportStart;
    const databaseBytes = (await stat(store.databasePath(caseId))).size;

    return {
      events,
      databaseBytes,
      importMs,
      importEventsPerSecond: importMs > 0 ? events / (importMs / 1000) : 0,
      coldOpenMs,
      filteredQueryMs: queryP50Ms,
      queryP50Ms,
      queryP95Ms,
      filteredMatches,
      exportMs,
      exportedBytes,
      rssMiB: process.memoryUsage().rss / 1024 / 1024,
      peakRssMiB: peakRssBytes / 1024 / 1024,
    };
  } finally {
    await rm(root, { recursive: true });
  }
}

if (!sizes.length) throw new Error("--sizes must contain at least one positive integer");
for (const size of sizes) {
  const result = await benchmark(size);
  process.stdout.write(`${JSON.stringify(result)}\n`);
}
