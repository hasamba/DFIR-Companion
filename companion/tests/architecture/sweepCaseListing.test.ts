// AI Agent Forensics (#2690): every place that lists cases decides, on purpose, whether a hidden sweep
// case belongs in it. Analyst-facing lists filter it out with isAnalystCase; background and recovery
// readers keep it, or a sweep's hunt would be stranded after a restart. A NEW listCases() call site
// fails here until it is classified below.
import { describe, expect, it } from "vitest";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";

const SRC = join(import.meta.dirname, "..", "..", "src");

const ANALYST_FACING = new Set([
  "routes/caseLifecycle.ts", // GET /cases — every browser case picker reads it
  "routes/crossCase.ts", // cross-case IOC search: "other cases with this IOC"
  "routes/huntClient.ts", // #2670 earlier hunts of the same client: analyst cases the caller may open
]);
const KEEPS_SWEEPS = new Set([
  "routes/caseIdentity.ts", // next case id: a sweep's id is still taken
  "routes/serverSets.ts", // names the cases that use a set before a delete
  "routes/supportBundleRoutes.ts", // lock-state gate for the bundle's case log
  "reports/supportBundleBuilder.ts", // redaction vocabulary over every case id
  "routes/diagnosticsReport.ts", // diagnostics counts
  "routes/system.ts", // disk usage per case: sweep evidence uses real disk
  "composition/watsonVeloRecovery.ts",
  "composition/captureAnalysis.ts",
  "composition/socratesJobRunner.ts",
  "composition/runtimeStores.ts", // audit exporter
  "composition/cloudCollectRecovery.ts",
  "composition/veloHuntStatusTimers.ts", // a sweep's hunt must keep being polled and collected
  "composition/dropFolder.ts",
  "composition/maintenanceTasks.ts",
  "composition/veloMonitors.ts",
  "analysis/operationalCapacity.ts",
  "analysis/custodyIntegrity.ts",
  "analysis/jobLedgerStore.ts",
  "integrations/velociraptor/aiAgentRuns.ts", // the panel's own sweep list and retention
]);
const REMOTE = new Set(["integrations/iris/irisImportFetch.ts", "routes/reportsExport.ts"]); // IRIS's cases, not ours

function walk(dir: string): string[] {
  return readdirSync(dir).flatMap((n) => {
    const full = join(dir, n);
    return statSync(full).isDirectory() ? walk(full) : n.endsWith(".ts") ? [full] : [];
  });
}

const callers = walk(SRC)
  .filter((f) => /\.listCases\(\)/.test(readFileSync(f, "utf8")))
  .map((f) => relative(SRC, f).split(sep).join("/"))
  .filter((f) => f !== "storage/caseStore.ts");

describe("sweep cases and the case lists", () => {
  it("classifies every listCases() call site", () => {
    const unclassified = callers.filter(
      (f) => !ANALYST_FACING.has(f) && !KEEPS_SWEEPS.has(f) && !REMOTE.has(f),
    );
    expect(unclassified).toEqual([]);
  });

  it("filters sweep cases out of every analyst-facing list", () => {
    for (const f of ANALYST_FACING) expect(readFileSync(join(SRC, f), "utf8")).toContain("isAnalystCase");
  });
});
