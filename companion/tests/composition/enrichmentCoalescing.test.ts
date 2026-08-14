// A multi-file import must produce ONE enrichment run, not one per file.
//
// The sibling of tests/composition/resynthesisCoalescing.test.ts. Fixing the synthesis kick did not
// reach this path: with AI off (or no synthesis model configured) resynthesizeInBackground returns
// early and calls autoEnrichIfEnabled directly, BEFORE the exclusive registration that collapses
// the synthesis kicks. So a six-file import still queued six enrichment jobs — the reported
// "enrichment is queued ×6" cards in the cockpit.
import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { JobManager } from "../../src/analysis/jobManager.js";
import { createEnrichmentEngine } from "../../src/composition/enrichment.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import { pollFor } from "../helpers/poll.js";
import type { AppOptions } from "../../src/composition/appOptions.js";
import type { EnrichmentProvider } from "../../src/enrichment/provider.js";
import type { InvestigationState } from "../../src/analysis/stateTypes.js";

const CASE_ID = "case-multi-import";

async function harness() {
  const root = await mkdtemp(join(tmpdir(), "dfir-enrich-"));
  const store = new CaseStore(root);
  // perCaseConcurrency: 1 — the production default once the durable ledger is wired, and what makes
  // the kicks queue behind one another instead of running side by side.
  const jobManager = new JobManager({ perCaseConcurrency: 1 });

  const lookups: string[] = [];
  // scope "local" so the case enables it by default — external providers are opt-in per case.
  const provider: EnrichmentProvider = {
    name: "MISP",
    scope: "local",
    supports: () => true,
    lookup: async (_kind, value) => {
      lookups.push(value);
      return null;
    },
  };

  const state: InvestigationState = {
    ...emptyState(CASE_ID),
    iocs: [{ id: "ioc-1", type: "domain", value: "evilcorp.com", firstSeen: new Date(0).toISOString() }],
  };
  const saved: InvestigationState[] = [];
  const stateStore = {
    load: async () => state,
    save: async (next: InvestigationState) => {
      saved.push(next);
    },
  };

  const statuses: { status: string; detail?: string }[] = [];
  const options = {
    enrichmentProviders: [provider],
    stateStore,
    jobManager,
    enrichDelayMs: 0,
    onAiStatus: (_caseId: string, s: { status: string; detail?: string }) => statuses.push(s),
  } as unknown as AppOptions;

  const engine = createEnrichmentEngine({
    store,
    options,
    runStateExclusive: async (_caseId, fn) => fn(),
  });

  return { engine, jobManager, lookups, statuses };
}

const KICKS = 6;

const enrichmentJobs = (jm: JobManager) => jm.list(CASE_ID).filter((j) => j.kind === "enrichment");
const liveEnrichmentJobs = (jm: JobManager) => enrichmentJobs(jm).filter((j) => j.status !== "cancelled");

/**
 * Wait until all six kicks have REGISTERED. A kick reads the case's enrich-control file and its
 * state before it registers, so the barrier has to be a wall-clock poll on the observable outcome —
 * spinning a fixed number of microtask turns is exactly the pattern helpers/poll.ts was written to
 * replace, and under a loaded run it samples before the disk reads land and sees zero jobs.
 */
const allKicksRegistered = (jm: JobManager) =>
  pollFor(
    () => `${KICKS} enrichment registrations, last saw ${enrichmentJobs(jm).length}`,
    async () => (enrichmentJobs(jm).length >= KICKS ? true : undefined),
  );

describe("enrichment after a multi-file import", () => {
  it("collapses one kick per imported file into a single surviving enrichment job", async () => {
    const { engine, jobManager, lookups } = await harness();

    // Occupy the case's single concurrency slot the way an in-flight import does.
    const importJob = jobManager.register({ caseId: CASE_ID, kind: "import", label: "evtx" });
    await importJob.ready;

    // Six files in one import → six kicks.
    for (let i = 0; i < KICKS; i++) engine.autoEnrichIfEnabled(CASE_ID);
    await allKicksRegistered(jobManager);

    const live = liveEnrichmentJobs(jobManager);
    expect(live).toHaveLength(1); // the other five superseded each other
    expect(live[0].status).toBe("queued");
    expect(lookups).toEqual([]); // nothing queries while the import still holds the slot

    // Import finishes → the one surviving kick is admitted and queries each IOC once.
    await jobManager.finish(importJob.jobId);
    await pollFor(
      () => `the surviving run to query its IOC, last saw ${JSON.stringify(lookups)}`,
      async () => (lookups.length > 0 ? true : undefined),
    );
    expect(lookups).toEqual(["evilcorp.com"]);
  });

  it("does not report a superseded run's outcome over the newer kick", async () => {
    const { engine, jobManager, statuses } = await harness();

    const importJob = jobManager.register({ caseId: CASE_ID, kind: "import", label: "evtx" });
    await importJob.ready;
    for (let i = 0; i < KICKS; i++) engine.autoEnrichIfEnabled(CASE_ID);
    await allKicksRegistered(jobManager);
    // Give every superseded kick's rejection handler a turn to run before asserting on silence.
    await pollFor(
      () => `${KICKS - 1} superseded kicks, last saw ${KICKS - liveEnrichmentJobs(jobManager).length}`,
      async () => (liveEnrichmentJobs(jobManager).length === 1 ? true : undefined),
    );

    // A superseded kick must stay silent: the newer run owns the status banner, and an "enriched
    // 0/0" or error message from a cancelled one leaves the dashboard contradicting live progress.
    expect(statuses.filter((s) => s.status === "idle" || s.status === "error")).toEqual([]);
  });
});
