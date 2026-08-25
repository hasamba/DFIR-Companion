// A case with more enrichable IOCs than DFIR_ENRICH_MAX must still get ALL of them enriched.
//
// Reported: an analyst imported artifacts with enrichment off, collected more than 100 IOCs, then
// turned enrichment on. Exactly 100 were enriched. Re-opening the enrichment panel and pressing OK
// enriched the rest. The cap in enrichIocs cut the candidate list at `maxIocs` and the run ended
// there — nothing continued, and nothing said how many were left behind, because `summary.skipped`
// merges "already enriched" with "cut by the cap" into one number.
//
// The cap bounds how long ONE run holds the case's concurrency slot; it was never meant to abandon
// work. So a capped run now chains a follow-up batch after it saves, bounded by `enrichMaxBatches`.
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

const CASE_ID = "case-over-cap";

const ioc = (n: number) => ({
  id: `ioc-${n}`,
  type: "domain" as const,
  value: `host${String(n).padStart(3, "0")}.test`,
  firstSeen: new Date(0).toISOString(),
});

async function harness(opts: {
  iocCount: number;
  maxIocs: number;
  maxBatches?: number;
  /** Return false to make the provider report itself DOWN for this run. */
  probeOk?: () => boolean;
  /** Start with every IOC already checked by MISP — the state a `force` re-run has to get past. */
  preEnriched?: boolean;
  /** Awaited after each lookup, so a test can cancel the job and have it LAND mid-batch. */
  afterLookup?: (n: number, jm: JobManager) => Promise<void> | void;
}) {
  const root = await mkdtemp(join(tmpdir(), "dfir-enrich-batch-"));
  const store = new CaseStore(root);
  const jobManager = new JobManager({ perCaseConcurrency: 1 });

  const lookups: string[] = [];
  const provider: EnrichmentProvider = {
    name: "MISP",
    scope: "local",
    supports: () => true,
    lookup: async (_kind, value) => {
      lookups.push(value);
      await opts.afterLookup?.(lookups.length, jobManager);
      return null; // a miss still marks the IOC checked via enrichedBy
    },
    // probe() signals DOWN by throwing, not by a return value.
    ...(opts.probeOk
      ? {
          probe: async () => {
            if (!opts.probeOk!()) throw new Error("MISP unreachable");
          },
        }
      : {}),
  };

  let current: InvestigationState = {
    ...emptyState(CASE_ID),
    iocs: Array.from({ length: opts.iocCount }, (_, i) =>
      opts.preEnriched ? { ...ioc(i + 1), enrichedBy: ["MISP"], enrichments: [] } : ioc(i + 1),
    ),
  };
  const stateStore = {
    load: async () => ({ ...current, iocs: [...current.iocs] }),
    save: async (next: InvestigationState) => {
      current = next;
    },
  };

  const statuses: { status: string; detail?: string }[] = [];
  const options = {
    enrichmentProviders: [provider],
    stateStore,
    jobManager,
    enrichDelayMs: 0,
    enrichMaxIocs: opts.maxIocs,
    enrichMaxBatches: opts.maxBatches,
    enrichHealthPollMs: 0, // no recovery poller — this test drives the batches, not the poller
    onAiStatus: (_caseId: string, s: { status: string; detail?: string }) => statuses.push(s),
  } as unknown as AppOptions;

  const engine = createEnrichmentEngine({
    store,
    options,
    runStateExclusive: async (_caseId, fn) => fn(),
  });

  return {
    engine,
    lookups,
    statuses,
    unchecked: () => current.iocs.filter((i) => (i.enrichedBy ?? []).length === 0).length,
    idle: () => statuses.filter((s) => s.status === "idle"),
  };
}

/**
 * Wait for exactly `n` finished batches, then prove no `n + 1`th starts.
 *
 * Counting idle statuses is the deterministic signal: every batch announces idle once when it
 * saves. Polling for "lookups stopped growing" is not — the gap between two back-to-back batches
 * (save, register, await job.ready) looks identical to the end of the chain.
 */
async function settledBatches(h: { idle: () => unknown[]; lookups: string[] }, n: number): Promise<void> {
  await pollFor(
    () => `${n} finished batch(es), last saw ${h.idle().length}`,
    async () => (h.idle().length >= n ? true : undefined),
  );
  const after = h.lookups.length;
  await new Promise((r) => setTimeout(r, 100)); // long enough for another batch to have queried
  expect(h.idle()).toHaveLength(n); // no batch n+1 started
  expect(h.lookups).toHaveLength(after);
}

describe("enrichment when the case has more IOCs than the per-run cap", () => {
  it("enriches every IOC by chaining batches, not just the first capped run", async () => {
    const h = await harness({ iocCount: 250, maxIocs: 100 });

    h.engine.autoEnrichIfEnabled(CASE_ID); // one kick — the analyst turning enrichment on
    await settledBatches(h, 3); // 250 IOCs / 100 per batch

    // The bug: 100 lookups, 150 IOCs left untouched, and the analyst had to press OK again.
    expect(h.lookups).toHaveLength(250);
    expect(new Set(h.lookups).size).toBe(250); // no IOC paid a rate-limited provider twice
    expect(h.unchecked()).toBe(0);
  });

  it("stops at enrichMaxBatches instead of chaining forever on a very large case", async () => {
    const h = await harness({ iocCount: 250, maxIocs: 10, maxBatches: 3 });

    h.engine.autoEnrichIfEnabled(CASE_ID);
    await settledBatches(h, 3);

    expect(h.lookups).toHaveLength(30); // 3 batches × 10
    expect(h.unchecked()).toBe(220);
  });

  it("says how many IOCs the cap left behind, instead of folding them into 'skipped'", async () => {
    const h = await harness({ iocCount: 250, maxIocs: 10, maxBatches: 2 });

    h.engine.autoEnrichIfEnabled(CASE_ID);
    await settledBatches(h, 2);

    // The analyst must be able to see that work remains without counting rows by hand.
    const last = h.idle().at(-1) as { detail?: string };
    expect(last.detail).toMatch(/230 IOC\(s\) left by the cap/);
    expect(last.detail).toMatch(/DFIR_ENRICH_MAX/);
  });

  it("does not chain a batch that made no progress, so a down provider cannot spin the cap", async () => {
    // Every provider probes DOWN: the run queries nothing, so continuing would burn the whole
    // batch budget re-probing a dead server. The health poller owns recovery, not the chain.
    const h = await harness({ iocCount: 250, maxIocs: 10, maxBatches: 5, probeOk: () => false });

    h.engine.autoEnrichIfEnabled(CASE_ID);
    await settledBatches(h, 1); // one run, no chain

    expect(h.lookups).toEqual([]);
  });

  // `enrichedBy` is what normally advances the chain's cursor — and `force` exists precisely to
  // ignore it. Without a separate record of what each batch attempted, a forced chain re-queries
  // the same first N indicators every batch and never reaches the rest.
  it("advances a forced re-run past the cap, instead of re-querying the same IOCs each batch", async () => {
    const h = await harness({ iocCount: 25, maxIocs: 10, preEnriched: true });

    h.engine.enrichInBackground(CASE_ID, true); // force: re-check even already-enriched IOCs
    await settledBatches(h, 3);

    expect(h.lookups).toHaveLength(25);
    expect(new Set(h.lookups).size).toBe(25); // each indicator re-checked once, not three times
  });

  it("stops the chain when the analyst cancels, rather than starting the next batch", async () => {
    const h = await harness({
      iocCount: 250,
      maxIocs: 10,
      maxBatches: 9,
      // Cancel inside batch 2, and AWAIT it, so the abort has landed before enrichIocs reaches its
      // between-IOC check. Firing it un-awaited would only reproduce a race this test does not own:
      // with delayMs 0 a whole batch finishes inside the millisecond the cancel takes to settle,
      // which cannot happen at the 1500ms production throttle.
      afterLookup: async (n, jm) => {
        if (n !== 12) return;
        const job = jm.list(CASE_ID).find((j) => j.kind === "enrichment" && j.status === "running");
        if (job) await jm.cancel(job.id); // list() yields Job (.id), not RegisteredJob (.jobId)
      },
    });

    h.engine.autoEnrichIfEnabled(CASE_ID);
    await pollFor(
      () => `the cancelled batch to end, last saw ${h.lookups.length} lookup(s)`,
      async () => (h.lookups.length >= 12 ? true : undefined),
    );
    await new Promise((r) => setTimeout(r, 150)); // room for batches 3+ to have started

    expect(h.lookups).toHaveLength(12); // batch 2 stopped where it was told; batch 3 never ran
  });
});
