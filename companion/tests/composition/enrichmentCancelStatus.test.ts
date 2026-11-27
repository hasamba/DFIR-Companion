// Cancelling an enrichment run must not repaint the status pill over the job that takes its slot.
//
// Found live: Cancel frees the case's slot at once, so a queued second opinion started and set the
// pill to "running second opinion". The cancelled run was still finishing its current indicator, and
// its next progress push put "enriching IOC n/m" back on the pill for six minutes. Its closing
// push then said "idle" while the second opinion was still running.
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

const CASE_ID = "case-enrich-cancel";

const ioc = (id: string, value: string) => ({
  id,
  type: "domain" as const,
  value,
  firstSeen: new Date(0).toISOString(),
});

async function harness() {
  const root = await mkdtemp(join(tmpdir(), "dfir-enrich-cancel-"));
  const jobManager = new JobManager({ perCaseConcurrency: 1 });
  const lookups: string[] = [];
  let release = (): void => {};
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  const provider: EnrichmentProvider = {
    name: "MISP",
    scope: "local",
    supports: () => true,
    lookup: async (_kind, value) => {
      lookups.push(value);
      await gate;
      return null;
    },
  };
  let current: InvestigationState = {
    ...emptyState(CASE_ID),
    iocs: [ioc("ioc-1", "evilcorp.test"), ioc("ioc-2", "badguy.test")],
  };
  const load = async () => ({ ...current, iocs: [...current.iocs] });
  let saves = 0;
  const save = async (next: InvestigationState) => {
    current = next;
    saves++;
  };
  const statuses: { status: string; detail?: string }[] = [];
  const options = {
    enrichmentProviders: [provider],
    stateStore: { load, save, loadOverview: load, saveOverview: save },
    jobManager,
    enrichDelayMs: 0,
    onAiStatus: (_caseId: string, s: { status: string; detail?: string }) => statuses.push(s),
  } as unknown as AppOptions;
  const engine = createEnrichmentEngine({
    store: new CaseStore(root),
    options,
    runStateExclusive: async (_caseId, fn) => fn(),
  });
  return { engine, jobManager, lookups, statuses, release: () => release(), saveCount: () => saves };
}

describe("cancelling an enrichment run in flight", () => {
  it("leaves the status pill to the job that took the freed slot", async () => {
    const h = await harness();
    h.engine.autoEnrichIfEnabled(CASE_ID);
    await pollFor(
      () => `the run to reach its first lookup, last saw ${JSON.stringify(h.lookups)}`,
      async () => (h.lookups.length > 0 ? true : undefined),
    );

    const enrichJob = h.jobManager.list(CASE_ID).find((j) => j.kind === "enrichment")!;
    await h.jobManager.cancel(enrichJob.id);
    // The second opinion is admitted into the freed slot and owns the pill from here.
    const next = h.jobManager.register({ caseId: CASE_ID, kind: "second-opinion", label: "second opinion" });
    await next.ready;
    const sinceCancel = h.statuses.length;

    h.release(); // the in-flight lookup returns
    await pollFor(
      () => `the cancelled run to save what it finished, last saw ${h.saveCount()} save(s)`,
      async () => (h.saveCount() > 0 ? true : undefined),
    );
    // Its closing status push comes right after the save; let it land before asserting silence.
    await new Promise((resolve) => setTimeout(resolve, 50));

    expect(h.lookups).toEqual(["evilcorp.test"]); // stopped before the next indicator
    // Nothing the cancelled run pushed may claim the pill — no progress, no "idle".
    expect(h.statuses.slice(sinceCancel)).toEqual([]);
  });

  it("still reports the cancel when nothing else is running on the case", async () => {
    const h = await harness();
    h.engine.autoEnrichIfEnabled(CASE_ID);
    await pollFor(
      () => `the run to reach its first lookup, last saw ${JSON.stringify(h.lookups)}`,
      async () => (h.lookups.length > 0 ? true : undefined),
    );
    const enrichJob = h.jobManager.list(CASE_ID).find((j) => j.kind === "enrichment")!;
    await h.jobManager.cancel(enrichJob.id);
    const sinceCancel = h.statuses.length;

    h.release();
    await pollFor(
      () => `the cancelled run to report idle, last saw ${JSON.stringify(h.statuses.slice(sinceCancel))}`,
      async () => (h.statuses.slice(sinceCancel).some((s) => s.status === "idle") ? true : undefined),
    );
    expect(h.statuses.slice(sinceCancel).filter((s) => s.status === "analyzing")).toEqual([]);
  });
});
