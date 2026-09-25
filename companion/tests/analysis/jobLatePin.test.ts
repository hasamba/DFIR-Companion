// A job whose model is known only once its work starts (#1629): the drop-folder sweep reads each
// file before it knows whether a model will run. The job gets a signal at registration (so the
// #1601 served-model stamp can find it) without becoming cancellable, and names its model the
// moment a model is about to run — never earlier, never twice.
import { describe, expect, it, vi } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { JobManager } from "../../src/analysis/jobManager.js";
import { createJob, emptyJobTable, finishJob, getJob, pinJobModel } from "../../src/analysis/jobRegistry.js";
import { ServedModelRegistry } from "../../src/analysis/servedModels.js";
import { JobLedgerStore } from "../../src/analysis/jobLedgerStore.js";

const T0 = "2026-09-25T00:00:00.000Z";
const SONNET = { model: "sonnet", provider: "claude-code" };
const CSV = { kind: "import" as const, parameters: { kind: "csv" } };

function manager(registry = new ServedModelRegistry(), ledger?: JobLedgerStore): JobManager {
  const jobs = new JobManager({ now: () => T0, ...(ledger ? { ledger } : {}) });
  // The real resolver's rule for imports: only a csv/log kind names the text model.
  jobs.useModelResolver((input) =>
    input.kind === "import" && input.parameters?.kind === "csv" ? SONNET : undefined,
  );
  jobs.useServedModels(registry);
  return jobs;
}

describe("modelCallSignal", () => {
  it("hands the caller a signal but the job stays non-cancellable", async () => {
    const jobs = manager();
    const { jobId, signal } = jobs.register({ caseId: "c1", kind: "import", modelCallSignal: true });
    expect(signal).toBeInstanceOf(AbortSignal);
    expect(jobs.get(jobId)!.cancellable).toBe(false);
    expect(await jobs.cancel(jobId)).toEqual({ ok: false, reason: "not-cancellable" });
    expect(signal!.aborted).toBe(false);
  });

  it("gives no signal without it (unchanged default)", () => {
    const jobs = manager();
    expect(jobs.register({ caseId: "c1", kind: "import" }).signal).toBeUndefined();
  });
});

describe("JobManager.pinModel", () => {
  it("names the model late, then the served stamp finds the job by its signal", async () => {
    const registry = new ServedModelRegistry();
    const jobs = manager(registry);
    const { jobId, signal, ready } = jobs.register({ caseId: "c1", kind: "import", modelCallSignal: true });
    await ready;
    expect(jobs.get(jobId)!.model).toBeUndefined();
    jobs.pinModel(jobId, CSV);
    expect(jobs.get(jobId)).toMatchObject({ model: "sonnet", modelProvider: "claude-code" });
    registry.record({ provider: "claude-code", alias: "sonnet", resolvedModel: "claude-sonnet-5", signal });
    await jobs.finish(jobId);
    expect(jobs.list("c1")[0].modelLabel).toBe("sonnet → Sonnet 5");
  });

  it("a provider that reports no served version leaves the alias only", async () => {
    const registry = new ServedModelRegistry();
    const jobs = manager(registry);
    const { jobId, signal } = jobs.register({ caseId: "c1", kind: "import", modelCallSignal: true });
    jobs.pinModel(jobId, CSV);
    registry.record({ provider: "claude-code", alias: "sonnet", resolvedModel: undefined, signal });
    await jobs.finish(jobId);
    expect(jobs.list("c1")[0].modelLabel).toBe("sonnet");
  });

  it("names nothing when the resolver says no model runs", () => {
    const jobs = manager();
    const { jobId } = jobs.register({ caseId: "c1", kind: "import", modelCallSignal: true });
    jobs.pinModel(jobId, { kind: "import", parameters: { kind: "evtx" } });
    expect(jobs.get(jobId)!.model).toBeUndefined();
  });

  it("never overwrites a model already pinned", () => {
    const jobs = manager();
    const { jobId } = jobs.register({
      caseId: "c1",
      kind: "import",
      modelCallSignal: true,
      model: { model: "opus", provider: "claude-code" },
    });
    jobs.pinModel(jobId, CSV);
    expect(jobs.get(jobId)!.model).toBe("opus");
  });

  it("persists the late pin to the ledger", async () => {
    const store = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-1629-")));
    await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const ledger = new JobLedgerStore(store);
    const jobs = manager(new ServedModelRegistry(), ledger);
    await jobs.ready();
    const { jobId, ready } = jobs.register({ caseId: "c1", kind: "import", modelCallSignal: true });
    await ready;
    jobs.pinModel(jobId, CSV);
    await vi.waitFor(async () => {
      const [row] = await ledger.list("c1");
      expect(row).toMatchObject({ id: jobId, model: "sonnet", modelProvider: "claude-code" });
    });
  });
});

describe("pinJobModel", () => {
  const base = () =>
    createJob(emptyJobTable(), { id: "job_1", caseId: "c1", kind: "import", status: "running", now: T0 });

  it("pins model and provider", () => {
    const job = getJob(
      pinJobModel(base(), "job_1", { model: "sonnet", modelProvider: "claude-code" }, T0),
      "job_1",
    );
    expect(job).toMatchObject({ model: "sonnet", modelProvider: "claude-code" });
  });

  it("is a no-op on a finished job, an already-pinned job, or an empty identity", () => {
    const finished = finishJob(base(), "job_1", T0);
    expect(pinJobModel(finished, "job_1", { model: "sonnet" }, T0)).toBe(finished);
    const pinned = pinJobModel(base(), "job_1", { model: "opus" }, T0);
    expect(pinJobModel(pinned, "job_1", { model: "sonnet" }, T0)).toBe(pinned);
    const table = base();
    expect(pinJobModel(table, "job_1", {}, T0)).toBe(table);
  });
});
