import { describe, expect, it } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { JobLedgerStore } from "../../src/analysis/jobLedgerStore.js";
import { JobManager } from "../../src/analysis/jobManager.js";
import { pollFor } from "../helpers/poll.js";

function clock(): () => string {
  let second = 0;
  return () => `2026-07-31T00:00:${String(second++).padStart(2, "0")}.000Z`;
}

async function harness(
  options: {
    globalConcurrency?: number;
    perCaseConcurrency?: number;
    max?: number;
  } = {},
) {
  const root = await mkdtemp(join(tmpdir(), "dfir-job-ledger-"));
  const cases = new CaseStore(root);
  for (const caseId of ["case-a", "case-b"]) {
    await cases.createCase({ caseId, name: caseId, investigator: "analyst", aiProvider: null });
  }
  const ledger = new JobLedgerStore(cases);
  const manager = new JobManager({
    ledger,
    now: clock(),
    id: (() => {
      let id = 0;
      return () => `job_test_${++id}`;
    })(),
    ...options,
  });
  await manager.ready();
  return { cases, ledger, manager };
}

describe("durable job ledger", () => {
  it("restores a running job as interrupted with its stable id and last committed checkpoint", async () => {
    const { ledger, manager } = await harness();
    const registered = manager.register({
      caseId: "case-a",
      kind: "import",
      label: "csv: evidence.csv",
      cancellable: true,
      idempotencyKey: "import:sha256:abc",
      parameters: {
        artifact: "imports/0001_evidence.csv",
        providerToken: "must-not-survive",
      },
    });
    await registered.ready;
    await manager.checkpoint(registered.jobId, {
      done: 3,
      total: 10,
      detail: "batch 3 committed",
      cursor: { batch: 3 },
    });

    const restarted = new JobManager({
      ledger,
      now: clock(),
      id: () => "job_after_restart",
    });
    await restarted.ready();

    expect(restarted.get(registered.jobId)).toMatchObject({
      id: registered.jobId,
      status: "interrupted",
      progress: { done: 3, total: 10 },
      lastCheckpoint: {
        progress: { done: 3, total: 10 },
        cursor: { batch: 3 },
      },
    });
    expect(restarted.get(registered.jobId)?.parameters).toEqual({
      artifact: "imports/0001_evidence.csv",
      providerToken: "[REDACTED]",
    });
  });

  it("deduplicates repeated registration by case and idempotency key", async () => {
    const { manager } = await harness();
    const first = manager.register({
      caseId: "case-a",
      kind: "import",
      idempotencyKey: "import:sha256:def",
    });
    await first.ready;
    const repeated = manager.register({
      caseId: "case-a",
      kind: "import",
      idempotencyKey: "import:sha256:def",
    });

    expect(repeated.jobId).toBe(first.jobId);
    expect(repeated.reused).toBe(true);
    expect(manager.list("case-a")).toHaveLength(1);
  });

  it("keeps capacity for another case instead of letting one case occupy every worker", async () => {
    const { manager } = await harness({ globalConcurrency: 2, perCaseConcurrency: 1 });
    const firstA = manager.register({ caseId: "case-a", kind: "import" });
    const secondA = manager.register({ caseId: "case-a", kind: "enrichment", cancellable: true });
    const firstB = manager.register({ caseId: "case-b", kind: "synthesis", cancellable: true });

    await Promise.all([firstA.ready, firstB.ready]);
    expect(manager.get(firstA.jobId)?.status).toBe("running");
    expect(manager.get(firstB.jobId)?.status).toBe("running");
    expect(manager.get(secondA.jobId)?.status).toBe("queued");

    await manager.finish(firstA.jobId);
    await secondA.ready;
    expect(manager.get(secondA.jobId)?.status).toBe("running");
  });

  it("cancels a queued job deterministically before its work can start", async () => {
    const { manager } = await harness({ globalConcurrency: 1, perCaseConcurrency: 1 });
    const running = manager.register({ caseId: "case-a", kind: "import" });
    await running.ready;
    const queued = manager.register({
      caseId: "case-b",
      kind: "synthesis",
      cancellable: true,
    });
    expect(manager.get(queued.jobId)?.status).toBe("queued");

    const result = await manager.cancel(queued.jobId);

    expect(result.ok).toBe(true);
    expect(queued.signal?.aborted).toBe(true);
    await expect(queued.ready).rejects.toMatchObject({ name: "AbortError" });
    expect(manager.get(queued.jobId)?.status).toBe("cancelled");
  });

  it("records structured failures and refuses work beyond the retry budget", async () => {
    const { manager } = await harness();
    const job = manager.register({
      caseId: "case-a",
      kind: "enrichment",
      cancellable: true,
      resumable: true,
      maxRetries: 1,
    });
    await job.ready;

    await manager.fail(job.jobId, new Error("provider unavailable"), {
      code: "provider_unavailable",
      retryable: true,
    });

    expect(manager.get(job.jobId)).toMatchObject({
      status: "failed",
      maxRetries: 1,
      failure: {
        code: "provider_unavailable",
        message: "provider unavailable",
        retryable: true,
      },
    });
    manager.registerResumeHandler("enrichment", async () => {
      throw new Error("provider is still unavailable");
    });
    expect(await manager.resume(job.jobId)).toMatchObject({ ok: true });
    await pollFor("retried job failing", async () => {
      return manager.get(job.jobId)?.status === "failed" ? true : undefined;
    });
    expect(await manager.resume(job.jobId)).toEqual({
      ok: false,
      reason: "retry-exhausted",
    });
  });

  it("resumes an interrupted job with the same id and durable checkpoint", async () => {
    const { ledger, manager } = await harness();
    const registered = manager.register({
      caseId: "case-a",
      kind: "deep-pass",
      cancellable: true,
      resumable: true,
      maxRetries: 1,
      parameters: { minSeverity: "High" },
    });
    await registered.ready;
    await manager.checkpoint(registered.jobId, {
      done: 2,
      total: 5,
      cursor: { nextBatch: 2 },
    });

    const restarted = new JobManager({
      ledger,
      now: clock(),
      id: () => "job_must_not_replace_the_interrupted_id",
    });
    await restarted.ready();
    let resumedFrom: unknown;
    restarted.registerResumeHandler("deep-pass", async (job) => {
      resumedFrom = job.lastCheckpoint?.cursor;
    });

    const result = await restarted.resume(registered.jobId);
    expect(result).toMatchObject({
      ok: true,
      job: { id: registered.jobId, attempt: 2 },
    });
    const terminal = await pollFor("resumed job reaching succeeded", async () => {
      const job = restarted.get(registered.jobId);
      return job?.status === "succeeded" ? job : undefined;
    });

    expect(terminal.id).toBe(registered.jobId);
    expect(resumedFrom).toEqual({ nextBatch: 2 });
    expect(await restarted.resume(registered.jobId)).toEqual({
      ok: false,
      reason: "not-interrupted",
    });
  });

  it("can promote an older non-cancellable EVTX job when its resume handler is cooperative", async () => {
    const { ledger, manager } = await harness();
    const registered = manager.register({
      caseId: "case-a",
      kind: "import",
      resumable: true,
      maxRetries: 1,
      parameters: { kind: "evtxxml" },
    });
    await registered.ready;

    const restarted = new JobManager({ ledger, now: clock() });
    await restarted.ready();
    let receivedSignal: AbortSignal | undefined;
    restarted.registerResumeHandler(
      "import",
      async (_job, signal) => {
        receivedSignal = signal;
        await new Promise<void>((resolve) => {
          signal?.addEventListener("abort", () => resolve(), { once: true });
        });
      },
      { cancellable: (job) => job.parameters?.kind === "evtxxml" },
    );

    const result = await restarted.resume(registered.jobId);
    expect(result).toMatchObject({
      ok: true,
      job: { id: registered.jobId, cancellable: true },
    });
    await pollFor("resumed EVTX job starting", async () => {
      return restarted.get(registered.jobId)?.status === "running" ? true : undefined;
    });

    expect(receivedSignal).toBeInstanceOf(AbortSignal);
    expect(await restarted.cancel(registered.jobId)).toMatchObject({ ok: true });
    expect(receivedSignal?.aborted).toBe(true);
  });

  it("admits higher-priority queued work first and retains parent linkage", async () => {
    const { manager } = await harness({
      globalConcurrency: 1,
      perCaseConcurrency: 1,
    });
    const parent = manager.register({ caseId: "case-a", kind: "import" });
    await parent.ready;
    const low = manager.register({
      caseId: "case-b",
      kind: "enrichment",
      priority: "low",
      parentJobId: parent.jobId,
    });
    const high = manager.register({
      caseId: "case-b",
      kind: "deep-pass",
      priority: "high",
      parentJobId: parent.jobId,
    });

    await manager.finish(parent.jobId);
    await high.ready;

    expect(manager.get(high.jobId)).toMatchObject({
      status: "running",
      parentJobId: parent.jobId,
    });
    expect(manager.get(low.jobId)?.status).toBe("queued");
  });

  it("bounds completed history per case without one case evicting another", async () => {
    const { manager } = await harness({ max: 1 });
    const first = manager.register({ caseId: "case-a", kind: "import" });
    await first.ready;
    await manager.finish(first.jobId);
    const second = manager.register({ caseId: "case-b", kind: "import" });
    await second.ready;
    await manager.finish(second.jobId);

    expect(manager.list("case-a").map((job) => job.id)).toEqual([first.jobId]);
    expect(manager.list("case-b").map((job) => job.id)).toEqual([second.jobId]);
  });
});
