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
    onError?: (error: Error) => void;
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
    // Wait for handler entry, not for the status flip. `scheduleQueued` marks the job "running"
    // and only resolves its admission after an intervening ledger write, so a poll on the status
    // can return a full disk round-trip before `runResumedJob` invokes the handler — which is what
    // sets `receivedSignal` (issue #506). Handler entry implies "running": `runResumedJob` bails
    // unless the job is running, so this poll subsumes the status check rather than dropping it.
    await pollFor("the resumed EVTX job's handler to receive its abort signal", async () => receivedSignal);

    expect(receivedSignal).toBeInstanceOf(AbortSignal);
    expect(restarted.get(registered.jobId)?.status).toBe("running");
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

  // scheduleQueued marks a job "running" in memory BEFORE it can persist that transition. If the
  // ledger write fails there is no way back on its own: the job is running to every reader, its
  // admission promise never settles, and because nextAdmissible counts running jobs against
  // perCaseConcurrency (1 with a ledger) the case never admits another job again — a permanent
  // wedge that only a restart clears (#512).
  it("releases the admission and the case slot when the ledger write for a start fails", async () => {
    const errors: Error[] = [];
    const { ledger, manager } = await harness({ onError: (error) => errors.push(error) });
    const realUpdate = ledger.update.bind(ledger);
    let failNext = true;
    ledger.update = async (job) => {
      if (failNext && job.status === "running") {
        failNext = false;
        throw new Error("ledger offline");
      }
      return realUpdate(job);
    };

    const wedged = manager.register({ caseId: "case-a", kind: "import" });
    await expect(wedged.ready).rejects.toThrow(/ledger offline/);
    await manager.drain();

    // The failed admission must not leave a phantom "running" job holding the case's only slot.
    expect(manager.get(wedged.jobId)?.status).not.toBe("running");
    expect(errors.map((error) => error.message)).toContain("ledger offline");

    // The case still accepts work: the next job is admitted and runs to completion.
    const next = manager.register({ caseId: "case-a", kind: "import" });
    await next.ready;
    expect(manager.get(next.jobId)?.status).toBe("running");
    await manager.finish(next.jobId);
    expect(manager.get(next.jobId)?.status).toBe("succeeded");
  });

  // Failing the one job must not abandon the rest of the pass. Nothing guarantees another
  // scheduleQueued run — it takes a fresh registration or a terminal transition — so a job already
  // sitting in the queue would wait indefinitely for an admission that never settles.
  it("still admits the jobs queued behind one whose ledger write failed", async () => {
    const { ledger, manager } = await harness({
      globalConcurrency: 2,
      perCaseConcurrency: 2,
      onError: () => {},
    });
    // Saturate the two slots, then queue two more. Their own registration passes admit nothing, so
    // the only pass that can ever start them is the one triggered by a slot being freed below —
    // which is exactly the pass the failure interrupts.
    const running = [
      manager.register({ caseId: "case-a", kind: "import" }),
      manager.register({ caseId: "case-a", kind: "import" }),
    ];
    await Promise.all(running.map((job) => job.ready));
    const doomed = manager.register({ caseId: "case-a", kind: "enrichment" });
    const behind = manager.register({ caseId: "case-a", kind: "synthesis" });
    // Let both registrations commit AND their own scheduling passes drain, so the pass triggered by
    // the finish below is genuinely the only one left that can start either of them.
    await Promise.all([doomed.durable, behind.durable]);
    await manager.drain();
    expect(manager.get(doomed.jobId)?.status).toBe("queued");
    expect(manager.get(behind.jobId)?.status).toBe("queued");

    const realUpdate = ledger.update.bind(ledger);
    let failNext = true;
    ledger.update = async (job) => {
      if (failNext && job.status === "running") {
        failNext = false;
        throw new Error("ledger offline");
      }
      return realUpdate(job);
    };

    // One freed slot, one pass: it must get past the doomed job to the one behind it.
    await manager.finish(running[0].jobId);

    await expect(doomed.ready).rejects.toThrow(/ledger offline/);
    await behind.ready;
    expect(manager.get(behind.jobId)?.status).toBe("running");
  });
});
