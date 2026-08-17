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

  // A superseded job leaves NO row — not in memory, and not in the ledger, which is the only place
  // one would survive a restart. The reported bug was eleven "cancelled" re-synthesis rows in the
  // jobs popover after a multi-file import, none of which the analyst cancelled: each imported file
  // kicks a re-synthesis, and each kick supersedes the one before it.
  //
  // The first kick is left to commit before the rest fire, so this covers both halves of the
  // supersede: a row already on disk (the supersede itself deletes it) and six that are superseded
  // before their inserts even begin (nothing is ever written). The test after this one covers the
  // third case — superseded mid-insert — which needs a held write to reproduce.
  it("erases a superseded row from the ledger", async () => {
    const { ledger, manager } = await harness({ perCaseConcurrency: 1 });
    // Hold the case's one slot the way an in-flight import does, so every kick stays queued.
    const importJob = manager.register({ caseId: "case-a", kind: "import" });
    await importJob.ready;

    const committed = manager.register({
      caseId: "case-a",
      kind: "synthesis",
      cancellable: true,
      exclusive: true,
    });
    await committed.durable; // on disk before anything supersedes it
    const kicks = Array.from({ length: 6 }, () =>
      manager.register({ caseId: "case-a", kind: "synthesis", cancellable: true, exclusive: true }),
    );
    const survivor = kicks[kicks.length - 1];
    await survivor.durable;

    let seen: string[] = [];
    const synthesisRows = async () => {
      const rows = (await ledger.list("case-a")).filter((row) => row.kind === "synthesis");
      seen = rows.map((row) => row.id);
      return rows;
    };
    // The deletes are chained off each insert, so poll rather than assume they have all landed.
    // The description is resolved LAST and must stay synchronous — an async closure here reports
    // "[object Promise]" and throws away the one observation that makes the failure diagnosable.
    await pollFor(
      () => `one synthesis row in the ledger, last saw ${JSON.stringify(seen)}`,
      async () => ((await synthesisRows()).length === 1 ? true : undefined),
    );
    expect((await synthesisRows())[0]).toMatchObject({ id: survivor.jobId, status: "queued" });
    expect(manager.list("case-a").filter((job) => job.kind === "synthesis")).toHaveLength(1);

    // The restart is the point: a ledger row left behind comes back, and comes back `cancelled`.
    const restarted = new JobManager({ ledger, now: clock(), id: () => "job_after_restart" });
    await restarted.ready();
    const restored = restarted.list("case-a").filter((job) => job.kind === "synthesis");
    expect(restored).toHaveLength(1);
    expect(restored[0]).toMatchObject({ id: survivor.jobId, status: "interrupted" });
  });

  // The half the burst above cannot reach: a job superseded WHILE its own INSERT is in flight.
  // register() supersedes synchronously, so at that moment there is nothing on disk to delete — and
  // a row appears a moment later with nothing left pointing at it. Two imports finishing a few
  // milliseconds apart is all it takes, and the row survives to the next restart.
  it("erases a row superseded while its own insert was in flight", async () => {
    const { ledger, manager } = await harness({ perCaseConcurrency: 1 });
    const importJob = manager.register({ caseId: "case-a", kind: "import" });
    await importJob.ready;

    // Hold the first kick's insert open, so the second kick supersedes it mid-write.
    let releaseInsert = (): void => {};
    const insertStarted = new Promise<void>((started) => {
      const realInsert = ledger.insert.bind(ledger);
      ledger.insert = async (job) => {
        if (job.kind !== "synthesis") return realInsert(job);
        ledger.insert = realInsert; // only the first one waits
        const result = await realInsert(job);
        started();
        await new Promise<void>((release) => {
          releaseInsert = release;
        });
        return result;
      };
    });

    const first = manager.register({
      caseId: "case-a",
      kind: "synthesis",
      cancellable: true,
      exclusive: true,
    });
    await insertStarted; // the row is on disk; nothing has superseded it yet
    const second = manager.register({
      caseId: "case-a",
      kind: "synthesis",
      cancellable: true,
      exclusive: true,
    });
    releaseInsert();
    await second.durable;

    let seen: string[] = [];
    const synthesisRows = async () => {
      const rows = (await ledger.list("case-a")).filter((row) => row.kind === "synthesis");
      seen = rows.map((row) => row.id);
      return rows;
    };
    await pollFor(
      () => `only the surviving kick in the ledger, last saw ${JSON.stringify(seen)}`,
      async () => ((await synthesisRows()).length === 1 ? true : undefined),
    );
    expect((await synthesisRows())[0]).toMatchObject({ id: second.jobId });
    expect(manager.get(first.jobId)).toBeUndefined();
  });

  // The third owner of the DELETE. A resume puts a row back in the queue WITHOUT going through
  // persistNewAndSchedule — the row has been on disk since the run that was interrupted — so if a
  // supersede lands while resume() is writing, neither of the other two paths cleans up. Deep pass
  // is the kind that can reach it: resumable, exclusive and cancellable all at once.
  it("erases a resumed row superseded while resume() was writing it back", async () => {
    const { ledger, manager } = await harness({ perCaseConcurrency: 1 });
    const original = manager.register({
      caseId: "case-a",
      kind: "deep-pass",
      cancellable: true,
      resumable: true,
      exclusive: true,
      maxRetries: 2,
    });
    await original.ready;

    // Restart: the running deep pass comes back interrupted, with a live Resume.
    const restarted = new JobManager({ ledger, now: clock(), id: () => "job_new_deep_pass" });
    await restarted.ready();
    restarted.registerResumeHandler("deep-pass", async () => {});
    expect(restarted.get(original.jobId)?.status).toBe("interrupted");

    // Hold the requeue write open, so the new deep pass supersedes the resumed row mid-write.
    let releaseUpdate = (): void => {};
    const updateStarted = new Promise<void>((started) => {
      const realUpdate = ledger.update.bind(ledger);
      ledger.update = async (job) => {
        if (job.id !== original.jobId || job.status !== "queued") return realUpdate(job);
        ledger.update = realUpdate; // only the requeue waits
        await realUpdate(job);
        started();
        await new Promise<void>((release) => {
          releaseUpdate = release;
        });
      };
    });

    const resuming = restarted.resume(original.jobId);
    await updateStarted;
    // The analyst starts a fresh deep pass instead of waiting — exclusive, so it takes over.
    const replacement = restarted.register({
      caseId: "case-a",
      kind: "deep-pass",
      cancellable: true,
      exclusive: true,
    });
    releaseUpdate();

    // The resume lost the race and says so, rather than reporting a job it no longer owns.
    expect(await resuming).toEqual({ ok: false, reason: "unknown" });
    expect(restarted.get(original.jobId)).toBeUndefined();
    await replacement.durable;

    const deepPassRows = async () => (await ledger.list("case-a")).filter((row) => row.kind === "deep-pass");
    let seen: string[] = [];
    await pollFor(
      () => `only the replacement deep pass in the ledger, last saw ${JSON.stringify(seen)}`,
      async () => {
        const rows = await deepPassRows();
        seen = rows.map((row) => row.id);
        return rows.length === 1 ? true : undefined;
      },
    );
    expect((await deepPassRows())[0]).toMatchObject({ id: replacement.jobId });

    // The point of the delete: a row left behind comes back offering Resume on work that a newer
    // run has already taken over.
    const afterRestart = new JobManager({ ledger, now: clock(), id: () => "job_unused" });
    await afterRestart.ready();
    expect(afterRestart.get(original.jobId)).toBeUndefined();
  });
});
