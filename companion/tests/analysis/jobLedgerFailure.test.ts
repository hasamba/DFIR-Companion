import { describe, expect, it } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { JobLedgerStore } from "../../src/analysis/jobLedgerStore.js";
import { JobManager } from "../../src/analysis/jobManager.js";
import type { Job } from "../../src/analysis/jobRegistry.js";

// #2409: a failed job-ledger write while a job ends, is cancelled or is resumed must never leave
// the queue stalled. Memory is the authority for the running process; the failure is reported.

function clock(): () => string {
  let second = 0;
  return () => `2026-11-08T00:00:${String(second++).padStart(2, "0")}.000Z`;
}

async function harness() {
  const root = await mkdtemp(join(tmpdir(), "dfir-job-ledger-fail-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: "case-a", name: "case-a", investigator: "analyst", aiProvider: null });
  const ledger = new JobLedgerStore(cases);
  const errors: string[] = [];
  let id = 0;
  const options = {
    ledger,
    now: clock(),
    id: () => `job_t_${++id}`,
    onError: (error: Error) => errors.push(error.message),
  };
  const manager = new JobManager(options);
  await manager.ready();
  const realUpdate = ledger.update.bind(ledger);
  /** Fail the next ledger update whose row matches; every other write goes through. */
  const failNextUpdate = (match: (job: Job) => boolean) => {
    let armed = true;
    ledger.update = async (job) => {
      if (armed && match(job)) {
        armed = false;
        throw new Error("ledger offline");
      }
      return realUpdate(job);
    };
  };
  return { cases, ledger, manager, errors, failNextUpdate, realUpdate, options };
}

describe("job ledger write failures (#2409)", () => {
  it("a failed write when a job finishes still frees its slot and starts the next queued job", async () => {
    const { manager, errors, failNextUpdate } = await harness();
    const first = manager.register({ caseId: "case-a", kind: "import" });
    await first.ready;
    const behind = manager.register({ caseId: "case-a", kind: "import" });
    await behind.durable;
    await manager.drain();
    expect(manager.get(behind.jobId)?.status).toBe("queued");

    failNextUpdate((job) => job.id === first.jobId && job.status === "succeeded");
    await expect(manager.finish(first.jobId)).resolves.toBeUndefined();

    expect(manager.get(first.jobId)?.status).toBe("succeeded");
    await behind.ready;
    expect(manager.get(behind.jobId)?.status).toBe("running");
    expect(errors.join("\n")).toMatch(new RegExp(`${first.jobId} is succeeded .*ledger offline`));
  });

  it("a failed write when a job fails still starts the next queued job", async () => {
    const { manager, errors, failNextUpdate } = await harness();
    const first = manager.register({ caseId: "case-a", kind: "import" });
    await first.ready;
    const behind = manager.register({ caseId: "case-a", kind: "import" });
    await behind.durable;
    failNextUpdate((job) => job.id === first.jobId && job.status === "failed");
    await expect(manager.fail(first.jobId, new Error("parse error"))).resolves.toBeUndefined();
    await behind.ready;
    expect(manager.get(behind.jobId)?.status).toBe("running");
    expect(errors.some((m) => m.includes("ledger offline"))).toBe(true);
  });

  it("a failed write when cancelling a running job still aborts it and starts the next one", async () => {
    const { manager, errors, failNextUpdate } = await harness();
    const first = manager.register({ caseId: "case-a", kind: "synthesis", cancellable: true });
    await first.ready;
    const behind = manager.register({ caseId: "case-a", kind: "import" });
    await behind.durable;

    failNextUpdate((job) => job.id === first.jobId && job.status === "cancelled");
    const result = await manager.cancel(first.jobId);

    expect(result).toMatchObject({ ok: true, job: { status: "cancelled" } });
    expect(first.signal?.aborted).toBe(true);
    await behind.ready;
    expect(manager.get(behind.jobId)?.status).toBe("running");
    expect(errors.join("\n")).toMatch(/is cancelled .*ledger offline/);
    expect(await manager.cancel(first.jobId)).toEqual({ ok: false, reason: "terminal" });
  });

  it("a failed write when cancelling a queued job still rejects its admission", async () => {
    const { manager, failNextUpdate } = await harness();
    const running = manager.register({ caseId: "case-a", kind: "import" });
    await running.ready;
    const queued = manager.register({ caseId: "case-a", kind: "synthesis", cancellable: true });
    await queued.durable;

    failNextUpdate((job) => job.id === queued.jobId && job.status === "cancelled");
    expect((await manager.cancel(queued.jobId)).ok).toBe(true);
    await expect(queued.ready).rejects.toMatchObject({ name: "AbortError" });
  });

  it("a failed prune after a recorded transition is reported but does not fail it", async () => {
    const { ledger, manager, errors } = await harness();
    const job = manager.register({ caseId: "case-a", kind: "import" });
    await job.ready;
    ledger.prune = async () => {
      throw new Error("prune offline");
    };
    await manager.finish(job.jobId);
    expect(manager.get(job.jobId)?.status).toBe("succeeded");
    expect(errors).toContain("prune offline");
    expect(errors.some((m) => m.includes("ledger write failed"))).toBe(false);
  });

  async function interruptedJob() {
    const h = await harness();
    const original = h.manager.register({
      caseId: "case-a",
      kind: "deep-pass",
      cancellable: true,
      resumable: true,
      maxRetries: 2,
    });
    await original.ready;
    // Restart: the running job comes back interrupted with a live Resume.
    let id = 0;
    const restarted = new JobManager({ ...h.options, id: () => `job_r_${++id}` });
    await restarted.ready();
    const ran: string[] = [];
    restarted.registerResumeHandler("deep-pass", async (job) => {
      ran.push(job.id);
    });
    expect(restarted.get(original.jobId)?.status).toBe("interrupted");
    return { ...h, restarted, jobId: original.jobId, ran };
  }

  it("a resume the ledger refused changes nothing, leaves no phantom slot, and can be retried", async () => {
    const { restarted, jobId, ran, errors, failNextUpdate } = await interruptedJob();
    failNextUpdate((job) => job.id === jobId && job.status === "queued");

    expect(await restarted.resume(jobId)).toEqual({ ok: false, reason: "ledger-write-failed" });
    expect(restarted.get(jobId)).toMatchObject({ status: "interrupted", attempt: 1 });
    expect(errors.join("\n")).toMatch(new RegExp(`${jobId} resume was not recorded: ledger offline`));

    // The case still admits other work: no phantom queued/running row holds its one slot.
    const other = restarted.register({ caseId: "case-a", kind: "import" });
    await other.ready;
    expect(restarted.get(other.jobId)?.status).toBe("running");
    await restarted.finish(other.jobId);

    const retried = await restarted.resume(jobId);
    expect(retried.ok).toBe(true);
    await restarted.drain();
    await new Promise((r) => setTimeout(r, 50));
    expect(ran).toEqual([jobId]);
  });

  it("a scheduling pass during the resume write cannot start the job before it is recorded", async () => {
    const { restarted, jobId, ledger, realUpdate } = await interruptedJob();
    let release = (): void => {};
    let started = (): void => {};
    const writeStarted = new Promise<void>((resolve) => (started = resolve));
    ledger.update = async (job) => {
      if (job.id !== jobId || job.status !== "queued") return realUpdate(job);
      started();
      await new Promise<void>((resolve) => (release = resolve));
      throw new Error("ledger offline");
    };
    const resuming = restarted.resume(jobId);
    await writeStarted;
    // Another job in the case runs and ends, which runs a scheduling pass mid-write.
    const other = restarted.register({ caseId: "case-a", kind: "import" });
    await other.ready;
    await restarted.finish(other.jobId);
    await restarted.drain();
    expect(restarted.get(jobId)?.status).toBe("interrupted");
    expect(await restarted.resume(jobId)).toEqual({ ok: false, reason: "not-interrupted" });

    release();
    expect(await resuming).toEqual({ ok: false, reason: "ledger-write-failed" });
    expect(restarted.get(jobId)?.status).toBe("interrupted");
    expect((await ledger.list("case-a")).find((row) => row.id === jobId)?.status).toBe("interrupted");
  });

  // The guard must cover the prune that follows the write, not just the write itself.
  it("a supersede or second resume while the resume is pruning cannot slip past the guard", async () => {
    const { restarted, jobId, ledger } = await interruptedJob();
    const realPrune = ledger.prune.bind(ledger);
    let release = (): void => {};
    let started = (): void => {};
    const pruneStarted = new Promise<void>((resolve) => (started = resolve));
    let armed = true;
    ledger.prune = async (caseId, max) => {
      if (armed) {
        armed = false;
        started();
        await new Promise<void>((resolve) => (release = resolve));
      }
      return realPrune(caseId, max);
    };
    const resuming = restarted.resume(jobId);
    await pruneStarted;
    expect(await restarted.resume(jobId)).toEqual({ ok: false, reason: "not-interrupted" });
    const replacement = restarted.register({
      caseId: "case-a",
      kind: "deep-pass",
      cancellable: true,
      exclusive: true,
    });
    release();

    expect(await resuming).toEqual({ ok: false, reason: "unknown" });
    expect(restarted.get(jobId)).toBeUndefined();
    await replacement.ready;
    expect(restarted.get(replacement.jobId)?.status).toBe("running");
    const rows = (await ledger.list("case-a")).filter((row) => row.kind === "deep-pass");
    expect(rows.map((row) => row.id)).toEqual([replacement.jobId]);
  });
});
