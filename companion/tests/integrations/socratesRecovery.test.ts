import { describe, it, expect } from "vitest";
import { mkdtemp, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SocratesJobStore, type SocratesJob } from "../../src/integrations/socrates/socratesJobStore.js";
import {
  recoverSocratesJobs,
  INTERRUPTED_IMPORT_MESSAGE,
  UNCONFIGURED_MESSAGE,
  type RecoveryDeps,
} from "../../src/integrations/socrates/socratesRecovery.js";

// #2408: a restart used to leave every unfinished SO-CRATES job "processing"/"importing" forever.

async function makeStore() {
  const root = await mkdtemp(join(tmpdir(), "socrates-recovery-"));
  await mkdir(join(root, "state"), { recursive: true });
  const cases = { stateDir: () => join(root, "state") } as unknown as ConstructorParameters<
    typeof SocratesJobStore
  >[0];
  return new SocratesJobStore(cases);
}

function job(over: Partial<SocratesJob> = {}): SocratesJob {
  return {
    jobId: "j1",
    md5: "a".repeat(32),
    sourceName: "evil.pcap",
    status: "processing",
    startedAt: "2026-11-08T00:00:00.000Z",
    ...over,
  };
}

function deps(store: SocratesJobStore, over: Partial<RecoveryDeps> = {}) {
  const resumed: string[] = [];
  const closed: SocratesJob[] = [];
  const d: RecoveryDeps = {
    store,
    isActive: () => false,
    configured: () => true,
    resume: (_c, j) => resumed.push(j.jobId),
    closed: async (_c, j) => {
      closed.push(j);
    },
    warn: () => {},
    ...over,
  };
  return { d, resumed, closed };
}

describe("recoverSocratesJobs", () => {
  it("resumes a job that was still processing", async () => {
    const store = await makeStore();
    await store.upsert("c", job());
    const { d, resumed } = deps(store);
    expect(await recoverSocratesJobs("c", d)).toEqual({ resumed: 1, interrupted: 0 });
    expect(resumed).toEqual(["j1"]);
    expect((await store.get("c", "j1"))?.status).toBe("processing");
  });

  it("marks a job caught mid-import as interrupted, saying its verdicts may already be in", async () => {
    const store = await makeStore();
    await store.upsert("c", job({ status: "importing", dropRelpath: "in/evil.pcap" }));
    const { d, resumed, closed } = deps(store);
    expect(await recoverSocratesJobs("c", d)).toEqual({ resumed: 0, interrupted: 1 });
    expect(resumed).toEqual([]);
    const after = await store.get("c", "j1");
    expect(after).toMatchObject({ status: "error", error: INTERRUPTED_IMPORT_MESSAGE });
    expect(after?.finishedAt).toBeTruthy();
    expect(closed.map((j) => j.dropRelpath)).toEqual(["in/evil.pcap"]);
  });

  it("marks a processing job interrupted when SO-CRATES is no longer configured", async () => {
    const store = await makeStore();
    await store.upsert("c", job());
    const { d, resumed } = deps(store, { configured: () => false });
    await recoverSocratesJobs("c", d);
    expect(resumed).toEqual([]);
    expect(await store.get("c", "j1")).toMatchObject({ status: "error", error: UNCONFIGURED_MESSAGE });
  });

  it("leaves finished jobs and jobs a live poller owns alone", async () => {
    const store = await makeStore();
    await store.upsert("c", job({ jobId: "done", status: "imported" }));
    await store.upsert("c", job({ jobId: "failed", status: "error", error: "x" }));
    await store.upsert("c", job({ jobId: "live", status: "importing" }));
    const { d, resumed } = deps(store, { isActive: (id) => id === "live" });
    expect(await recoverSocratesJobs("c", d)).toEqual({ resumed: 0, interrupted: 0 });
    expect(resumed).toEqual([]);
    expect((await store.get("c", "live"))?.status).toBe("importing");
  });

  it("one job that cannot be recovered does not stop the rest", async () => {
    const store = await makeStore();
    await store.upsert("c", job({ jobId: "a" }));
    await store.upsert("c", job({ jobId: "b" }));
    const warnings: string[] = [];
    const { d, resumed } = deps(store, {
      resume: (_c, j) => {
        if (j.jobId === "b") throw new Error("boom");
        resumed.push(j.jobId);
      },
      warn: (l) => warnings.push(l),
    });
    await recoverSocratesJobs("c", d);
    expect(resumed).toEqual(["a"]);
    expect(warnings.join("\n")).toMatch(/could not recover job b/);
  });
});
