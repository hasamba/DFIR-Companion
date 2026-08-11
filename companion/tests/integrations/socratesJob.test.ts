import { describe, it, expect } from "vitest";
import { mkdtemp, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SocratesJobStore, type SocratesJob } from "../../src/integrations/socrates/socratesJobStore.js";
import { pollUntilImported, type PollerDeps } from "../../src/integrations/socrates/socratesPoller.js";
import type { SocratesStatus } from "../../src/integrations/socrates/socratesApi.js";

// Minimal CaseStore stand-in: the store only ever calls stateDir().
async function makeStore() {
  const root = await mkdtemp(join(tmpdir(), "socrates-job-"));
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
    startedAt: "2026-07-29T00:00:00.000Z",
    ...over,
  };
}

describe("SocratesJobStore", () => {
  it("returns an empty list before anything is written", async () => {
    expect(await (await makeStore()).list("case-1")).toEqual([]);
  });

  it("round-trips a job and updates it in place by jobId", async () => {
    const store = await makeStore();
    await store.upsert("case-1", job());
    await store.upsert("case-1", job({ status: "imported", addedEvents: 4 }));
    const all = await store.list("case-1");
    expect(all).toHaveLength(1);
    expect(all[0].status).toBe("imported");
    expect(all[0].addedEvents).toBe(4);
  });

  it("keeps multiple concurrent jobs newest first", async () => {
    const store = await makeStore();
    await store.upsert("case-1", job({ jobId: "j1" }));
    await store.upsert("case-1", job({ jobId: "j2" }));
    expect((await store.list("case-1")).map((j) => j.jobId)).toEqual(["j2", "j1"]);
  });
});

describe("pollUntilImported", () => {
  const noSleep = async () => {};

  function deps(statuses: SocratesStatus[], over: Partial<PollerDeps> = {}): PollerDeps {
    let i = 0;
    return {
      store: { upsert: async (_c: string, j: SocratesJob) => j } as unknown as SocratesJobStore,
      checkStatus: async () => statuses[Math.min(i++, statuses.length - 1)],
      fetchVerdicts: async () => ({ text: "[]", alerts: 1, yara: 0, sigma: 0 }),
      ingest: async () => ({ addedEvents: 3, addedIocs: 2 }),
      sleep: noSleep,
      ...over,
    };
  }

  it("imports once the analysis reports ready", async () => {
    const d = deps([{ status: "processing", phase: "network" }, { status: "ready" }]);
    const res = await pollUntilImported("case-1", job(), d);
    expect(res.status).toBe("imported");
    expect(res.addedEvents).toBe(3);
    expect(res.addedIocs).toBe(2);
    expect(res.finishedAt).toBeTruthy();
  });

  it("records the failure reason when analysis errors", async () => {
    const res = await pollUntilImported(
      "case-1",
      job(),
      deps([{ status: "error", message: "suricata died" }]),
    );
    expect(res.status).toBe("error");
    expect(res.error).toContain("suricata died");
  });

  it("gives up after maxAttempts instead of polling a nonexistent md5 forever", async () => {
    // /api/check-status never 404s, so an unknown md5 answers "processing" indefinitely.
    const res = await pollUntilImported("case-1", job(), deps([{ status: "processing", phase: "" }]), {
      maxAttempts: 3,
    });
    expect(res.status).toBe("error");
    expect(res.error).toMatch(/timed out/i);
  });

  it("records an import failure rather than claiming success", async () => {
    const d = deps([{ status: "ready" }], {
      ingest: async () => {
        throw new Error("importer rejected the blob");
      },
    });
    const res = await pollUntilImported("case-1", job(), d);
    expect(res.status).toBe("error");
    expect(res.error).toContain("importer rejected the blob");
  });
});
