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

// #927. The 240-attempt ceiling bounds COMPLETED status checks. It says nothing about time: a check
// that takes four minutes to answer "processing" is one attempt, and a check that never answers is
// attempt 1 forever. The comment above the ceiling promises "20 minutes"; that was only true when
// every request completed promptly. DFIR_TOOL_SOCRATES_TIMEOUT_MS is a duration the operator set,
// so the loop has to honour it as a duration.
describe("pollUntilImported — wall-clock deadline", () => {
  const noSleep = async () => {};

  it("fails on the deadline even when every check completes, so slow answers cannot stretch it", async () => {
    // A clock the poller reads: each status check "takes" six minutes. Under a 20-minute budget
    // the fourth check is over the line, long before the 240th attempt.
    let clock = 0;
    let checks = 0;
    const res = await pollUntilImported(
      "case-1",
      job(),
      {
        store: { upsert: async (_c: string, j: SocratesJob) => j } as unknown as SocratesJobStore,
        checkStatus: async () => {
          checks++;
          clock += 6 * 60_000;
          return { status: "processing", phase: "network" };
        },
        fetchVerdicts: async () => ({ text: "[]", alerts: 0, yara: 0, sigma: 0 }),
        ingest: async () => ({ addedEvents: 0, addedIocs: 0 }),
        sleep: noSleep,
        now: () => clock,
      },
      { maxAttempts: 240, intervalMs: 5_000, totalMs: 20 * 60_000 },
    );
    expect(res.status).toBe("error");
    expect(res.error).toMatch(/timed out/i);
    expect(res.error).toMatch(/20 min/);
    expect(checks).toBeLessThanOrEqual(4);
  });

  it("defaults the deadline to maxAttempts × interval, so the attempt ceiling and the clock agree", async () => {
    let clock = 0;
    let checks = 0;
    const res = await pollUntilImported(
      "case-1",
      job(),
      {
        store: { upsert: async (_c: string, j: SocratesJob) => j } as unknown as SocratesJobStore,
        checkStatus: async () => {
          checks++;
          clock += 1_000; // each check takes a second; with a 100 ms interval × 3 attempts the budget is 300 ms
          return { status: "processing" };
        },
        fetchVerdicts: async () => ({ text: "[]", alerts: 0, yara: 0, sigma: 0 }),
        ingest: async () => ({ addedEvents: 0, addedIocs: 0 }),
        sleep: noSleep,
        now: () => clock,
      },
      { maxAttempts: 3, intervalMs: 100 },
    );
    expect(res.status).toBe("error");
    expect(res.error).toMatch(/timed out/i);
    expect(checks).toBe(1);
  });
});

// #2408: restart recovery and honest terminal states.
describe("SocratesJobStore — guarded writes (#2408)", () => {
  it("never overwrites a finished job, and hands back the stored one", async () => {
    const store = await makeStore();
    await store.upsert("case-1", job({ status: "imported", addedEvents: 4 }));
    const back = await store.upsert("case-1", job({ status: "processing", phase: "network" }));
    expect(back.status).toBe("imported");
    expect((await store.list("case-1"))[0]).toMatchObject({ status: "imported", addedEvents: 4 });
  });

  it("drops only finished jobs when the history cap is reached", async () => {
    const store = await makeStore();
    await store.upsert("case-1", job({ jobId: "live-oldest", status: "processing" }));
    for (let i = 0; i < 30; i++)
      await store.upsert("case-1", job({ jobId: `done-${i}`, status: "imported" }));
    await store.upsert("case-1", job({ jobId: "live-newest", status: "importing" }));
    const ids = (await store.list("case-1")).map((j) => j.jobId);
    expect(ids).toHaveLength(25);
    expect(ids).toContain("live-oldest");
    expect(ids[0]).toBe("live-newest");
  });

  it("keeps every in-flight job even past the cap", async () => {
    const store = await makeStore();
    for (let i = 0; i < 27; i++) await store.upsert("case-1", job({ jobId: `live-${i}` }));
    expect(await store.list("case-1")).toHaveLength(27);
  });
});

describe("pollUntilImported — honest outcomes (#2408)", () => {
  const noSleep = async () => {};
  function recordingStore(failWhen: (j: SocratesJob) => boolean = () => false) {
    const writes: SocratesJob[] = [];
    const store = {
      upsert: async (_c: string, j: SocratesJob) => {
        if (failWhen(j)) throw new Error("disk full");
        writes.push(j);
        return j;
      },
    } as unknown as SocratesJobStore;
    return { store, writes };
  }
  const base = {
    fetchVerdicts: async () => ({ text: "[]", alerts: 1, yara: 0, sigma: 0 }),
    ingest: async () => ({ addedEvents: 3, addedIocs: 2 }),
    sleep: noSleep,
  };

  it("keeps the phase it recorded when the analysis later fails", async () => {
    const { store, writes } = recordingStore();
    const statuses: SocratesStatus[] = [
      { status: "processing", phase: "logs" },
      { status: "error", message: "zeek died" },
    ];
    let i = 0;
    const res = await pollUntilImported("c", job(), {
      ...base,
      store,
      checkStatus: async () => statuses[i++],
    });
    expect(res).toMatchObject({ status: "error", phase: "logs" });
    expect(writes.at(-1)).toMatchObject({ status: "error", phase: "logs" });
  });

  it("reports imported, never error, when ingest succeeded but the final save keeps failing", async () => {
    const { store, writes } = recordingStore((j) => j.status === "imported");
    const warnings: string[] = [];
    const res = await pollUntilImported("c", job(), {
      ...base,
      store,
      checkStatus: async () => ({ status: "ready" }),
      warn: (l) => warnings.push(l),
    });
    expect(res.status).toBe("imported");
    expect(writes.some((w) => w.status === "error")).toBe(false);
    expect(warnings.join("\n")).toMatch(/imported but the job record could not be updated/);
  });

  it("retries the final save so a transient failure still records imported", async () => {
    let failures = 1;
    const { store, writes } = recordingStore((j) => j.status === "imported" && failures-- > 0);
    const res = await pollUntilImported("c", job(), {
      ...base,
      store,
      checkStatus: async () => ({ status: "ready" }),
    });
    expect(res.status).toBe("imported");
    expect(writes.at(-1)?.status).toBe("imported");
  });

  it("does not ingest when the import start cannot be recorded", async () => {
    let ingested = 0;
    const { store } = recordingStore((j) => j.status === "importing");
    const res = await pollUntilImported("c", job(), {
      ...base,
      store,
      checkStatus: async () => ({ status: "ready" }),
      ingest: async () => {
        ingested++;
        return { addedEvents: 1, addedIocs: 0 };
      },
    });
    expect(ingested).toBe(0);
    expect(res.status).toBe("error");
  });

  it("keeps polling through a phase save failure", async () => {
    const { store } = recordingStore((j) => j.status === "processing");
    const statuses: SocratesStatus[] = [{ status: "processing", phase: "network" }, { status: "ready" }];
    let i = 0;
    const res = await pollUntilImported("c", job(), {
      ...base,
      store,
      checkStatus: async () => statuses[i++],
    });
    expect(res.status).toBe("imported");
  });

  it("a fresh job fails fast on a refused status check", async () => {
    const { store } = recordingStore();
    const res = await pollUntilImported("c", job(), {
      ...base,
      store,
      checkStatus: async () => {
        throw new Error("ECONNREFUSED");
      },
    });
    expect(res.status).toBe("error");
  });

  it("a resumed job polls through refused checks until the server comes up", async () => {
    const { store } = recordingStore();
    let calls = 0;
    const res = await pollUntilImported(
      "c",
      job(),
      {
        ...base,
        store,
        checkStatus: async () => {
          if (++calls < 4) throw new Error("ECONNREFUSED");
          return { status: "ready" };
        },
      },
      { tolerateStatusErrors: true, maxAttempts: 10 },
    );
    expect(res.status).toBe("imported");
  });

  it("a resumed job that never reaches the server reports the last error at the deadline", async () => {
    const { store } = recordingStore();
    const res = await pollUntilImported(
      "c",
      job(),
      {
        ...base,
        store,
        checkStatus: async () => {
          throw new Error("ECONNREFUSED");
        },
      },
      { tolerateStatusErrors: true, maxAttempts: 3 },
    );
    expect(res.status).toBe("error");
    expect(res.error).toMatch(/ECONNREFUSED.*time limit/);
  });
});
