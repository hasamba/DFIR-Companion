// The import memory guard (#1874). An import's peak memory grows with the size of the whole case,
// not the file, and past what the machine has the kernel kills the server — for every case, with
// nothing to restart it. The guard refuses the import BEFORE that, with a message that says why
// and what to do. The evidence is already stored when it runs, so a refusal loses nothing.
import { describe, it, expect, afterEach } from "vitest";
import {
  assessImportMemory,
  estimateIncomingEvents,
  createImportMemoryGuard,
  ImportMemoryRefusedError,
  IMPORT_RSS_BYTES_PER_EVENT,
  IMPORT_HEAP_BYTES_PER_EVENT,
} from "../../src/analysis/importMemoryGuard.js";
import { ImportLock } from "../../src/analysis/importLock.js";

const GB = 1024 ** 3;
const roomy = { availableBytes: 16 * GB, rssBytes: 0.5 * GB, heapLimitBytes: 8 * GB, reservedBytes: 0 };

describe("assessImportMemory", () => {
  it("admits an import whose estimate fits", () => {
    expect(assessImportMemory({ caseEvents: 10_000, incomingEvents: 2_000, ...roomy }).ok).toBe(true);
  });

  it("refuses when the estimate exceeds what the process can still use, and says why", () => {
    const events = 140_000;
    const verdict = assessImportMemory({
      caseEvents: events,
      incomingEvents: 2_000,
      ...roomy,
      availableBytes: 4 * GB,
    });
    expect(verdict.ok).toBe(false);
    if (verdict.ok) return;
    expect(verdict.needBytes).toBe((events + 2_000) * IMPORT_RSS_BYTES_PER_EVENT);
    expect(verdict.message).toMatch(/140,000 events/);
    expect(verdict.message).toMatch(/nothing was changed/i);
    expect(verdict.message).toMatch(/DFIR_IMPORT_MEMORY_GUARD=off/);
  });

  it("says what was saved and how to retry in the caller's words, when it gives them", () => {
    const starved = { caseEvents: 140_000, incomingEvents: 2_000, ...roomy, availableBytes: 0 };
    const fallback = assessImportMemory(starved);
    const worded = assessImportMemory({
      ...starved,
      wording: { saved: "The hunt's rows are saved in the case", retry: "press Collect now on this hunt" },
    });
    if (fallback.ok || worded.ok) throw new Error("expected both to be refused");
    expect(fallback.message).toMatch(/The file is saved in the case and nothing was changed\./);
    expect(fallback.message).toMatch(/Then import the file again\./);
    expect(worded.message).toMatch(/The hunt's rows are saved in the case and nothing was changed\./);
    expect(worded.message).toMatch(/Then press Collect now on this hunt\./);
    expect(worded.message).not.toMatch(/import the file again/);
  });

  it("refuses when the V8 heap limit is too small for the case, even with free memory", () => {
    const caseEvents = Math.ceil((2 * GB) / IMPORT_HEAP_BYTES_PER_EVENT) + 1;
    const verdict = assessImportMemory({ caseEvents, incomingEvents: 0, ...roomy, heapLimitBytes: 2 * GB });
    expect(verdict.ok).toBe(false);
    if (!verdict.ok) expect(verdict.message).toMatch(/max-old-space-size/);
  });

  it("counts memory another import has reserved as spoken for", () => {
    const base = { caseEvents: 40_000, incomingEvents: 2_000, ...roomy, availableBytes: 6 * GB };
    expect(assessImportMemory(base).ok).toBe(true);
    expect(assessImportMemory({ ...base, reservedBytes: 3 * GB }).ok).toBe(false);
  });
});

describe("estimateIncomingEvents", () => {
  it("sizes a known file at one event per 200 bytes, capped by DFIR_MAX_EVENTS", () => {
    expect(estimateIncomingEvents(550_000, { incomingBytes: 5_340_001 })).toBe(26_701);
    expect(estimateIncomingEvents(2_000, { incomingBytes: 5_340_001 })).toBe(2_000);
  });

  it("assumes the default cap when the size is unknown, even if the cap was raised", () => {
    expect(estimateIncomingEvents(550_000)).toBe(2_000);
    expect(estimateIncomingEvents(500)).toBe(500);
  });
});

describe("createImportMemoryGuard", () => {
  const saved = process.env.DFIR_IMPORT_MEMORY_GUARD;
  afterEach(() => {
    if (saved === undefined) delete process.env.DFIR_IMPORT_MEMORY_GUARD;
    else process.env.DFIR_IMPORT_MEMORY_GUARD = saved;
  });

  const probe = (availableBytes: number) => () => ({
    availableBytes,
    rssBytes: 0.5 * GB,
    heapLimitBytes: 64 * GB,
  });

  it("throws a named refusal and reserves nothing when the case is too big", async () => {
    const guard = createImportMemoryGuard({ countEvents: async () => 200_000, probe: probe(4 * GB) });
    // A raised cap does not inflate an unsized import; the case size alone refuses this one.
    await expect(guard.admit("big")).rejects.toBeInstanceOf(ImportMemoryRefusedError);
    expect(guard.reservedBytes()).toBe(0);
  });

  it("reserves an admitted import's estimate until it is released, across cases", async () => {
    const counts: Record<string, number> = { a: 30_000, b: 30_000 };
    const guard = createImportMemoryGuard({
      countEvents: async (caseId) => counts[caseId],
      probe: probe(5 * GB),
    });
    const releaseA = await guard.admit("a");
    expect(guard.reservedBytes()).toBe(32_000 * IMPORT_RSS_BYTES_PER_EVENT);
    await expect(guard.admit("b")).rejects.toBeInstanceOf(ImportMemoryRefusedError);
    releaseA();
    releaseA(); // idempotent
    expect(guard.reservedBytes()).toBe(0);
    const releaseB = await guard.admit("b");
    releaseB();
  });

  it("admits a small case even when DFIR_MAX_EVENTS was raised for full MFT imports", async () => {
    const guard = createImportMemoryGuard({
      countEvents: async () => 5_000,
      probe: probe(4 * GB),
      maxEvents: () => 550_000,
    });
    (await guard.admit("small", { incomingBytes: 500_000 }))();
    (await guard.admit("small"))();
  });

  it("reserves heap too: two imports that each fit the heap are not both admitted", async () => {
    const guard = createImportMemoryGuard({
      countEvents: async () => 30_000,
      probe: () => ({ availableBytes: 64 * GB, rssBytes: 0.5 * GB, heapLimitBytes: 2.5 * GB }),
    });
    const releaseA = await guard.admit("a", { incomingEvents: 0 }); // 30k x 48 KB ≈ 1.4 GB
    await expect(guard.admit("b", { incomingEvents: 0 })).rejects.toThrow(/held by other imports/);
    releaseA();
    (await guard.admit("b", { incomingEvents: 0 }))();
  });

  it("is off when DFIR_IMPORT_MEMORY_GUARD=off, and never counts", async () => {
    process.env.DFIR_IMPORT_MEMORY_GUARD = "off";
    let counted = false;
    const guard = createImportMemoryGuard({
      countEvents: async () => {
        counted = true;
        return 10_000_000;
      },
      probe: probe(1 * GB),
    });
    (await guard.admit("x"))();
    expect(counted).toBe(false);
  });

  it("fails open when the case cannot be counted", async () => {
    const guard = createImportMemoryGuard({
      countEvents: async () => {
        throw new Error("db busy");
      },
      probe: probe(1 * GB),
    });
    (await guard.admit("x"))();
  });
});

describe("ImportLock with an admission check", () => {
  const refuseBig = {
    admit: async (caseId: string) => {
      if (caseId === "big") throw new ImportMemoryRefusedError("too big");
      return () => {};
    },
  };

  it("releases the case when the import is refused, so the next import is not wedged", async () => {
    const lock = new ImportLock(refuseBig);
    await expect(lock.acquire("big", {})).rejects.toThrow("too big");
    await expect(lock.runSized("big", {}, async () => "ran")).rejects.toThrow("too big");
    const release = await lock.acquire("small", {});
    release();
  });

  it("does not run the import body when refused", async () => {
    const lock = new ImportLock(refuseBig);
    let ran = false;
    await expect(
      lock.runSized("big", {}, async () => {
        ran = true;
      }),
    ).rejects.toThrow();
    expect(ran).toBe(false);
  });

  it("releases the reservation with the section", async () => {
    let released = 0;
    const lock = new ImportLock({ admit: async () => () => void released++ });
    const release = await lock.acquire("c", {});
    expect(released).toBe(0);
    release();
    expect(released).toBe(1);
    await lock.runSized("c", {}, async () => {});
    expect(released).toBe(2);
  });

  it("admits only a caller that passes a size hint — one that stores evidence inside the section is never refused", async () => {
    const lock = new ImportLock(refuseBig);
    (await lock.acquire("big"))();
    expect(await lock.runExclusive("big", async () => "ran")).toBe("ran");
  });
});
