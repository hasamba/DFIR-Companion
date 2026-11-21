// The import memory guard's re-check for an import that outgrows its admission (#2812). The bulk
// Velociraptor importer keeps every graded row, so its admission (capped by DFIR_MAX_EVENTS) can be
// far below what it really adds. The guard re-checks the import against the REAL count as it grows,
// without counting the import's own reservation against itself. Every number here is synthetic.
import { describe, it, expect, afterEach } from "vitest";
import {
  createImportMemoryGuard,
  ImportMemoryRefusedError,
  IMPORT_RSS_BYTES_PER_EVENT,
  type MemorySnapshot,
} from "../../src/analysis/importMemoryGuard.js";
import { ImportLock } from "../../src/analysis/importLock.js";

const GB = 1024 ** 3;

function guardWith(counts: Record<string, number>, availableBytes: number) {
  let probes = 0;
  const snapshot = (): MemorySnapshot => {
    probes++;
    return { availableBytes, rssBytes: 0.5 * GB, heapLimitBytes: 64 * GB };
  };
  const guard = createImportMemoryGuard({
    countEvents: async (caseId) => counts[caseId],
    probe: snapshot,
    maxEvents: () => 2_000,
  });
  return { guard, probes: () => probes };
}

describe("createImportMemoryGuard — re-check inside an import section (#2812)", () => {
  const saved = process.env.DFIR_IMPORT_MEMORY_GUARD;
  afterEach(() => {
    if (saved === undefined) delete process.env.DFIR_IMPORT_MEMORY_GUARD;
    else process.env.DFIR_IMPORT_MEMORY_GUARD = saved;
  });

  it("has nothing to re-check without a section admission", async () => {
    const { guard } = guardWith({ c: 70_000 }, 10 * GB);
    expect(await guard.openSectionCheck("c")).toBeNull();
    // An admission made without the section (a re-grade preview, the drop folder's pre-read ask)
    // does not stand for the running import either.
    const release = await guard.admit("c", { incomingBytes: 1_000 });
    expect(await guard.openSectionCheck("c")).toBeNull();
    release();
  });

  it("never refuses an import that stays within what it was admitted for", async () => {
    const { guard, probes } = guardWith({ c: 70_000 }, 10 * GB);
    const release = await guard.admit("c", { incomingBytes: 100_000_000 }, { section: true });
    const before = probes();
    const check = await guard.openSectionCheck("c");
    expect(check).not.toBeNull();
    check!(2_000);
    expect(probes()).toBe(before); // nothing outgrown: no memory reading at all
    release();
  });

  it("refuses with the standard message once the real count outgrows what the server can take", async () => {
    // 70,000 + 2,000 fit 10 GB; 70,000 + 96,000 graded rows need ~20 GB.
    const { guard } = guardWith({ c: 70_000 }, 10 * GB);
    const release = await guard.admit("c", { incomingBytes: 700_000_000 }, { section: true });
    const check = (await guard.openSectionCheck("c"))!;
    check(5_000); // still fits
    const err = (() => {
      try {
        check(96_000);
      } catch (e) {
        return e;
      }
      return null;
    })();
    expect(err).toBeInstanceOf(ImportMemoryRefusedError);
    const message = (err as Error).message;
    expect(message).toMatch(/^Import refused to protect the server: this case holds 70,000 events/);
    expect(message).toMatch(/The file is saved in the case and nothing was changed\./);
    expect(message).toMatch(/DFIR_IMPORT_MEMORY_GUARD=off/);
    expect((err as ImportMemoryRefusedError).othersReserved).toBe(false);
    release();
    expect(guard.reservedBytes()).toBe(0);
  });

  it("does not count the import's own reservation against itself", async () => {
    // Usable 3.5 GB. Admitted at 20,000 + 2,000 (2.7 GB reserved). Growing to 25,000 needs 3.05 GB:
    // fits on its own, but would be refused if its own 2.7 GB were also counted as held.
    const { guard } = guardWith({ c: 20_000 }, 3 * GB);
    const release = await guard.admit("c", { incomingBytes: 50_000_000 }, { section: true });
    const check = (await guard.openSectionCheck("c"))!;
    expect(() => check(5_000)).not.toThrow();
    release();
  });

  it("grows the reservation as the import grows, and the release returns all of it", async () => {
    const { guard } = guardWith({ a: 10_000, b: 10_000 }, 6 * GB);
    const releaseA = await guard.admit("a", { incomingBytes: 50_000_000 }, { section: true });
    expect(guard.reservedBytes()).toBe(12_000 * IMPORT_RSS_BYTES_PER_EVENT);
    const check = (await guard.openSectionCheck("a"))!;
    check(40_000);
    expect(guard.reservedBytes()).toBe(50_000 * IMPORT_RSS_BYTES_PER_EVENT);
    check(20_000); // never shrinks
    expect(guard.reservedBytes()).toBe(50_000 * IMPORT_RSS_BYTES_PER_EVENT);
    // The grown reservation is what another case's import is now admitted against.
    await expect(guard.admit("b", { incomingBytes: 50_000_000 }, { section: true })).rejects.toBeInstanceOf(
      ImportMemoryRefusedError,
    );
    releaseA();
    expect(guard.reservedBytes()).toBe(0);
  });

  it("says whether other imports held memory when it refuses mid-run", async () => {
    const { guard } = guardWith({ a: 10_000, b: 10_000 }, 6 * GB);
    const releaseB = await guard.admit("b", { incomingBytes: 1_000 }, { section: true });
    const releaseA = await guard.admit("a", { incomingBytes: 1_000 }, { section: true });
    const check = (await guard.openSectionCheck("a"))!;
    const err = (() => {
      try {
        check(40_000);
      } catch (e) {
        return e;
      }
      return null;
    })();
    expect((err as ImportMemoryRefusedError).othersReserved).toBe(true);
    releaseA();
    releaseB();
  });

  it("re-counts the case when a run opens its check, so earlier files of the same section count", async () => {
    // One section imports two files (a drop batch): the second starts from the case as the first left it.
    const counts = { c: 10_000 };
    const { guard } = guardWith(counts, 3 * GB);
    const release = await guard.admit("c", { incomingBytes: 1_000_000 }, { section: true });
    const first = (await guard.openSectionCheck("c"))!;
    first(8_000);
    counts.c = 18_000; // the first file's rows are committed
    const second = (await guard.openSectionCheck("c"))!;
    expect(() => second(12_000)).toThrow(/this case holds 18,000 events/);
    release();
  });

  it("keeps the admission's own refusal wording", async () => {
    const { guard } = guardWith({ c: 70_000 }, 10 * GB);
    const wording = {
      saved: "The hunt's rows are saved in the case",
      retry: "press Collect now on this hunt",
    };
    const release = await guard.admit("c", { incomingBytes: 1_000, wording }, { section: true });
    const check = (await guard.openSectionCheck("c"))!;
    expect(() => check(96_000)).toThrow(/The hunt's rows are saved in the case and nothing was changed\./);
    release();
  });

  it("refuses nothing when DFIR_IMPORT_MEMORY_GUARD=off, even switched off mid-run", async () => {
    const { guard } = guardWith({ c: 70_000 }, 10 * GB);
    const release = await guard.admit("c", { incomingBytes: 1_000 }, { section: true });
    const check = (await guard.openSectionCheck("c"))!;
    process.env.DFIR_IMPORT_MEMORY_GUARD = "off";
    expect(() => check(96_000)).not.toThrow();
    expect(await guard.openSectionCheck("c")).toBeNull();
    release();
  });

  it("fails open when the case cannot be re-counted", async () => {
    let fail = false;
    const guard = createImportMemoryGuard({
      countEvents: async () => {
        if (fail) throw new Error("db busy");
        return 70_000;
      },
      probe: () => ({ availableBytes: 10 * GB, rssBytes: 0, heapLimitBytes: 64 * GB }),
    });
    const release = await guard.admit("c", { incomingBytes: 1_000 }, { section: true });
    fail = true;
    expect(await guard.openSectionCheck("c")).toBeNull();
    release();
  });

  it("stops checking once the section is released", async () => {
    const { guard } = guardWith({ c: 70_000 }, 10 * GB);
    const release = await guard.admit("c", { incomingBytes: 1_000 }, { section: true });
    const check = (await guard.openSectionCheck("c"))!;
    release();
    expect(() => check(96_000)).not.toThrow();
    expect(guard.reservedBytes()).toBe(0);
  });
});

describe("ImportLock marks its admissions as the section's own (#2812)", () => {
  it("a sized section can be re-checked; an unsized one and a preview cannot", async () => {
    const { guard } = guardWith({ c: 70_000 }, 10 * GB);
    const lock = new ImportLock(guard);
    await lock.runSized("c", { incomingBytes: 1_000 }, async () => {
      expect(await guard.openSectionCheck("c")).not.toBeNull();
    });
    // No size hint: the caller may store its evidence inside the section, so nothing is re-checked.
    await lock.runExclusive("c", async () => {
      expect(await guard.openSectionCheck("c")).toBeNull();
    });
    const releasePreview = await lock.admitWithoutSection("c", { incomingBytes: 1_000 });
    expect(await guard.openSectionCheck("c")).toBeNull();
    releasePreview();
    const release = await lock.acquire("c", { incomingBytes: 1_000 });
    expect(await guard.openSectionCheck("c")).not.toBeNull();
    release();
    expect(await guard.openSectionCheck("c")).toBeNull();
  });
});
