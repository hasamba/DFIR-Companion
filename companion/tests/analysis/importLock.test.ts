import { describe, it, expect } from "vitest";
import { ImportLock } from "../../src/analysis/importLock.js";
import { createImportMemoryGuard, ImportMemoryRefusedError } from "../../src/analysis/importMemoryGuard.js";

// The primitive behind "one import writer per case". Its contract is small and load-bearing: FIFO
// per case, independent across cases, and a failed section must not wedge the ones behind it.

const tick = (): Promise<void> => new Promise((r) => setTimeout(r, 0));

describe("ImportLock", () => {
  it("runs one section at a time for a case, in arrival order", async () => {
    const lock = new ImportLock();
    const order: string[] = [];
    const section = (name: string) =>
      lock.runExclusive("c1", async () => {
        order.push(`${name}:start`);
        await tick();
        order.push(`${name}:end`);
      });

    await Promise.all([section("a"), section("b"), section("c")]);

    // Interleaving would show as a start between another section's start and end.
    expect(order).toEqual(["a:start", "a:end", "b:start", "b:end", "c:start", "c:end"]);
  });

  it("does not serialize different cases against each other", async () => {
    const lock = new ImportLock();
    let releaseC1: (() => void) | null = null;
    const held = lock.runExclusive("c1", () => new Promise<void>((r) => (releaseC1 = r)));

    // c2 must not wait on the section c1 is still holding.
    await expect(lock.runExclusive("c2", async () => "done")).resolves.toBe("done");

    releaseC1!();
    await held;
  });

  it("hands the section to the next caller when one throws", async () => {
    const lock = new ImportLock();
    const failed = lock.runExclusive("c1", async () => {
      throw new Error("import blew up");
    });
    const after = lock.runExclusive("c1", async () => "still served");

    await expect(failed).rejects.toThrow("import blew up");
    await expect(after).resolves.toBe("still served");
  });

  it("acquire() holds the section until the release is called", async () => {
    const lock = new ImportLock();
    const order: string[] = [];

    const release = await lock.acquire("c1");
    order.push("held");
    const queued = lock.runExclusive("c1", async () => {
      order.push("queued ran");
    });

    await tick();
    expect(order).toEqual(["held"]); // the queued section must not have run yet

    release();
    await queued;
    expect(order).toEqual(["held", "queued ran"]);
  });

  it("serializes two acquire() holders", async () => {
    const lock = new ImportLock();
    const first = await lock.acquire("c1");
    let secondGranted = false;
    const second = lock.acquire("c1").then((release) => {
      secondGranted = true;
      return release;
    });

    await tick();
    expect(secondGranted).toBe(false);

    first();
    (await second)();
    expect(secondGranted).toBe(true);
  });
});

// #2366: read-only work as heavy as an import (the Sigma re-grade preview) is admitted by the same
// memory guard, without the case's import section, and its reservation counts against imports.
describe("ImportLock.admitWithoutSection (#2366)", () => {
  const MB = 1024 ** 2;
  /** Room for one 1,000-event reservation (128 MB of the 200 MB the probe reports), not two. */
  const guarded = () =>
    new ImportLock(
      createImportMemoryGuard({
        countEvents: async () => 0,
        probe: () => ({ availableBytes: 200 * MB, rssBytes: 0, heapLimitBytes: 8 * 1024 * MB }),
      }),
    );
  const hint = { incomingEvents: 1000 };

  it("holds a reservation that a sectioned import is refused against, until it is released", async () => {
    const lock = guarded();
    const release = await lock.admitWithoutSection("c1", hint);
    expect(lock.isBusy("c1")).toBe(false); // no section taken

    await expect(lock.acquire("c2", hint)).rejects.toBeInstanceOf(ImportMemoryRefusedError);
    await expect(lock.admitWithoutSection("c2", hint)).rejects.toBeInstanceOf(ImportMemoryRefusedError);

    release();
    const section = await lock.acquire("c2", hint);
    section();
  });

  it("is not blocked by an import section held for the same case", async () => {
    const lock = new ImportLock({ admit: async () => () => {} });
    const section = await lock.acquire("c1");
    const release = await lock.admitWithoutSection("c1", hint); // resolves although the section is held
    release();
    section();
  });

  it("admits everything when no guard is wired or no size is given", async () => {
    let admitted = 0;
    (await new ImportLock().admitWithoutSection("c1", hint))();
    const counting = new ImportLock({
      admit: async () => {
        admitted++;
        return () => {};
      },
    });
    (await counting.admitWithoutSection("c1"))();
    expect(admitted).toBe(0);
  });
});
