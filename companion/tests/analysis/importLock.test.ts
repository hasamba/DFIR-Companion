import { describe, it, expect } from "vitest";
import { ImportLock } from "../../src/analysis/importLock.js";

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
