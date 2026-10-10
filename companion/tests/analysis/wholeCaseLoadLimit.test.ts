import { describe, it, expect } from "vitest";
import { LoadLimiter } from "../../src/analysis/wholeCaseLoadLimit.js";

// #1915: at most N whole-case loads materialise at once; the rest wait their turn in order.

function deferred<T>() {
  let resolve!: (v: T) => void;
  let reject!: (e: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

const flush = () => new Promise((r) => setImmediate(r));

describe("LoadLimiter (#1915)", () => {
  it("runs at most `max` loads at once and starts the rest in arrival order", async () => {
    const limiter = new LoadLimiter(2);
    const gates = [deferred<number>(), deferred<number>(), deferred<number>(), deferred<number>()];
    const started: number[] = [];
    let active = 0;
    let peak = 0;
    const runs = gates.map((g, i) =>
      limiter.run(async () => {
        started.push(i);
        active++;
        peak = Math.max(peak, active);
        try {
          return await g.promise;
        } finally {
          active--;
        }
      }),
    );
    await flush();
    expect(started).toEqual([0, 1]);
    gates[1].resolve(1);
    await flush();
    expect(started).toEqual([0, 1, 2]);
    gates[0].resolve(0);
    gates[2].resolve(2);
    gates[3].resolve(3);
    expect(await Promise.all(runs)).toEqual([0, 1, 2, 3]);
    expect(peak).toBe(2);
    expect(limiter.active).toBe(0);
    expect(limiter.waiting).toBe(0);
  });

  it("frees the slot when a load rejects or throws synchronously", async () => {
    const limiter = new LoadLimiter(1);
    await expect(limiter.run(() => Promise.reject(new Error("boom")))).rejects.toThrow("boom");
    await expect(
      limiter.run(() => {
        throw new Error("sync");
      }),
    ).rejects.toThrow("sync");
    expect(limiter.active).toBe(0);
    expect(await limiter.run(async () => "after")).toBe("after");
  });

  it("refuses a limit below one", () => {
    expect(() => new LoadLimiter(0)).toThrow();
  });

  it("is re-entrant inside a permit, but work left running after the release takes its own", async () => {
    const limiter = new LoadLimiter(1);
    expect(await limiter.run(() => limiter.run(async () => "nested"))).toBe("nested");
    const resume = deferred<void>();
    let detached!: Promise<string>;
    await limiter.run(async () => {
      detached = (async () => {
        await resume.promise;
        return limiter.run(async () => "detached");
      })();
    });
    const holder = deferred<void>();
    const held = limiter.run(() => holder.promise);
    resume.resolve();
    await flush();
    expect(limiter.waiting).toBe(1); // the detached load queues behind the holder
    holder.resolve();
    await held;
    expect(await detached).toBe("detached");
  });

  // #1915 (reopened): a waiter whose client went away is dropped from the queue, never run.
  describe("abort", () => {
    it("an aborted queued waiter rejects with AbortError, never runs, and the permit passes on", async () => {
      const limiter = new LoadLimiter(1);
      const holder = deferred<string>();
      const held = limiter.run(() => holder.promise);
      const gone = new AbortController();
      let ranGone = false;
      const abandoned = limiter.run(async () => {
        ranGone = true;
        return "gone";
      }, gone.signal);
      const next = limiter.run(async () => "next");
      await flush();
      expect(limiter.waiting).toBe(2);
      gone.abort();
      await expect(abandoned).rejects.toMatchObject({ name: "AbortError" });
      expect(limiter.waiting).toBe(1);
      holder.resolve("held");
      expect(await held).toBe("held");
      expect(await next).toBe("next");
      expect(ranGone).toBe(false);
      expect(limiter.active).toBe(0);
      expect(limiter.waiting).toBe(0);
    });

    it("a pre-aborted signal is refused before it queues or takes a free permit", async () => {
      const limiter = new LoadLimiter(1);
      const signal = AbortSignal.abort();
      let ran = false;
      await expect(
        limiter.run(async () => {
          ran = true;
        }, signal),
      ).rejects.toMatchObject({ name: "AbortError" });
      expect(ran).toBe(false);
      expect(limiter.active).toBe(0);
      expect(limiter.waiting).toBe(0);
    });

    it("an abort after the load has started does not cancel it or leak its permit", async () => {
      const limiter = new LoadLimiter(1);
      const controller = new AbortController();
      const gate = deferred<string>();
      const run = limiter.run(() => gate.promise, controller.signal);
      await flush();
      controller.abort();
      gate.resolve("done");
      expect(await run).toBe("done");
      expect(limiter.active).toBe(0);
    });
  });
});
