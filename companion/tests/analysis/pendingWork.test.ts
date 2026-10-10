import { describe, expect, it } from "vitest";
import { WorkTracker, trackedWork } from "../../src/analysis/pendingWork.js";

// #1915 (review follow-up): the gate holds an abandoned request's slot until the work it started has
// settled. That rests on this count being right at any depth and after any await.

function deferred<T = void>() {
  let resolve!: (v: T) => void;
  let reject!: (e: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

const tick = (): Promise<void> => new Promise((r) => setImmediate(r));

describe("WorkTracker", () => {
  it("counts tracked work started under it, at any depth and after an await", async () => {
    const tracker = new WorkTracker();
    const a = deferred<number>();
    const b = deferred<number>();
    const done = tracker.run(async () => {
      await tick();
      const first = trackedWork(() => a.promise);
      const second = (async () => {
        await tick();
        return trackedWork(() => b.promise);
      })();
      return Promise.all([first, second]);
    });
    await tick();
    await tick();
    await tick();
    expect(tracker.pending).toBe(2);
    a.resolve(1);
    await tick();
    expect(tracker.pending).toBe(1);
    b.resolve(2);
    expect(await done).toEqual([1, 2]);
    expect(tracker.pending).toBe(0);
  });

  it("ends the count when tracked work rejects", async () => {
    const tracker = new WorkTracker();
    const a = deferred();
    const done = tracker.run(() => trackedWork(() => a.promise));
    expect(tracker.pending).toBe(1);
    a.reject(new Error("load failed"));
    await expect(done).rejects.toThrow("load failed");
    expect(tracker.pending).toBe(0);
  });

  it("whenIdle fires once nothing is pending, and waits for pending work first", async () => {
    const tracker = new WorkTracker();
    const a = deferred();
    void tracker.run(() => trackedWork(() => a.promise));
    let idle = 0;
    tracker.whenIdle(() => idle++);
    await tick();
    await tick();
    expect(idle).toBe(0);
    a.resolve();
    await tick();
    await tick();
    expect(idle).toBe(1);
  });

  it("whenIdle fires at once (after a macrotask) when nothing was ever started", async () => {
    const tracker = new WorkTracker();
    let idle = 0;
    tracker.whenIdle(() => idle++);
    expect(idle).toBe(0);
    await tick();
    expect(idle).toBe(1);
  });

  it("work outside any tracker runs unchanged", async () => {
    expect(await trackedWork(async () => 7)).toBe(7);
  });

  it("an end function is idempotent", () => {
    const tracker = new WorkTracker();
    const end = tracker.begin();
    end();
    end();
    expect(tracker.pending).toBe(0);
  });
});
