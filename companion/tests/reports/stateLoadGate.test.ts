import { describe, it, expect } from "vitest";
import { CaseLoadCoalescer } from "../../src/reports/stateLoadGate.js";
import { LoadLimiter } from "../../src/analysis/wholeCaseLoadLimit.js";

// #1915: concurrent reads of one case share a load, but a caller never receives data a load read
// before the caller arrived. Only the queued (not yet reading) cohort is joinable.

const gateWith = (max = 2) => new CaseLoadCoalescer<string>(new LoadLimiter(max));

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

/** A read source whose every read waits on its own gate; records how many reads started. */
function source() {
  const gates: ReturnType<typeof deferred<string>>[] = [];
  return {
    gates,
    read: () => {
      const g = deferred<string>();
      gates.push(g);
      return g.promise;
    },
  };
}

describe("CaseLoadCoalescer (#1915)", () => {
  it("a burst shares one read while the first is running, plus one fresh read for the late arrivals", async () => {
    const gate = gateWith();
    const src = source();
    const first = gate.load("c1", src.read);
    await flush(); // the first load now holds a permit and is reading
    // These arrive while the first read is already reading: they must not get its result.
    const late = [gate.load("c1", src.read), gate.load("c1", src.read), gate.load("c1", src.read)];
    expect(src.gates).toHaveLength(1);
    src.gates[0].resolve("old");
    expect(await first).toBe("old");
    await flush();
    expect(src.gates).toHaveLength(2);
    src.gates[1].resolve("new");
    expect(await Promise.all(late)).toEqual(["new", "new", "new"]);
    expect(gate.size).toBe(0);
  });

  it("a third wave arriving while the pending cohort reads forms exactly one more read", async () => {
    const gate = gateWith();
    const src = source();
    const a = gate.load("c1", src.read);
    await flush();
    const b = gate.load("c1", src.read);
    src.gates[0].resolve("a");
    await a;
    await flush();
    expect(src.gates).toHaveLength(2); // b is now reading
    const c1 = gate.load("c1", src.read);
    const c2 = gate.load("c1", src.read);
    src.gates[1].resolve("b");
    expect(await b).toBe("b");
    await flush();
    expect(src.gates).toHaveLength(3);
    src.gates[2].resolve("c");
    expect(await Promise.all([c1, c2])).toEqual(["c", "c"]);
  });

  it("a call after a load settled starts a fresh read (no result is kept)", async () => {
    const gate = gateWith();
    let n = 0;
    const read = async () => `v${++n}`;
    expect(await gate.load("c1", read)).toBe("v1");
    expect(await gate.load("c1", read)).toBe("v2");
    expect(gate.size).toBe(0);
  });

  it("different cases never share a read", async () => {
    const gate = gateWith();
    const [x, y] = await Promise.all([
      gate.load("c1", async () => "one"),
      gate.load("c2", async () => "two"),
    ]);
    expect([x, y]).toEqual(["one", "two"]);
  });

  it("a failed running read fails only its own callers; the pending cohort reads afresh", async () => {
    const gate = gateWith();
    const src = source();
    const first = gate.load("c1", src.read);
    await flush();
    const second = gate.load("c1", src.read);
    src.gates[0].reject(new Error("transient"));
    await expect(first).rejects.toThrow("transient");
    await flush();
    src.gates[1].resolve("ok");
    expect(await second).toBe("ok");
    expect(gate.size).toBe(0);
  });

  it("a read that throws synchronously rejects its callers and leaves no entry behind", async () => {
    const gate = gateWith();
    await expect(
      gate.load("c1", () => {
        throw new Error("sync");
      }),
    ).rejects.toThrow("sync");
    await flush();
    expect(gate.size).toBe(0);
    expect(await gate.load("c1", async () => "next")).toBe("next");
  });

  it("callers arriving while a load waits for a permit all join it: one read", async () => {
    const limiter = new LoadLimiter(1);
    const gate = new CaseLoadCoalescer<string>(limiter);
    let releaseOther!: () => void;
    const other = limiter.run(() => new Promise<void>((r) => (releaseOther = r)));
    const src = source();
    const burst = [gate.load("c1", src.read), gate.load("c1", src.read)];
    await flush();
    burst.push(gate.load("c1", src.read)); // still queued behind the other case's load
    await flush();
    expect(src.gates).toHaveLength(0);
    releaseOther();
    await other;
    await flush();
    expect(src.gates).toHaveLength(1);
    src.gates[0].resolve("shared");
    expect(await Promise.all(burst)).toEqual(["shared", "shared", "shared"]);
  });

  it("the load runs under its permit: a whole-case load inside it takes no second permit", async () => {
    const limiter = new LoadLimiter(1);
    const gate = new CaseLoadCoalescer<string>(limiter);
    // With one permit, a nested acquire would wait forever.
    const result = await gate.load("c1", () => limiter.run(async () => "nested"));
    expect(result).toBe("nested");
    expect(limiter.active).toBe(0);
  });
});
