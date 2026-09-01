import { describe, it, expect } from "vitest";
import {
  DEFAULT_MAX_STDERR_BYTES,
  DEFAULT_MAX_STDOUT_BYTES,
  StreamTail,
} from "../../src/providers/childStreamTail.js";

describe("StreamTail", () => {
  it("keeps everything while the retained output is under the cap", () => {
    const tail = new StreamTail(1000);
    tail.push("alpha");
    tail.push("beta");
    expect(tail.text()).toBe("alphabeta");
    expect(tail.byteLength).toBe(9);
  });

  // WHICH end survives is the whole point: every consumer of these runners reads the end of the
  // stream — the last `result` event, or a short snippet of an error — so the cap has to drop the
  // oldest chunks, not the newest.
  it("drops the oldest chunks and keeps the tail once the cap is passed", () => {
    const tail = new StreamTail(10);
    tail.push("aaaaa");
    tail.push("bbbbb");
    tail.push("ccccc");
    // Only as many chunks as the cap requires are dropped: what fits inside the budget stays, so
    // the retained tail is as long as it can be rather than just the newest event.
    expect(tail.text()).toBe("bbbbbccccc");
    expect(tail.byteLength).toBe(10);
    tail.push("d");
    expect(tail.text()).toBe("cccccd");
  });

  it("keeps at least the newest chunk, however large it is", () => {
    const tail = new StreamTail(4);
    tail.push("first");
    tail.push("x".repeat(50));
    // A cap must never yield empty output: the newest chunk is what a consumer is looking for.
    expect(tail.text()).toBe("x".repeat(50));
  });

  // The cap is named in bytes, so it has to be measured in bytes. String.length counts UTF-16 code
  // units, which undercounts every non-ASCII character — and this output carries plenty of them
  // (hostnames, filenames, quoted log text), so a cap measured that way would let the buffer run to
  // several times its stated limit.
  it("measures the cap in UTF-8 bytes, not UTF-16 code units", () => {
    const tail = new StreamTail(10);
    tail.push("€€€€"); // 4 code units, 12 bytes
    expect(tail.byteLength).toBe(12);
    tail.push("z");
    // The euro chunk is over the cap on its own, so pushing anything after it drops it whole.
    expect(tail.text()).toBe("z");
  });

  it("keeps the whole stream when the cap is Infinity", () => {
    const tail = new StreamTail(Infinity);
    for (let i = 0; i < 100; i++) tail.push("x".repeat(1000));
    expect(tail.byteLength).toBe(100_000);
  });

  // The defect #762 and #763 are about: a cap that only engages when a caller remembers to ask for
  // one is not a cap. Both defaults must be finite, or the buffer is unbounded again for every call
  // site that does not opt in.
  it("defaults to a finite ceiling for both streams", () => {
    expect(Number.isFinite(DEFAULT_MAX_STDOUT_BYTES)).toBe(true);
    expect(Number.isFinite(DEFAULT_MAX_STDERR_BYTES)).toBe(true);
    expect(DEFAULT_MAX_STDOUT_BYTES).toBeGreaterThan(0);
    expect(DEFAULT_MAX_STDERR_BYTES).toBeGreaterThan(0);
  });
});
