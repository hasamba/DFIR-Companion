import { describe, it, expect } from "vitest";
import {
  DEFAULT_MAX_STDERR_BYTES,
  DEFAULT_MAX_STDOUT_BYTES,
  StreamEnds,
  StreamHead,
  StreamTail,
} from "../../src/providers/childStreamBuffer.js";

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

describe("StreamHead", () => {
  it("keeps everything while the retained output is under the cap", () => {
    const head = new StreamHead(1000);
    head.push("alpha");
    head.push("beta");
    expect(head.text()).toBe("alphabeta");
    expect(head.byteLength).toBe(9);
  });

  // The mirror of StreamTail, and the reason both exist: every reader of these runners' stderr
  // slices the FIRST 200-300 characters into an error message, so the newest output is the part
  // that can be dropped.
  it("drops later output and keeps the head once the cap is reached", () => {
    const head = new StreamHead(8);
    head.push("aaaaa");
    head.push("bbbbb");
    head.push("ccccc");
    expect(head.text()).toBe("aaaaabbbbb");
    expect(head.byteLength).toBe(10);
  });

  it("keeps the first chunk whole, however large it is", () => {
    const head = new StreamHead(4);
    head.push("x".repeat(50));
    head.push("dropped");
    // Whole chunks, never a byte-exact slice: a cap that cut mid-string could split a surrogate
    // pair, and the overshoot is at most one pipe chunk.
    expect(head.text()).toBe("x".repeat(50));
  });

  it("measures the cap in UTF-8 bytes, not UTF-16 code units", () => {
    const head = new StreamHead(10);
    head.push("€€€"); // 3 code units, 9 bytes — still under the cap
    expect(head.byteLength).toBe(9);
    head.push("zz");
    expect(head.text()).toBe("€€€zz");
    head.push("dropped");
    expect(head.text()).toBe("€€€zz");
  });

  it("keeps the whole stream when the cap is Infinity", () => {
    const head = new StreamHead(Infinity);
    for (let i = 0; i < 100; i++) head.push("x".repeat(1000));
    expect(head.byteLength).toBe(100_000);
  });
});

describe("StreamEnds", () => {
  it("keeps everything, with no truncation marker, while under the budget", () => {
    const ends = new StreamEnds(100, 100);
    ends.push("alpha");
    ends.push("beta");
    // Nothing was lost, so nothing may claim it was: a marker on complete output is a lie about
    // evidence, and the reader cannot tell it from a real elision.
    expect(ends.text()).toBe("alphabeta");
  });

  // The whole point of holding both ends. classifyKind() scans stderr for auth and rate-limit
  // keywords, and analysis/ai/retry.ts treats "auth" and "rate_limit" as NON-retryable. An error
  // line the buffer dropped is therefore not merely a worse message — it downgrades the kind to a
  // retryable one and the pipeline runs the same doomed call again.
  it("keeps an early error AND a late one, dropping only the middle", () => {
    const ends = new StreamEnds(20, 20);
    ends.push("Error: not logged in\n");
    for (let i = 0; i < 50; i++) ends.push("noise noise noise\n");
    ends.push("429 rate limit\n");

    const text = ends.text();
    expect(text).toContain("Error: not logged in");
    expect(text).toContain("429 rate limit");
    expect(text).toContain("stderr truncated");
  });

  it("still lets a front-slicing reader find the first error", () => {
    const ends = new StreamEnds(200, 50);
    ends.push("Error: not logged in\n");
    for (let i = 0; i < 50; i++) ends.push("x".repeat(100));
    // claudeCode.ts and finalText slice the first 200 characters; codex.ts the first 300. The head
    // budget has to come first in the joined text for that to keep working.
    expect(ends.text().slice(0, 200)).toContain("Error: not logged in");
  });

  it("marks the elision only once something was actually dropped", () => {
    const exact = new StreamEnds(5, 5);
    exact.push("aaaaa");
    exact.push("bbbbb");
    // Head full, tail holds the rest, nothing lost between them.
    expect(exact.text()).toBe("aaaaabbbbb");
    exact.push("ccccc");
    expect(exact.text()).toContain("stderr truncated");
  });

  it("keeps the whole stream when both budgets are Infinity", () => {
    const ends = new StreamEnds(Infinity, Infinity);
    for (let i = 0; i < 100; i++) ends.push("x".repeat(1000));
    expect(ends.text()).toBe("x".repeat(100_000));
  });

  // The marker is scanned by classifyKind() along with everything else, and its regexes include
  // /5\d\d/ for a server-error code. A byte count in the marker could match that by accident and
  // reclassify the error, so the marker carries no digits.
  it("uses a marker with no digits in it", () => {
    const ends = new StreamEnds(5, 5);
    for (let i = 0; i < 10; i++) ends.push("aaaaa");
    const marker = ends.text().replace(/a/g, "");
    expect(marker).not.toMatch(/\d/);
  });
});
