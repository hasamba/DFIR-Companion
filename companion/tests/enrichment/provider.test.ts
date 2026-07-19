import { describe, it, expect } from "vitest";
import { RateLimitError, parseRetryAfterMs, withRateLimitRetry } from "../../src/enrichment/provider.js";

describe("parseRetryAfterMs", () => {
  it("returns undefined for a missing header", () => {
    expect(parseRetryAfterMs(null)).toBeUndefined();
    expect(parseRetryAfterMs(undefined)).toBeUndefined();
    expect(parseRetryAfterMs("")).toBeUndefined();
  });

  it("parses a whole-number-of-seconds header to ms", () => {
    expect(parseRetryAfterMs("30")).toBe(30_000);
    expect(parseRetryAfterMs("0")).toBe(0);
  });

  it("parses an HTTP-date header relative to the given clock", () => {
    const now = Date.parse("2026-01-01T00:00:00Z");
    expect(parseRetryAfterMs("Thu, 01 Jan 2026 00:00:05 GMT", now)).toBe(5000);
  });

  it("never returns a negative wait (a past date clamps to 0)", () => {
    const now = Date.parse("2026-01-01T00:00:10Z");
    expect(parseRetryAfterMs("Thu, 01 Jan 2026 00:00:00 GMT", now)).toBe(0);
  });

  it("returns undefined for garbage it can't parse as seconds or a date", () => {
    expect(parseRetryAfterMs("not-a-value")).toBeUndefined();
  });
});

describe("withRateLimitRetry", () => {
  const noRandom = () => 0;   // deterministic: no extra jitter on top of the computed wait

  it("returns the result immediately when fn succeeds", async () => {
    const r = await withRateLimitRetry(async () => "ok", { sleep: async () => {}, random: noRandom });
    expect(r).toBe("ok");
  });

  it("does not retry a plain error (only RateLimitError triggers a retry)", async () => {
    let calls = 0;
    await expect(withRateLimitRetry(async () => { calls++; throw new Error("boom"); }, { sleep: async () => {}, random: noRandom }))
      .rejects.toThrow("boom");
    expect(calls).toBe(1);
  });

  it("retries a RateLimitError up to the configured limit, then throws", async () => {
    let calls = 0;
    const slept: number[] = [];
    await expect(withRateLimitRetry(
      async () => { calls++; throw new RateLimitError("rate limited"); },
      { retries: 2, backoffMs: 100, sleep: async (ms) => { slept.push(ms); }, random: noRandom },
    )).rejects.toThrow(RateLimitError);
    expect(calls).toBe(3);              // initial attempt + 2 retries
    expect(slept).toEqual([100, 200]);  // exponential backoff, doubling each attempt
  });

  it("succeeds on a later attempt after retrying", async () => {
    let calls = 0;
    const r = await withRateLimitRetry(async () => {
      calls++;
      if (calls < 3) throw new RateLimitError("rate limited");
      return "recovered";
    }, { retries: 5, backoffMs: 10, sleep: async () => {}, random: noRandom });
    expect(r).toBe("recovered");
    expect(calls).toBe(3);
  });

  it("honours the server's Retry-After over the computed exponential backoff", async () => {
    const slept: number[] = [];
    await expect(withRateLimitRetry(
      async () => { throw new RateLimitError("rate limited", 5000); },
      { retries: 1, backoffMs: 100, sleep: async (ms) => { slept.push(ms); }, random: noRandom },
    )).rejects.toThrow(RateLimitError);
    expect(slept).toEqual([5000]);   // 5s from Retry-After, not the 100ms backoff schedule
  });

  it("adds jitter on top of the wait without ever waiting less than requested", async () => {
    const slept: number[] = [];
    await expect(withRateLimitRetry(
      async () => { throw new RateLimitError("rate limited", 1000); },
      { retries: 1, sleep: async (ms) => { slept.push(ms); }, random: () => 0.5 },
    )).rejects.toThrow(RateLimitError);
    expect(slept[0]).toBeGreaterThanOrEqual(1000);
    expect(slept[0]).toBeLessThanOrEqual(1200);   // up to 20% jitter
  });

  it("caps exponential backoff at maxBackoffMs", async () => {
    const slept: number[] = [];
    await expect(withRateLimitRetry(
      async () => { throw new RateLimitError("rate limited"); },
      { retries: 3, backoffMs: 1000, maxBackoffMs: 1500, sleep: async (ms) => { slept.push(ms); }, random: noRandom },
    )).rejects.toThrow(RateLimitError);
    expect(slept).toEqual([1000, 1500, 1500]);   // 1000·2^0, capped at 1500 from attempt 1 onward
  });
});
