import { describe, it, expect } from "vitest";
import { withRetry } from "../../src/analysis/ai/retry.js";

// #1608: a cancelled or superseded synthesis throws an AbortError. Retrying it would call the
// provider again for a result nobody keeps — the exact cost the issue is about.

describe("retry policy — aborts", () => {
  it("does not retry an AbortError", async () => {
    let calls = 0;
    const run = withRetry(
      async () => {
        calls += 1;
        const err = new Error("synthesis superseded by a newer run");
        err.name = "AbortError";
        throw err;
      },
      3,
      1,
    );
    await expect(run).rejects.toThrow("superseded");
    expect(calls, "an abort must stop on the first throw").toBe(1);
  });
});
