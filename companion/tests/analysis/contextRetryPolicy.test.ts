import { describe, it, expect } from "vitest";
import { withRetry } from "../../src/analysis/ai/retry.js";
import { ProviderError } from "../../src/providers/provider.js";

// A "context" failure is a size wall: the prompt alone overflows the window, or the reply was cut off
// at max_tokens. The next attempt sends the same request and hits the same wall, so retrying only
// multiplies the wait (and, for a cut-off reply, the bill) before the analyst sees the error.

describe("retry policy — context-size failures", () => {
  it("does not retry a context error", async () => {
    let calls = 0;
    const run = withRetry(
      async () => {
        calls += 1;
        throw new ProviderError("reply was cut off at max_tokens", "context");
      },
      3,
      1,
    );
    await expect(run).rejects.toBeInstanceOf(ProviderError);
    expect(calls, "a context error must be surfaced on the first throw").toBe(1);
  });

  it("still retries an unclassified provider error", async () => {
    let calls = 0;
    const run = withRetry(
      async () => {
        calls += 1;
        throw new ProviderError("declined the request", "other");
      },
      2,
      1,
    );
    await expect(run).rejects.toBeInstanceOf(ProviderError);
    expect(calls).toBe(3);
  });
});
