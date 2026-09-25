import { describe, it, expect } from "vitest";
import { withRetry } from "../../src/analysis/ai/retry.js";
import { ProviderError, outputLimitError } from "../../src/providers/provider.js";

// A "context" failure is a size wall: the prompt alone overflows the window. An "output_limit" failure
// is the other wall: the reply was cut off at max_tokens. The next attempt sends the same request and
// hits the same wall, so retrying only multiplies the wait (and, for a cut-off reply, the bill).

describe("retry policy — context-size failures", () => {
  it("does not retry a context error", async () => {
    let calls = 0;
    const run = withRetry(
      async () => {
        calls += 1;
        throw new ProviderError("prompt is over the model's context window", "context");
      },
      3,
      1,
    );
    await expect(run).rejects.toBeInstanceOf(ProviderError);
    expect(calls, "a context error must be surfaced on the first throw").toBe(1);
  });

  it("does not retry an output-limit error", async () => {
    // A reasoning model that spends its whole output limit thinking does it again on the identical
    // request — each GLM attempt that failed this way cost ~90s and 16,000 tokens.
    let calls = 0;
    const run = withRetry(
      async () => {
        calls += 1;
        throw outputLimitError("Ollama", 16000, 15600);
      },
      3,
      1,
    );
    await expect(run).rejects.toMatchObject({ kind: "output_limit" });
    expect(calls, "an output-limit error must be surfaced on the first throw").toBe(1);
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
