import { describe, it, expect } from "vitest";
import { withRetry } from "../../src/analysis/ai/retry.js";
import { PresidioApprovalRequired, PresidioScanError } from "../../src/analysis/presidio.js";
import { ProviderError } from "../../src/providers/provider.js";

// Which Presidio failures withRetry is allowed to repeat.
//
// The regression this pins is a self-inflicted one: raising the scan budget from 10s to 60s made a
// RETRIED timeout six times more expensive, because aborting a request does not cancel the work
// inside the analyzer. Each retry queued behind the scan just abandoned and was slower than the one
// before — four attempts at 60s is ~240s of an analyst waiting to be told what attempt one knew.

describe("retry policy — Presidio scan failures", () => {
  it("does not retry a scan that ran out of budget", async () => {
    let calls = 0;
    const run = withRetry(
      async () => {
        calls += 1;
        throw new PresidioScanError("did not finish", true);
      },
      3,
      1,
    );
    await expect(run).rejects.toBeInstanceOf(PresidioScanError);
    expect(calls, "a timed-out scan must be surfaced on the first throw").toBe(1);
  });

  it("still retries a scan that failed for another reason", async () => {
    // A refused connection can be a genuine blip — the analyzer restarting, a port rebinding — and
    // costs nothing to re-attempt, because nothing was left running on the other end.
    let calls = 0;
    const run = withRetry(
      async () => {
        calls += 1;
        throw new PresidioScanError("ECONNREFUSED", false);
      },
      3,
      1,
    );
    await expect(run).rejects.toBeInstanceOf(PresidioScanError);
    expect(calls).toBe(4);
  });

  it("still does not retry an approval gate", async () => {
    let calls = 0;
    const run = withRetry(
      async () => {
        calls += 1;
        throw new PresidioApprovalRequired([{ value: "Jane Doe", category: "PERSON" }]);
      },
      3,
      1,
    );
    await expect(run).rejects.toBeInstanceOf(PresidioApprovalRequired);
    expect(calls).toBe(1);
  });

  it("leaves the provider-error policy alone", async () => {
    let authCalls = 0;
    await expect(
      withRetry(
        async () => {
          authCalls += 1;
          throw new ProviderError("bad key", "auth");
        },
        3,
        1,
      ),
    ).rejects.toBeInstanceOf(ProviderError);
    expect(authCalls, "auth is non-retryable and must stay that way").toBe(1);

    let blipCalls = 0;
    await expect(
      withRetry(
        async () => {
          blipCalls += 1;
          throw new Error("transient");
        },
        2,
        1,
      ),
    ).rejects.toThrow("transient");
    expect(blipCalls, "an unclassified error is still retryable").toBe(3);
  });
});
