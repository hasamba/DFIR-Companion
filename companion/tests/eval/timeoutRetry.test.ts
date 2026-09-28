import { describe, expect, it } from "vitest";
import { ProviderError, type AIProvider, type AnalyzeRequest } from "../../src/providers/provider.js";
import { TimeoutRetryProvider } from "./timeoutRetry.js";

// #1747: one hung eval call must not fail a whole attestation run.
function scripted(outcomes: (string | Error)[]): AIProvider & { calls: number } {
  const provider = {
    name: "stub",
    model: "stub-model",
    supportsThinking: true,
    calls: 0,
    async analyze() {
      const outcome = outcomes[Math.min(provider.calls, outcomes.length - 1)];
      provider.calls += 1;
      if (outcome instanceof Error) throw outcome;
      return { rawText: outcome };
    },
  };
  return provider;
}

const REQUEST: AnalyzeRequest = { systemPrompt: "s", userPrompt: "u", images: [] };
const timeout = (): ProviderError => new ProviderError("timed out", "timeout");

describe("TimeoutRetryProvider (#1747)", () => {
  it("makes exactly one call when the first succeeds", async () => {
    const inner = scripted(["ok"]);
    const retry = new TimeoutRetryProvider(inner);
    await expect(retry.analyze(REQUEST)).resolves.toEqual({ rawText: "ok" });
    expect(inner.calls).toBe(1);
    expect(retry.lostMs()).toBe(0);
  });

  it("retries a timed-out call once and records the time lost to it", async () => {
    const inner = scripted([timeout(), "ok"]);
    const retry = new TimeoutRetryProvider(inner);
    await expect(retry.analyze(REQUEST)).resolves.toEqual({ rawText: "ok" });
    expect(inner.calls).toBe(2);
    expect(retry.lostMs()).toBeGreaterThanOrEqual(0);
  });

  it("gives up after a second timeout", async () => {
    const inner = scripted([timeout(), timeout()]);
    await expect(new TimeoutRetryProvider(inner).analyze(REQUEST)).rejects.toMatchObject({ kind: "timeout" });
    expect(inner.calls).toBe(2);
  });

  it("passes through a different error after a timeout, and never retries a non-timeout error", async () => {
    const other = new ProviderError("bad key", "auth");
    const afterTimeout = scripted([timeout(), other]);
    await expect(new TimeoutRetryProvider(afterTimeout).analyze(REQUEST)).rejects.toBe(other);
    const direct = scripted([other, "ok"]);
    await expect(new TimeoutRetryProvider(direct).analyze(REQUEST)).rejects.toBe(other);
    expect(direct.calls).toBe(1);
  });

  it("does not retry a cancelled request", async () => {
    const controller = new AbortController();
    controller.abort();
    const inner = scripted([timeout(), "ok"]);
    await expect(
      new TimeoutRetryProvider(inner).analyze({ ...REQUEST, signal: controller.signal }),
    ).rejects.toMatchObject({ kind: "timeout" });
    expect(inner.calls).toBe(1);
  });

  it("keeps the wrapped provider's identity and capabilities", () => {
    const retry = new TimeoutRetryProvider(scripted(["ok"]));
    expect(retry).toMatchObject({ name: "stub", model: "stub-model", supportsThinking: true });
  });
});
