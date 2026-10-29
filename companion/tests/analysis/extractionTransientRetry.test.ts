// #2248: one 429 or timeout lost a whole screenshot window, because the shared retry policy treats
// rate_limit and timeout as non-retryable and nothing else retried extraction. Extraction now has
// its own bounded, backed-off retry for those two kinds only. The global policy other AI paths rely
// on is unchanged, and auth stays a wall.
import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ProviderError, type ProviderErrorKind } from "../../src/providers/provider.js";
import type { AIProvider, AnalyzeResult } from "../../src/providers/provider.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { withRetry } from "../../src/analysis/ai/retry.js";
import type { CaptureMetadata } from "../../src/types.js";

const DELTA = JSON.stringify({
  findings: [],
  iocs: [],
  mitreTechniques: [],
  threadsOpened: [],
  threadsClosed: [],
  timelineNote: "n",
  summary: "ok",
});

function capture(seq: number): CaptureMetadata {
  return {
    caseId: "c1",
    sequenceNumber: seq,
    timestamp: "2026-05-28T10:00:00.000Z",
    url: "https://example.test",
    tabTitle: "t",
    triggerType: "timer",
    contentHash: "0",
    isDuplicate: false,
    screenshotFile: `00000${seq}_t.webp`,
  };
}

/** A provider that fails with `kind` for the first `failures` calls, then answers. */
function flaky(kind: ProviderErrorKind, failures: number) {
  let calls = 0;
  const provider: AIProvider = {
    name: "flaky",
    model: "m",
    async analyze(): Promise<AnalyzeResult> {
      calls += 1;
      if (calls <= failures) throw new ProviderError(`${kind} #${calls}`, kind);
      return { rawText: DELTA };
    },
  } as unknown as AIProvider;
  return { provider, calls: () => calls };
}

let stateStore: StateStore;

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-extract-retry-"));
  const caseStore = new CaseStore(root);
  await caseStore.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
  stateStore = new StateStore(caseStore);
});

function pipelineFor(provider: AIProvider) {
  return new AnalysisPipeline({
    provider,
    stateStore,
    backoffMs: 0,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
}

describe("screenshot extraction retries transient provider errors (#2248)", () => {
  it.each(["rate_limit", "timeout"] as const)("retries a %s and then succeeds", async (kind) => {
    const f = flaky(kind, 2);
    await expect(pipelineFor(f.provider).analyzeWindow("c1", [capture(1)])).resolves.toBeDefined();
    expect(f.calls()).toBe(3);
  });

  it("gives up after the bounded number of transient retries", async () => {
    const f = flaky("rate_limit", 100);
    await expect(pipelineFor(f.provider).analyzeWindow("c1", [capture(1)])).rejects.toThrow(/rate_limit/);
    expect(f.calls()).toBe(3); // the first try plus two transient retries
  });

  it("never retries an auth error", async () => {
    const f = flaky("auth", 100);
    await expect(pipelineFor(f.provider).analyzeWindow("c1", [capture(1)])).rejects.toThrow(/auth/);
    expect(f.calls()).toBe(1);
  });

  it("leaves the shared retry policy alone: rate_limit is still not retried there", async () => {
    let calls = 0;
    await expect(
      withRetry(
        async () => {
          calls += 1;
          throw new ProviderError("429", "rate_limit");
        },
        3,
        0,
      ),
    ).rejects.toThrow("429");
    expect(calls).toBe(1);
  });
});
