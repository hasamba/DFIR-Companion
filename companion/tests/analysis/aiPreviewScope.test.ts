import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { AiPreviewCaptured, runAiPreview } from "../../src/analysis/ai/aiPreviewScope.js";
import { analyzeRestored, type ProviderCallContext } from "../../src/analysis/ai/providerCall.js";
import { executeDeepPassBatches } from "../../src/analysis/deepPassExecution.js";
import { withRetry } from "../../src/analysis/ai/retry.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import { createConsoleLogger } from "../../src/logging/logger.js";
import { beginCaseWrite } from "../../src/storage/caseIncarnation.js";
import {
  isReadOnlyScope,
  readOnlyStateOverlay,
  ReadOnlyScopeWriteError,
  runReadOnly,
  runStorageUpkeep,
} from "../../src/storage/readOnlyScope.js";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import type { AIProvider, AnalyzeRequest, AnalyzeResult } from "../../src/providers/provider.js";

// #2491 — the mechanics under "Preview what the AI will see": the read-only scope, the capture at
// the AI-call gate, and the paths that must not swallow the stop.

class Recording implements AIProvider {
  readonly name = "rec";
  readonly model = "m";
  readonly sent: AnalyzeRequest[] = [];
  async analyze(req: AnalyzeRequest): Promise<AnalyzeResult> {
    this.sent.push(req);
    return { rawText: "{}" };
  }
}

const ctx: ProviderCallContext = { log: createConsoleLogger("error"), opts: {} };
const req = (userPrompt: string): AnalyzeRequest => ({ systemPrompt: "SYS", userPrompt, images: [] });

describe("read-only storage scope", () => {
  it("refuses every case write admitted through beginCaseWrite, and only inside the scope", async () => {
    expect(() => beginCaseWrite("/tmp/x/state.json")()).not.toThrow();
    await runReadOnly(async () => {
      expect(isReadOnlyScope()).toBe(true);
      expect(() => beginCaseWrite("/tmp/x/state.json")).toThrow(ReadOnlyScopeWriteError);
      // Storage upkeep a read performs is let through.
      expect(runStorageUpkeep(() => isReadOnlyScope())).toBe(false);
    });
    expect(isReadOnlyScope()).toBe(false);
  });

  it("holds a saved state in memory: a load in the scope sees it, the disk never does", async () => {
    const cases = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-ro-")));
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const store = new StateStore(cases);
    await store.save(emptyState("c1"));
    const staged = { ...emptyState("c1"), attackerPath: "staged" };
    await runReadOnly(async () => {
      await store.save(staged);
      expect(readOnlyStateOverlay()?.has("c1")).toBe(true);
      expect((await store.load("c1")).attackerPath).toBe("staged");
    });
    expect((await store.load("c1")).attackerPath).not.toBe("staged");
  });
});

describe("the AI-call gate inside a preview", () => {
  it("captures the first request and never calls the provider", async () => {
    const provider = new Recording();
    const result = await runAiPreview(async () => {
      await analyzeRestored(ctx, "c1", emptyState("c1"), provider, req("first"), "narrative");
    });
    expect(provider.sent).toHaveLength(0);
    expect(result.outcome).toBe("captured");
    if (result.outcome !== "captured") return;
    expect(result.call).toMatchObject({ kind: "narrative", systemPrompt: "SYS", maskedPrompt: "first" });
  });

  it("does not intercept a real call running at the same time outside the preview", async () => {
    const provider = new Recording();
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const preview = runAiPreview(async () => {
      await gate;
      await analyzeRestored(ctx, "c1", emptyState("c1"), provider, req("preview"), "ask");
    });
    await analyzeRestored(ctx, "c1", emptyState("c1"), provider, req("real"), "ask");
    release();
    const result = await preview;
    expect(provider.sent.map((r) => r.userPrompt)).toEqual(["real"]);
    expect(result.outcome).toBe("captured");
  });

  it("reports an action that finished without asking as no-ai-call", async () => {
    expect((await runAiPreview(async () => "nothing to do")).outcome).toBe("no-ai-call");
  });

  it("keeps the first capture even when the action swallows the stop and asks again", async () => {
    const provider = new Recording();
    const result = await runAiPreview(async () => {
      for (const p of ["one", "two"])
        await analyzeRestored(ctx, "c1", emptyState("c1"), provider, req(p), "x").catch(() => undefined);
    });
    expect(result.outcome === "captured" && result.call.maskedPrompt).toBe("one");
    expect(provider.sent).toHaveLength(0);
  });

  it("is never retried", async () => {
    const fn = vi.fn(async () => {
      throw new AiPreviewCaptured();
    });
    await expect(withRetry(fn, 3, 0)).rejects.toBeInstanceOf(AiPreviewCaptured);
    expect(fn).toHaveBeenCalledTimes(1);
  });
});

describe("the deep pass stops at its first batch in a preview", () => {
  it("does not treat the stop as a failed batch and carry on", async () => {
    const batches = [[{ id: "a" }], [{ id: "b" }], [{ id: "c" }]] as unknown as ForensicEvent[][];
    const observe = vi.fn(async () => {
      throw new AiPreviewCaptured();
    });
    const onFailure = vi.fn();
    const onCheckpoint = vi.fn(async () => undefined);
    await expect(
      executeDeepPassBatches({
        batches,
        floor: "Medium",
        selectionHash: "h",
        validEventIds: new Set(["a", "b", "c"]),
        digestBudget: 1000,
        renderBatch: () => "batch",
        observe,
        onFailure,
        onCheckpoint,
      }),
    ).rejects.toBeInstanceOf(AiPreviewCaptured);
    expect(observe).toHaveBeenCalledTimes(1);
    expect(onFailure).not.toHaveBeenCalled();
    expect(onCheckpoint).not.toHaveBeenCalled();
  });
});
