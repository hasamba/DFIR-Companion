import { describe, expect, it, beforeEach } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { AiCostStore, promptTokensOf } from "../../src/analysis/aiCost.js";
import { inUsageScope, newUsageTally, noteUsage } from "../../src/analysis/ai/usageScope.js";

// #2663: cache figures in the AI cost file, on one convention across providers, and a round's own tally.

let cases: CaseStore;
let store: AiCostStore;
beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-aicost-cache-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  store = new AiCostStore(cases);
});

describe("promptTokensOf (#2663)", () => {
  it("Anthropic-style input excludes cache: all input = input + reads + writes", () => {
    expect(promptTokensOf({ inputTokens: 100, cacheReadTokens: 900, cacheCreationTokens: 50 })).toBe(1050);
  });
  it("Gemini/OpenAI-style input already includes the cached part", () => {
    expect(promptTokensOf({ inputTokens: 1000, cacheReadTokens: 900, inputIncludesCache: true })).toBe(1000);
  });
});

describe("AiCostStore cache figures (#2663)", () => {
  it("accumulates prompt, cache read and write per bucket and model; raw input is unchanged", async () => {
    await store.record("c1", "watson", "claude-code", "sonnet", {
      inputTokens: 100,
      outputTokens: 10,
      cacheReadTokens: 900,
    });
    const s = await store.record("c1", "watson", "claude-code", "sonnet", {
      inputTokens: 50,
      outputTokens: 5,
      cacheCreationTokens: 200,
    });
    const b = s.watson;
    expect(b.totalInputTokens).toBe(150);
    expect(b.promptTokens).toBe(1250);
    expect(b.cacheReadTokens).toBe(900);
    expect(b.cacheWriteTokens).toBe(200);
    expect(b.hasCache).toBe(true);
    expect(b.cacheSince).toMatch(/^\d{4}-\d\d-\d\dT/);
    expect(b.byModel["claude-code/sonnet"].cacheReadTokens).toBe(900);
  });

  it("an explicit zero cache read is reported cache; an absent one is not", async () => {
    let s = await store.record("c1", "other", "p", "m", { inputTokens: 10, outputTokens: 1 });
    expect(s.other.hasCache).toBe(false);
    s = await store.record("c1", "other", "p", "m", { inputTokens: 10, outputTokens: 1, cacheReadTokens: 0 });
    expect(s.other.hasCache).toBe(true);
  });

  it("a file written before the cache counters loads as zero and keeps its lifetime totals", async () => {
    const legacy = {
      watson: {
        totalCalls: 4,
        totalCostUSD: 1,
        hasCost: true,
        totalInputTokens: 4000,
        totalOutputTokens: 400,
        hasTokens: true,
        byModel: {},
      },
    };
    await writeFile(join(cases.stateDir("c1"), "ai-cost.json"), JSON.stringify(legacy));
    const before = await store.load("c1");
    expect(before.watson.promptTokens).toBe(0);
    expect(before.watson.hasCache).toBe(false);
    const after = await store.record("c1", "watson", "p", "m", {
      inputTokens: 10,
      outputTokens: 1,
      cacheReadTokens: 5,
    });
    expect(after.watson.totalInputTokens).toBe(4010);
    expect(after.watson.promptTokens).toBe(15);
  });
});

describe("a round's own usage tally (#2663)", () => {
  it("counts every call made inside its scope, and none outside it", async () => {
    const tally = newUsageTally();
    noteUsage({ inputTokens: 999 }); // outside any round: not counted
    await inUsageScope(tally, async () => {
      noteUsage({ inputTokens: 100, cacheReadTokens: 900 });
      await Promise.resolve();
      noteUsage({ inputTokens: 40, cacheReadTokens: 10, inputIncludesCache: true });
    });
    expect(tally).toEqual({ promptTokens: 1040, cacheReadTokens: 910, reported: true });
  });

  it("two rounds running together never mix their counts", async () => {
    const a = newUsageTally();
    const b = newUsageTally();
    await Promise.all([
      inUsageScope(a, async () => {
        await new Promise((r) => setTimeout(r, 5));
        noteUsage({ inputTokens: 1 });
      }),
      inUsageScope(b, async () => {
        noteUsage({ inputTokens: 2 });
        await new Promise((r) => setTimeout(r, 1));
        noteUsage({ inputTokens: 3 });
      }),
    ]);
    expect(a.promptTokens).toBe(1);
    expect(b.promptTokens).toBe(5);
  });
});
