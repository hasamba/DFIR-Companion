import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { AiCostStore, bucketForLabel } from "../../src/analysis/aiCost.js";

describe("bucketForLabel", () => {
  it("maps 'extract' to vision", () => {
    expect(bucketForLabel("extract")).toBe("vision");
  });
  it("maps the real synthesis label 'synthesis' and second-opinion reconcile to synthesis", () => {
    expect(bucketForLabel("synthesis")).toBe("synthesis");
    expect(bucketForLabel("second-opinion-reconcile")).toBe("synthesis");
  });
  it("also maps analyzeRestored's unused default label 'ai' to synthesis (defensive; no real call site currently omits the label)", () => {
    expect(bucketForLabel("ai")).toBe("synthesis");
  });
  it("maps everything else to other", () => {
    expect(bucketForLabel("ask")).toBe("other");
    expect(bucketForLabel("csv")).toBe("other");
    expect(bucketForLabel("narrative")).toBe("other");
  });
});

describe("AiCostStore", () => {
  let store: AiCostStore;
  beforeEach(async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-aicost-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    store = new AiCostStore(cases);
  });

  it("returns an all-empty state when no file exists yet", async () => {
    const state = await store.load("c1");
    expect(state.vision).toEqual({
      totalCalls: 0, totalCostUSD: 0, hasCost: false,
      totalInputTokens: 0, totalOutputTokens: 0, hasTokens: false,
      byModel: {},
    });
    expect(state.synthesis.totalCalls).toBe(0);
    expect(state.other.totalCalls).toBe(0);
  });

  it("accumulates cost and tokens into the right bucket and model", async () => {
    await store.record("c1", "vision", "openrouter", "google/gemini-3.1-flash-lite",
      { inputTokens: 100, outputTokens: 20, costUSD: 0.01 });
    await store.record("c1", "vision", "openrouter", "google/gemini-3.1-flash-lite",
      { inputTokens: 100, outputTokens: 20, costUSD: 0.01 });
    const state = await store.load("c1");
    expect(state.vision.totalCalls).toBe(2);
    expect(state.vision.totalCostUSD).toBeCloseTo(0.02);
    expect(state.vision.hasCost).toBe(true);
    expect(state.vision.totalInputTokens).toBe(200);
    expect(state.vision.totalOutputTokens).toBe(40);
    expect(state.vision.byModel["openrouter/google/gemini-3.1-flash-lite"]).toEqual({
      calls: 2, costUSD: 0.02, hasCost: true, inputTokens: 200, outputTokens: 40, hasTokens: true,
    });
    expect(state.synthesis.totalCalls).toBe(0);
  });

  it("still counts the call when usage is undefined, but leaves hasCost/hasTokens false", async () => {
    await store.record("c1", "other", "gemini", "gemini-2.5-pro", undefined);
    const state = await store.load("c1");
    expect(state.other.totalCalls).toBe(1);
    expect(state.other.hasCost).toBe(false);
    expect(state.other.hasTokens).toBe(false);
    expect(state.other.byModel["gemini/gemini-2.5-pro"]).toEqual({
      calls: 1, costUSD: 0, hasCost: false, inputTokens: 0, outputTokens: 0, hasTokens: false,
    });
  });

  it("tracks two different models in the same bucket separately", async () => {
    await store.record("c1", "synthesis", "openrouter", "anthropic/claude-opus-4.8", { costUSD: 0.5 });
    await store.record("c1", "synthesis", "openrouter", "z-ai/glm-5.2", { costUSD: 0.09 });
    const state = await store.load("c1");
    expect(state.synthesis.totalCalls).toBe(2);
    expect(state.synthesis.totalCostUSD).toBeCloseTo(0.59);
    expect(Object.keys(state.synthesis.byModel).sort()).toEqual([
      "openrouter/anthropic/claude-opus-4.8",
      "openrouter/z-ai/glm-5.2",
    ]);
  });

  it("keeps cases isolated from each other", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-aicost-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    await cases.createCase({ caseId: "c2", name: "n", investigator: "i", aiProvider: null });
    const s = new AiCostStore(cases);
    await s.record("c1", "vision", "openrouter", "m", { costUSD: 1 });
    const c2State = await s.load("c2");
    expect(c2State.vision.totalCalls).toBe(0);
  });
});
