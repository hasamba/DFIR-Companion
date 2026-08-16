import { describe, it, expect, beforeEach, vi } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { AssetOverridesStore } from "../../src/analysis/assetOverrides.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import type { PlaybookTask } from "../../src/analysis/playbook.js";

// Mirrors tests/analysis/caseReportHostMerge.test.ts, which proves the same thing for the four
// report-writing call sites in src/analysis/ai/caseReports.ts. This file proves it for the two
// hunt-generating call sites in src/analysis/ai/hunts.ts (buildFleetHuntPrompt via suggestHunts,
// buildPlaybookHuntPrompt via suggestPlaybookHunts): a suggested hunt must pivot on one canonical
// host, not silently split its VQL/rationale across two spellings of the same machine — and, unlike
// synthesis, must never refuse to suggest a hunt while a merge decision is pending.

let cases: CaseStore;
let stateStore: StateStore;
let assetOverridesStore: AssetOverridesStore;
let analyze: ReturnType<typeof vi.fn>;
let prompts: string[];

function ev(id: string, asset: string): ForensicEvent {
  return {
    id,
    timestamp: "2026-04-22T11:41:00Z",
    description: "LSASS access",
    severity: "Critical",
    mitreTechniques: ["T1003.001"],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset,
    sources: ["Sysmon"],
  };
}

function task(id: string): PlaybookTask {
  return {
    id,
    title: "Contain the affected endpoint",
    description: "",
    status: "todo",
    priority: "high",
    source: "custom",
    order: 0,
    createdAt: "2026-04-22T11:41:00Z",
    updatedAt: "2026-04-22T11:41:00Z",
  };
}

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-hunthostmerge-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  stateStore = new StateStore(cases);
  assetOverridesStore = new AssetOverridesStore(cases);
  prompts = [];
  analyze = vi.fn(async (req: { userPrompt?: string }) => {
    prompts.push(req.userPrompt ?? "");
    // { suggestions: [] } parses under both huntSuggestionsResponseSchema and
    // playbookHuntResponseSchema (each .catch()-guarded), so the same mock serves
    // suggestHunts()/suggestPlaybookHunts() without branching on which call is under test.
    return { rawText: JSON.stringify({ suggestions: [] }) };
  });
  const s = emptyState("c1");
  s.forensicTimeline.push(ev("a", "WIN11"), ev("b", "WIN11.windomain.local"));
  await stateStore.save(s);
});

function buildPipeline(): AnalysisPipeline {
  return new AnalysisPipeline({
    stateStore,
    assetOverridesStore,
    synthesisProvider: { name: "fake", analyze } as never,
    imageLoader: async () => ({ base64: "A", mimeType: "image/webp" }),
  });
}

describe("a merged host reaches every hunt generator as one machine", () => {
  it("suggestHunts renders only the canonical spelling", async () => {
    await assetOverridesStore.mergeAsset("c1", "host:win11", "host:win11.windomain.local");
    await buildPipeline().suggestHunts("c1");
    expect(prompts).toHaveLength(1);
    expect(prompts[0]).toContain("- win11.windomain.local (host)");
    expect(prompts[0]).not.toContain("- WIN11 (host)");
  });

  it("suggestPlaybookHunts renders only the canonical spelling", async () => {
    await assetOverridesStore.mergeAsset("c1", "host:win11", "host:win11.windomain.local");
    await buildPipeline().suggestPlaybookHunts("c1", [task("t1")]);
    expect(prompts).toHaveLength(1);
    expect(prompts[0]).toContain("- win11.windomain.local (host)");
    expect(prompts[0]).not.toContain("- WIN11 (host)");
  });

  // Constraint from the host-alias-index feature: an install with NEITHER assetOverridesStore NOR
  // velociraptorClientStore wired (older tests, CLI scripts) must behave exactly as before —
  // loadHostAliasIndex degrades to a usable empty index rather than failing the call. That empty
  // index still normalizes casing (resolveHost falls back through canonicalHostName's lowercase —
  // the same thing synthesis's already-shipped resolveHostsOrThrow does unconditionally), but with
  // no merge recorded anywhere the two spellings must NOT collapse into one asset row.
  it("still suggests hunts when no host-alias store is configured", async () => {
    const pipeline = new AnalysisPipeline({
      stateStore,
      synthesisProvider: { name: "fake", analyze } as never,
      imageLoader: async () => ({ base64: "A", mimeType: "image/webp" }),
    });
    await expect(pipeline.suggestHunts("c1")).resolves.toBeDefined();
    expect(prompts).toHaveLength(1);
    expect(prompts[0]).toContain("- win11 (host)");
    expect(prompts[0]).toContain("- win11.windomain.local (host)");
  });

  // The safety property the brief calls out explicitly: unlike synthesis's resolveHostsOrThrow,
  // neither hunt call site may ever throw HostMergeDecisionRequired — an analyst asking for hunts
  // against a case with an unresolved near-duplicate must still get suggestions.
  it("suggestPlaybookHunts still runs with an UNRESOLVED near-duplicate pair and no merge decision", async () => {
    // Two distinct spellings, no mergeAsset call — a pending near-duplicate synthesis would gate on.
    await expect(buildPipeline().suggestPlaybookHunts("c1", [task("t1")])).resolves.toBeDefined();
    expect(prompts).toHaveLength(1);
  });
});
