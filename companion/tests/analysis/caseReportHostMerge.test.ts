import { describe, it, expect, beforeEach, vi } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { AssetOverridesStore } from "../../src/analysis/assetOverrides.js";
import { HypothesisStore } from "../../src/analysis/hypothesisStore.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";

// Mirrors tests/analysis/synthesisPromptHostMerge.test.ts, which proves the same thing for the
// synthesis prompt. This file proves it for the four REPORT-WRITING call sites in
// src/analysis/ai/caseReports.ts: an exported report is a user-visible deliverable, so after an
// analyst merges two spellings of one host, it must not still describe two machines.

let cases: CaseStore;
let stateStore: StateStore;
let assetOverridesStore: AssetOverridesStore;
let hypothesisStore: HypothesisStore;
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

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-casereporthostmerge-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  stateStore = new StateStore(cases);
  assetOverridesStore = new AssetOverridesStore(cases);
  hypothesisStore = new HypothesisStore(cases);
  prompts = [];
  analyze = vi.fn(async (req: { userPrompt?: string }) => {
    prompts.push(req.userPrompt ?? "");
    // One lenient payload covers every report schema at once (each z.object() ignores fields it
    // does not declare), so the same mock serves generateNarrative/executiveSummary/
    // remediationPlan/hypothesisReview without branching on which call is under test.
    return {
      rawText: JSON.stringify({
        narrativeTimeline: "",
        summary: "",
        plan: "",
        reviews: [],
      }),
    };
  });
  const s = emptyState("c1");
  s.forensicTimeline.push(ev("a", "WIN11"), ev("b", "WIN11.windomain.local"));
  await stateStore.save(s);
});

function buildPipeline(): AnalysisPipeline {
  return new AnalysisPipeline({
    stateStore,
    assetOverridesStore,
    hypothesisStore,
    synthesisProvider: { name: "fake", analyze } as never,
    imageLoader: async () => ({ data: Buffer.from(""), mediaType: "image/png" }) as never,
  });
}

describe("a merged host reaches every case-report generator as one machine", () => {
  it("generateNarrative renders only the canonical spelling", async () => {
    await assetOverridesStore.mergeAsset("c1", "host:win11", "host:win11.windomain.local");
    await buildPipeline().generateNarrative("c1");
    expect(prompts).toHaveLength(1);
    expect(prompts[0]).toContain("- win11.windomain.local (host)");
    expect(prompts[0]).not.toContain("- WIN11 (host)");
  });

  it("executiveSummary renders only the canonical spelling", async () => {
    await assetOverridesStore.mergeAsset("c1", "host:win11", "host:win11.windomain.local");
    await buildPipeline().executiveSummary("c1");
    expect(prompts).toHaveLength(1);
    expect(prompts[0]).toContain("- win11.windomain.local (host)");
    expect(prompts[0]).not.toContain("- WIN11 (host)");
  });

  it("remediationPlan renders only the canonical spelling", async () => {
    await assetOverridesStore.mergeAsset("c1", "host:win11", "host:win11.windomain.local");
    await buildPipeline().remediationPlan("c1");
    expect(prompts).toHaveLength(1);
    expect(prompts[0]).toContain("- win11.windomain.local (host)");
    expect(prompts[0]).not.toContain("- WIN11 (host)");
  });

  it("hypothesisReview renders only the canonical spelling", async () => {
    await assetOverridesStore.mergeAsset("c1", "host:win11", "host:win11.windomain.local");
    // hypothesisReview returns early with no AI call when there is nothing OPEN to review.
    await hypothesisStore.add("c1", { title: "Attacker pivoted from WIN11 to a domain controller" });
    await buildPipeline().hypothesisReview("c1");
    expect(prompts).toHaveLength(1);
    expect(prompts[0]).toContain("- win11.windomain.local (host)");
    expect(prompts[0]).not.toContain("- WIN11 (host)");
  });

  // Constraint from the host-alias-index feature: an install with NEITHER assetOverridesStore NOR
  // velociraptorClientStore wired (older tests, CLI scripts) must behave exactly as before —
  // loadHostAliasIndex degrades to a usable empty index rather than failing the report. That empty
  // index still normalizes casing (resolveHost falls back through canonicalHostName's lowercase —
  // the same thing synthesis's already-shipped resolveHostsOrThrow does unconditionally), but with
  // no merge recorded anywhere the two spellings must NOT collapse into one asset row.
  it("still generates a report when no host-alias store is configured", async () => {
    const pipeline = new AnalysisPipeline({
      stateStore,
      hypothesisStore,
      synthesisProvider: { name: "fake", analyze } as never,
      imageLoader: async () => ({ data: Buffer.from(""), mediaType: "image/png" }) as never,
    });
    await expect(pipeline.executiveSummary("c1")).resolves.toBeDefined();
    expect(prompts).toHaveLength(1);
    expect(prompts[0]).toContain("- win11 (host)");
    expect(prompts[0]).toContain("- win11.windomain.local (host)");
  });
});
