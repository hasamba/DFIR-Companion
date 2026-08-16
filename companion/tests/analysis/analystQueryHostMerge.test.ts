import { describe, it, expect, beforeEach, vi } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { AssetOverridesStore } from "../../src/analysis/assetOverrides.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";

// Mirrors tests/analysis/caseReportHostMerge.test.ts, which proves the same thing for the four
// report-writing call sites in src/analysis/ai/caseReports.ts. This file proves it for the two
// analyst-facing call sites in src/analysis/ai/analystQueries.ts: a question the analyst types or
// an event they ask to have explained must read a merged near-duplicate host as one machine too —
// and, unlike synthesis, must never refuse to answer while a merge decision is pending.

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

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-analystqueryhostmerge-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  stateStore = new StateStore(cases);
  assetOverridesStore = new AssetOverridesStore(cases);
  prompts = [];
  analyze = vi.fn(async (req: { userPrompt?: string }) => {
    prompts.push(req.userPrompt ?? "");
    // One lenient payload covers both askSchema and explainEventSchema at once (each z.object()
    // ignores fields it does not declare), so the same mock serves ask()/explainEvent() without
    // branching on which call is under test.
    return {
      rawText: JSON.stringify({
        answer: "",
        status: "unknown",
        pointer: "",
        relatedEventIds: [],
        summary: "",
        whyItMatters: "",
        normalContext: "",
        suspiciousIndicators: "",
        attackMapping: "",
        pivotQueries: [],
        evidenceFor: "",
        evidenceAgainst: "",
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
    synthesisProvider: { name: "fake", analyze } as never,
    imageLoader: async () => ({ base64: "A", mimeType: "image/webp" }),
  });
}

describe("a merged host reaches every analyst-query generator as one machine", () => {
  it("ask renders only the canonical spelling", async () => {
    await assetOverridesStore.mergeAsset("c1", "host:win11", "host:win11.windomain.local");
    await buildPipeline().ask("c1", "What happened on the affected endpoint?");
    expect(prompts).toHaveLength(1);
    expect(prompts[0]).toContain("- win11.windomain.local (host)");
    expect(prompts[0]).not.toContain("- WIN11 (host)");
  });

  it("explainEvent renders only the canonical spelling", async () => {
    await assetOverridesStore.mergeAsset("c1", "host:win11", "host:win11.windomain.local");
    await buildPipeline().explainEvent("c1", "a");
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
  it("still answers when no host-alias store is configured", async () => {
    const pipeline = new AnalysisPipeline({
      stateStore,
      synthesisProvider: { name: "fake", analyze } as never,
      imageLoader: async () => ({ base64: "A", mimeType: "image/webp" }),
    });
    await expect(pipeline.ask("c1", "What happened on the affected endpoint?")).resolves.toBeDefined();
    expect(prompts).toHaveLength(1);
    expect(prompts[0]).toContain("- win11 (host)");
    expect(prompts[0]).toContain("- win11.windomain.local (host)");
  });

  // The safety property the brief calls out explicitly: unlike synthesis's resolveHostsOrThrow,
  // neither analyst-query call site may ever throw HostMergeDecisionRequired — an analyst asking a
  // question about a case with an unresolved near-duplicate must still get an answer. Wiring
  // hostDuplicateDismissalStore (the field that enables synthesis's gate) must not change that,
  // because these call sites never read it.
  it("ask still answers with an UNRESOLVED near-duplicate pair and no merge decision", async () => {
    // Two distinct spellings, no mergeAsset call — a pending near-duplicate synthesis would gate on.
    await expect(buildPipeline().ask("c1", "What happened here?")).resolves.toBeDefined();
    expect(prompts).toHaveLength(1);
  });
});
