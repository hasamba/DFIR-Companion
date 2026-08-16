import { describe, it, expect, beforeEach, vi } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { AssetOverridesStore } from "../../src/analysis/assetOverrides.js";
import { HostDuplicateDismissalStore } from "../../src/analysis/hostDuplicateDismissals.js";
import { HostMergeDecisionRequired } from "../../src/analysis/hostDuplicateGate.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";

function ev(id: string, asset: string): ForensicEvent {
  return {
    id,
    timestamp: "2026-04-22T11:41:00Z",
    description: "suspicious logon",
    severity: "High",
    mitreTechniques: ["T1078"],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset,
    sources: ["Sysmon"],
  };
}

let cases: CaseStore;
let stateStore: StateStore;
let assetOverridesStore: AssetOverridesStore;
let dismissals: HostDuplicateDismissalStore;
let analyze: ReturnType<typeof vi.fn>;

async function seed(assets: string[]): Promise<void> {
  const s = emptyState("c1");
  assets.forEach((a, i) => s.forensicTimeline.push(ev(`e${i}`, a)));
  await stateStore.save(s);
}

function pipeline(): AnalysisPipeline {
  return new AnalysisPipeline({
    stateStore,
    assetOverridesStore,
    hostDuplicateDismissalStore: dismissals,
    synthesisProvider: { name: "fake", analyze } as never,
    imageLoader: async () => ({ data: Buffer.from(""), mediaType: "image/png" }) as never,
  });
}

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-hostdupgate-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  stateStore = new StateStore(cases);
  assetOverridesStore = new AssetOverridesStore(cases);
  dismissals = new HostDuplicateDismissalStore(cases);
  analyze = vi.fn(async () => ({ text: "{}" }));
});

describe("synthesize() near-duplicate gate", () => {
  it("throws before calling the provider when a pair is unresolved", async () => {
    await seed(["WIN11", "WIN11.windomain.local"]);
    await expect(pipeline().synthesize("c1")).rejects.toBeInstanceOf(HostMergeDecisionRequired);
    expect(analyze).not.toHaveBeenCalled();
  });

  it("names the unresolved pair in the thrown error", async () => {
    await seed(["WIN11", "WIN11.windomain.local"]);
    const err = await pipeline()
      .synthesize("c1")
      .catch((e: HostMergeDecisionRequired) => e);
    expect((err as HostMergeDecisionRequired).pairs[0].canonical).toBe("win11.windomain.local");
  });

  it("does not throw once the pair is merged", async () => {
    await seed(["WIN11", "WIN11.windomain.local"]);
    await assetOverridesStore.mergeAsset("c1", "host:win11", "host:win11.windomain.local");
    await pipeline()
      .synthesize("c1")
      .catch(() => undefined);
    expect(analyze).toHaveBeenCalled();
  });

  it("does not throw once the pair is dismissed", async () => {
    await seed(["WIN11", "WIN11.windomain.local"]);
    await dismissals.append("c1", {
      canonical: "win11.windomain.local",
      other: "win11",
      dismissedAt: "t",
      dismissedBy: "a",
    });
    await pipeline()
      .synthesize("c1")
      .catch(() => undefined);
    expect(analyze).toHaveBeenCalled();
  });

  it("does not throw on a case with no near-duplicates", async () => {
    await seed(["WIN11", "DC01"]);
    await pipeline()
      .synthesize("c1")
      .catch(() => undefined);
    expect(analyze).toHaveBeenCalled();
  });

  it("is off when no dismissal store is configured", async () => {
    await seed(["WIN11", "WIN11.windomain.local"]);
    const ungated = new AnalysisPipeline({
      stateStore,
      assetOverridesStore,
      synthesisProvider: { name: "fake", analyze } as never,
      imageLoader: async () => ({ data: Buffer.from(""), mediaType: "image/png" }) as never,
    });
    await ungated.synthesize("c1").catch(() => undefined);
    expect(analyze).toHaveBeenCalled();
  });
});
