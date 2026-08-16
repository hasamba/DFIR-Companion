import { describe, it, expect, beforeEach, vi } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { AssetOverridesStore } from "../../src/analysis/assetOverrides.js";
import { HostDuplicateDismissalStore } from "../../src/analysis/hostDuplicateDismissals.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";

let cases: CaseStore;
let stateStore: StateStore;
let assetOverridesStore: AssetOverridesStore;
let dismissals: HostDuplicateDismissalStore;
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
  const root = await mkdtemp(join(tmpdir(), "dfir-hostmergeprompt-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  stateStore = new StateStore(cases);
  assetOverridesStore = new AssetOverridesStore(cases);
  dismissals = new HostDuplicateDismissalStore(cases);
  prompts = [];
  analyze = vi.fn(async (req: { userPrompt?: string }) => {
    prompts.push(req.userPrompt ?? "");
    return {
      rawText: JSON.stringify({
        findings: [],
        iocs: [],
        mitreTechniques: [],
        threadsOpened: [],
        threadsClosed: [],
        timelineNote: "",
        summary: "",
      }),
    };
  });
  const s = emptyState("c1");
  s.forensicTimeline.push(ev("a", "WIN11"), ev("b", "WIN11.windomain.local"));
  await stateStore.save(s);
});

describe("a merged host reaches the model as one machine", () => {
  it("renders only the canonical spelling in the prompt", async () => {
    await assetOverridesStore.mergeAsset("c1", "host:win11", "host:win11.windomain.local");
    const pipeline = new AnalysisPipeline({
      stateStore,
      assetOverridesStore,
      hostDuplicateDismissalStore: dismissals,
      synthesisProvider: { name: "fake", analyze } as never,
      imageLoader: async () => ({ data: Buffer.from(""), mediaType: "image/png" }) as never,
    });
    await pipeline.synthesize("c1").catch(() => undefined);
    expect(prompts).toHaveLength(1);
    expect(prompts[0]).toContain("<host:win11.windomain.local>");
    expect(prompts[0]).not.toContain("<host:WIN11>");
  });
});
