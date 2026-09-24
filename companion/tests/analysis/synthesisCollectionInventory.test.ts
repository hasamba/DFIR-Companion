import { describe, it, expect, beforeEach, vi } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { VeloHuntStore, type VeloHuntJob } from "../../src/analysis/veloHuntStore.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";

// #1588 — the collection inventory reaches the synthesis prompt, and a hunt whose outcome changes the
// inventory (no new timeline row) still triggers a fresh synthesis instead of a skip.

let cases: CaseStore;
let stateStore: StateStore;
let hunts: VeloHuntStore;
let prompts: string[];
let reply: Record<string, unknown>;

function ev(id: string, over: Partial<ForensicEvent> = {}): ForensicEvent {
  return {
    id,
    timestamp: "2026-08-28T09:00:00Z",
    description: `Sigma: suspicious file write ${id}`,
    severity: "High",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset: "WS01",
    sources: ["Chainsaw"],
    ...over,
  };
}

function pipeline(): AnalysisPipeline {
  const analyze = vi.fn(async (req: { userPrompt?: string }) => {
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
        ...reply,
      }),
    };
  });
  return new AnalysisPipeline({
    stateStore,
    veloHuntStore: hunts,
    synthesisProvider: { name: "fake", analyze } as never,
    retries: 0,
    imageLoader: async () => ({ data: Buffer.from(""), mediaType: "image/png" }) as never,
  });
}

const JOB: VeloHuntJob = {
  bundleId: "b",
  bundleName: "B",
  artifacts: ["Windows.Search.FileFinder"],
  huntId: "H.1",
  launchedAt: "2026-08-28T10:00:00Z",
  waitMinutes: 5,
  collectAt: "2026-08-28T10:05:00Z",
  status: "imported",
};

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-inventory-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  stateStore = new StateStore(cases);
  hunts = new VeloHuntStore(cases);
  prompts = [];
  reply = {};
  const s = emptyState("c1");
  s.forensicTimeline.push(ev("e1"), ev("e2", { timestamp: "2026-08-28T09:05:00Z" }));
  await stateStore.save(s);
});

describe("the collection inventory in the synthesis prompt (#1588)", () => {
  it("tells the model what the case holds and how to treat a negative answer", async () => {
    await pipeline().synthesize("c1", { force: true });
    const p = prompts[0];
    expect(p).toContain("COLLECTION INVENTORY");
    // Canonical (alias-resolved) host names are lowercase, as everywhere else in the prompt.
    expect(p).toContain("- ws01: collected raw: none; no raw collection found: execution, file-activity");
    expect(p).toContain("Chainsaw (detections) 2");
    expect(p).toContain("Rules for negative answers:");
  });

  it("a hunt that came back empty changes the inventory and re-runs synthesis", async () => {
    const pl = pipeline();
    await pl.synthesize("c1");
    await pl.synthesize("c1");
    expect(prompts).toHaveLength(1); // unchanged inputs → skipped
    await hunts.upsert("c1", { ...JOB, emptyArtifacts: ["Windows.Search.FileFinder"] });
    await pl.synthesize("c1");
    expect(prompts).toHaveLength(2);
    expect(prompts[1]).toContain("Windows.Search.FileFinder — returned no rows");
  });

  it("an impact answer the case could not have seen is saved as not settled, with one collection step", async () => {
    reply = {
      keyQuestions: [
        {
          id: "q_impact",
          question: "What was the impact?",
          status: "answered",
          answer: "No confirmed data encryption or destruction was observed.",
          pointer: "",
        },
      ],
      nextSteps: [],
    };
    await pipeline().synthesize("c1", { force: true });
    const saved = await stateStore.load("c1");
    const q = saved.keyQuestions.find((k) => k.id === "q_impact");
    expect(q?.status).toBe("partial");
    expect(q?.answer).toMatch(/Not settled — .*file-activity/);
    expect(q?.collect?.artifact).toBe("Windows.EventLogs.Evtx");
    const steps = saved.nextSteps.filter((n) => n.id.startsWith("ns-coverage-"));
    expect(steps).toHaveLength(1);
    expect(steps[0].collect?.host).toBe("ws01");
  });

  it("a malformed hunt file never stops synthesis; the bad jobs are dropped", async () => {
    const bad = [
      null,
      { huntId: "H.9" },
      { huntId: "H.2", status: "imported", artifacts: "not-a-list" },
      JOB,
    ];
    await writeFile(join(cases.stateDir("c1"), "velo-hunt.json"), JSON.stringify(bad));
    await pipeline().synthesize("c1", { force: true });
    expect(prompts).toHaveLength(1);
    expect(prompts[0]).toContain("COLLECTION INVENTORY");
    expect(prompts[0]).toContain("Windows.Search.FileFinder — in the archive only");
  });
});
