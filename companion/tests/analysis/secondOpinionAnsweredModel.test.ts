import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SynthMetaStore } from "../../src/analysis/synthMeta.js";
import { SecondOpinionStore } from "../../src/analysis/secondOpinionStore.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import {
  MockProvider,
  safetyStopError,
  type AIProvider,
  type AnalyzeRequest,
  type AnalyzeResult,
} from "../../src/providers/provider.js";

// #2076: when the primary's safety filter stops pass 0 and the fallback writes model A's synthesis,
// the second-opinion record and its telemetry name the fallback — the model that actually wrote A.
// The default referee still runs on the primary, so it keeps the primary's label.

const finding = (id: string, title: string) => ({
  id,
  severity: "Medium",
  title,
  description: "d",
  relatedIocs: [],
  mitreTechniques: [],
  status: "open",
  relatedEventIds: ["e1"],
});

const delta = (findings: unknown[]) =>
  JSON.stringify({
    findings,
    iocs: [],
    mitreTechniques: [],
    threadsOpened: [],
    threadsClosed: [],
    timelineNote: "",
    summary: "s",
    forensicEvents: [],
  });

const A_DELTA = delta([finding("f1", "Suspicious login")]);
const B_DELTA = delta([finding("f1", "Suspicious login"), finding("g2", "B only finding")]);

/** The primary: its safety filter stops every answer, synthesis and referee alike. */
class AlwaysStopped implements AIProvider {
  readonly name = "claude-code";
  readonly model = "opus";
  calls = 0;
  async analyze(_req: AnalyzeRequest): Promise<AnalyzeResult> {
    this.calls++;
    throw safetyStopError("Claude Code (opus)");
  }
}

let stateStore: StateStore;
let synthMetaStore: SynthMetaStore;
let secondOpinionStore: SecondOpinionStore;

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-so-answered-"));
  const caseStore = new CaseStore(root);
  await caseStore.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
  stateStore = new StateStore(caseStore);
  synthMetaStore = new SynthMetaStore(caseStore);
  secondOpinionStore = new SecondOpinionStore(caseStore);
  const seeded = emptyState("c1");
  seeded.forensicTimeline.push({
    id: "e1",
    timestamp: "2026-05-20T09:05:00.000Z",
    description: "logon",
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
  });
  await stateStore.save(seeded);
});

function pipeline(primary: AIProvider): AnalysisPipeline {
  return new AnalysisPipeline({
    provider: primary,
    synthesisProvider: primary,
    synthesisModelLabel: "opus",
    synthesisFallback: { provider: new MockProvider("codex", A_DELTA, "gpt-6-sol"), label: "gpt-6-sol" },
    stateStore,
    synthMetaStore,
    secondOpinionStore,
    secondOpinionProvider: new MockProvider("second", B_DELTA, "gpt-5"),
    secondOpinionModelLabel: "second/gpt-5",
    imageLoader: async () => ({ base64: "A", mimeType: "image/webp" }),
    retries: 0,
    backoffMs: 0,
  });
}

describe("second opinion names the model that wrote A (#2076)", () => {
  it("labels model A with the fallback when the primary was stopped on pass 0", async () => {
    const record = await pipeline(new AlwaysStopped()).secondOpinion("c1");

    expect(record.modelA).toBe("gpt-6-sol");
    expect(record.modelB).toBe("second/gpt-5");
    const meta = await synthMetaStore.load("c1");
    expect(meta.secondOpinionPerf?.modelA).toBe("gpt-6-sol");
  });

  it("keeps the default referee on the configured primary's label", async () => {
    const record = await pipeline(new AlwaysStopped()).secondOpinion("c1");

    // The referee runs on the primary, whose safety filter stops it too: the failure names the
    // model that was actually tried — the primary, not the fallback that wrote A.
    expect(record.refereeError?.referee).toBe("opus");
  });

  it("still names the fallback when pass 0 is a no-op over a fallback-written synthesis", async () => {
    const p = pipeline(new AlwaysStopped());
    await p.synthesize("c1"); // written by the fallback
    const primary = new AlwaysStopped();
    const record = await pipeline(primary).secondOpinion("c1"); // pass 0 skips: nothing changed

    expect(record.modelA).toBe("gpt-6-sol");
  });

  it("a referee-only re-run still runs under the configured primary's label", async () => {
    const p = pipeline(new AlwaysStopped());
    const first = await p.secondOpinion("c1");
    expect(first.modelA).toBe("gpt-6-sol");

    const { record, failed } = await p.rerunSecondOpinionReferee("c1");
    expect(failed).toBe(true);
    expect(record.refereeError?.referee).toBe("opus");
    expect(record.modelA).toBe("gpt-6-sol");
  });
});
