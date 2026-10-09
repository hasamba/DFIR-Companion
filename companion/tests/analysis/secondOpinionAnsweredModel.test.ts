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

/** True when the request is the second-opinion referee (reconcile) call. */
const isReferee = (req: AnalyzeRequest) => req.systemPrompt.includes("RECONCILING");

/** A verdict for every delta id in the reconcile prompt — enough for the referee pass to succeed. */
function verdictsFor(req: AnalyzeRequest): string {
  const ids = [...new Set(req.userPrompt.match(/\b[a-z_]+:[a-z0-9-]+/g) ?? [])];
  return JSON.stringify({
    summary: "judged",
    verdicts: ids.map((id) => ({ id, rationale: "r", recommendation: "review" })),
  });
}

/** Writes model A's synthesis and, when `referees`, answers the referee too. */
class Answering implements AIProvider {
  refereeCalls = 0;
  constructor(
    readonly name: string,
    readonly model: string,
    private readonly referees: boolean,
  ) {}
  async analyze(req: AnalyzeRequest): Promise<AnalyzeResult> {
    if (!isReferee(req)) return { rawText: A_DELTA };
    this.refereeCalls++;
    return { rawText: this.referees ? verdictsFor(req) : A_DELTA };
  }
}

/** The primary's filter stops synthesis only; it answers the referee. */
class StoppedOnSynthesis implements AIProvider {
  readonly name = "claude-code";
  readonly model = "opus";
  async analyze(req: AnalyzeRequest): Promise<AnalyzeResult> {
    if (isReferee(req)) return { rawText: verdictsFor(req) };
    throw safetyStopError("Claude Code (opus)");
  }
}

interface PipelineExtras {
  fallback?: AIProvider;
  referee?: { provider: AIProvider; label: string };
}

function pipeline(primary: AIProvider, extras: PipelineExtras = {}): AnalysisPipeline {
  return new AnalysisPipeline({
    provider: primary,
    synthesisProvider: primary,
    synthesisModelLabel: "opus",
    synthesisFallback: {
      provider: extras.fallback ?? new MockProvider("codex", A_DELTA, "gpt-6-sol"),
      label: "gpt-6-sol",
    },
    ...(extras.referee ? { referee: extras.referee } : {}),
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

  it("keeps the default referee on the configured primary's label when the primary judges", async () => {
    const record = await pipeline(new StoppedOnSynthesis()).secondOpinion("c1");

    // Pass 0 ran on the fallback, but the referee ran on the primary and it answered: the referee
    // is the primary, not the fallback that wrote A.
    expect(record.modelA).toBe("gpt-6-sol");
    expect(record.refereeError).toBeUndefined();
    expect(record.referee).toBe("opus");
  });

  it("still names the fallback when pass 0 is a no-op over a fallback-written synthesis", async () => {
    const p = pipeline(new AlwaysStopped());
    await p.synthesize("c1"); // written by the fallback
    const primary = new AlwaysStopped();
    const record = await pipeline(primary).secondOpinion("c1"); // pass 0 skips: nothing changed

    expect(record.modelA).toBe("gpt-6-sol");
  });

  it("a referee-only re-run names the model that was last tried", async () => {
    const p = pipeline(new AlwaysStopped()); // the fallback writes A but cannot referee
    const first = await p.secondOpinion("c1");
    expect(first.modelA).toBe("gpt-6-sol");

    const { record, failed } = await p.rerunSecondOpinionReferee("c1");
    expect(failed).toBe(true);
    // #2083: the primary was stopped, the fallback was asked and failed — the fallback is named.
    expect(record.refereeError?.referee).toBe("gpt-6-sol");
    expect(record.modelA).toBe("gpt-6-sol");
  });
});

describe("the default referee falls back on a safety stop (#2083)", () => {
  it("folds the fallback's verdicts and names the fallback as referee", async () => {
    const fallback = new Answering("codex", "gpt-6-sol", true);
    const record = await pipeline(new AlwaysStopped(), { fallback }).secondOpinion("c1");

    expect(fallback.refereeCalls).toBe(1);
    expect(record.refereeError).toBeUndefined();
    expect(record.referee).toBe("gpt-6-sol");
    expect(record.deltas.some((d) => d.rationale)).toBe(true);
  });

  it("names the fallback when the fallback was tried and failed too", async () => {
    const fallback = new Answering("codex", "gpt-6-sol", false);
    const record = await pipeline(new AlwaysStopped(), { fallback }).secondOpinion("c1");

    expect(fallback.refereeCalls).toBe(1);
    expect(record.refereeError?.referee).toBe("gpt-6-sol");
  });

  it("never falls back for a referee picked with DFIR_AI_RECONCILE_MODEL", async () => {
    const fallback = new Answering("codex", "gpt-6-sol", true);
    const picked = new AlwaysStopped();
    const record = await pipeline(new AlwaysStopped(), {
      fallback,
      referee: { provider: picked, label: "picked/referee" },
    }).secondOpinion("c1");

    expect(picked.calls).toBe(1);
    expect(fallback.refereeCalls).toBe(0);
    expect(record.refereeError?.referee).toBe("picked/referee");
  });

  it("a referee-only re-run falls back the same way", async () => {
    const first = await pipeline(new AlwaysStopped()).secondOpinion("c1"); // referee fails
    expect(first.refereeError).toBeDefined();

    const fallback = new Answering("codex", "gpt-6-sol", true);
    const { record, failed } = await pipeline(new AlwaysStopped(), { fallback }).rerunSecondOpinionReferee(
      "c1",
    );
    expect(failed).toBe(false);
    expect(fallback.refereeCalls).toBe(1);
    expect(record.referee).toBe("gpt-6-sol");
    expect(record.refereeError).toBeUndefined();
  });

  it("a referee-only re-run with a picked referee never falls back", async () => {
    await pipeline(new AlwaysStopped()).secondOpinion("c1"); // referee fails
    const fallback = new Answering("codex", "gpt-6-sol", true);
    const { record, failed } = await pipeline(new AlwaysStopped(), {
      fallback,
      referee: { provider: new AlwaysStopped(), label: "picked/referee" },
    }).rerunSecondOpinionReferee("c1");

    expect(failed).toBe(true);
    expect(fallback.refereeCalls).toBe(0);
    expect(record.refereeError?.referee).toBe("picked/referee");
  });
});
