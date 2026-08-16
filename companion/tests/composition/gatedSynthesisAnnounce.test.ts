// The header pill must not announce a synthesis that is not going to happen.
//
// REPORTED FROM A LIVE CASE: the Now cockpit showed "AI analysis is on hold: win11 and
// win11.windomain.local" while the header pill simultaneously read "AI: synthesizing …". Both
// synthesis paths announce optimistically — the debounce means the alternative is eight seconds of
// silence after the analyst turns AI on — and that announcement was made before anything consulted
// the gate. So for the whole debounce window the two surfaces contradicted each other, and the one
// an analyst glances at said the AI was working when it had not started and would not start.
//
// Making the terminal status correct (it reports "blocked" once synthesize() throws) was not enough:
// the question "is it working or is it blocked?" is asked DURING that window, which is exactly when
// the UI was wrong.
import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { AssetOverridesStore } from "../../src/analysis/assetOverrides.js";
import { HostDuplicateDismissalStore } from "../../src/analysis/hostDuplicateDismissals.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { JobManager } from "../../src/analysis/jobManager.js";
import { createCaptureAnalysis } from "../../src/composition/captureAnalysis.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import type { AppOptions } from "../../src/composition/appOptions.js";
import { pollFor } from "../helpers/poll.js";

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

interface Seen {
  status: string;
  phase?: string;
  detail?: string;
}

async function harness(assets: string[]) {
  const root = await mkdtemp(join(tmpdir(), "dfir-announce-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(cases);
  const s = emptyState("c1");
  assets.forEach((a, i) => s.forensicTimeline.push(ev(`e${i}`, a)));
  await stateStore.save(s);

  const assetOverridesStore = new AssetOverridesStore(cases);
  const hostDuplicateDismissalStore = new HostDuplicateDismissalStore(cases);
  const modelCalls: number[] = [];
  const pipeline = new AnalysisPipeline({
    stateStore,
    assetOverridesStore,
    hostDuplicateDismissalStore,
    synthesisProvider: {
      name: "fake",
      analyze: async () => {
        modelCalls.push(1);
        throw new Error("model reached");
      },
    } as never,
    imageLoader: async () => ({ data: Buffer.from(""), mediaType: "image/png" }) as never,
  });

  const seen: Seen[] = [];
  const options = {
    pipeline,
    stateStore,
    assetOverridesStore,
    hostDuplicateDismissalStore,
    jobManager: new JobManager({ perCaseConcurrency: 1 }),
    autoSynthesize: true,
    autoSynthesizeDebounceMs: 20, // production default is 8000 — the window this bug lived in
    onAiStatus: (_c: string, e: Seen) => seen.push(e),
  } as unknown as AppOptions;

  const analysis = createCaptureAnalysis({
    store: cases,
    options,
    hasAiProvider: () => true,
    getControl: async () => ({ enabled: true, lastAnalyzedSeq: 0 }),
    setControl: async () => ({ enabled: true, lastAnalyzedSeq: 0 }),
    recordAiError: () => {},
    autoEnrichIfEnabled: () => {},
    dispatchNotify: () => {},
  });
  return { analysis, seen, modelCalls };
}

const DUPLICATE = ["WIN11", "WIN11.windomain.local"];
const DISTINCT = ["WIN11", "DC01.windomain.local"];

describe("turning AI on for a case held at the merge gate", () => {
  it("never claims to be synthesizing", async () => {
    const { analysis, seen } = await harness(DUPLICATE);
    await analysis.backfill("c1");
    await pollFor(
      () => `a blocked status, saw ${JSON.stringify(seen)}`,
      async () => (seen.some((e) => e.status === "blocked") ? true : undefined),
    );
    // The precise regression: not one "analyzing / synthesizing" event anywhere in the sequence.
    // Before the fix this produced "synthesizing imported evidence" then "synthesizing conclusions".
    const claimedSynthesis = seen.filter((e) => e.status === "analyzing" && e.phase === "synthesizing");
    expect(claimedSynthesis, "the pill announced a run that could not start").toEqual([]);
  });

  it("says blocked as its FIRST word on the subject, not after the debounce", async () => {
    const { analysis, seen } = await harness(DUPLICATE);
    await analysis.backfill("c1");
    await pollFor(
      () => `a blocked status, saw ${JSON.stringify(seen)}`,
      async () => (seen.some((e) => e.status === "blocked") ? true : undefined),
    );
    expect(seen[0].status).toBe("blocked");
    expect(seen[0].detail).toContain("duplicate host");
  });

  it("never calls the model", async () => {
    const { analysis, seen, modelCalls } = await harness(DUPLICATE);
    await analysis.backfill("c1");
    await pollFor(
      () => `a blocked status, saw ${JSON.stringify(seen)}`,
      async () => (seen.some((e) => e.status === "blocked") ? true : undefined),
    );
    expect(modelCalls).toEqual([]);
  });
});

// The guard must not fire on an ordinary case, or turning AI on would report every case as held.
describe("turning AI on for a case with no duplicate pair", () => {
  it("announces synthesis and reaches the model", async () => {
    const { analysis, seen, modelCalls } = await harness(DISTINCT);
    await analysis.backfill("c1");
    await pollFor(
      () => `the model to be reached, saw ${JSON.stringify(seen)}`,
      async () => (modelCalls.length > 0 ? true : undefined),
    );
    expect(seen.some((e) => e.status === "analyzing" && e.phase === "synthesizing")).toBe(true);
    expect(seen.some((e) => e.status === "blocked")).toBe(false);
  });
});
