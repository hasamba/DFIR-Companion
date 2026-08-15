// Task 11: the near-duplicate merge gate lives in synthesize() (hostDuplicateGate.ts), but a case
// with AI disabled never reaches synthesize() at all — resynthesizeInBackground() bails at its
// `!pipeline.hasSynthesisProvider()` guard before any gate runs. Without a separate check, that
// case would sit on an unresolved duplicate forever with no signal. notifyHostDuplicates() runs
// the same derivation import-side, ahead of both early returns, so an AI-disabled install still
// gets told.
import { describe, it, expect, beforeEach, vi } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { AssetOverridesStore } from "../../src/analysis/assetOverrides.js";
import { HostDuplicateDismissalStore } from "../../src/analysis/hostDuplicateDismissals.js";
import { createCaptureAnalysis } from "../../src/composition/captureAnalysis.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import { pollFor } from "../helpers/poll.js";

function ev(id: string, asset: string): ForensicEvent {
  return {
    id,
    timestamp: "2026-04-22T11:41:00Z",
    description: "d",
    severity: "High",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset,
    sources: ["Sysmon"],
  };
}

let cases: CaseStore;
let stateStore: StateStore;
let dispatchNotify: ReturnType<typeof vi.fn>;

async function seed(assets: string[]): Promise<void> {
  const s = emptyState("c1");
  assets.forEach((a, i) => s.forensicTimeline.push(ev(`e${i}`, a)));
  await stateStore.save(s);
}

function analysis() {
  return createCaptureAnalysis({
    store: cases,
    options: {
      stateStore,
      assetOverridesStore: new AssetOverridesStore(cases),
      hostDuplicateDismissalStore: new HostDuplicateDismissalStore(cases),
    },
    hasAiProvider: () => false,
    getControl: async () => ({ enabled: false }) as never,
    setControl: async () => ({ enabled: false }) as never,
    recordAiError: () => {},
    autoEnrichIfEnabled: () => {},
    dispatchNotify,
  });
}

// notifyHostDuplicates() is deliberately fire-and-forget (`void notifyHostDuplicates(caseId)`), so
// there is no promise the test can await directly. It also does real I/O — StateStore.load()
// round-trips through a worker_threads worker (caseSqliteWorker.ts), and the alias-index +
// dismissal-store loads are each a real fs readFile — so a single setImmediate/microtask tick does
// not reach the dispatchNotify call; measured empirically the full chain takes ~13-18ms. Poll on
// wall-clock time (tests/helpers/poll.ts), the same helper resynthesisCoalescing.test.ts already
// uses to observe this same fire-and-forget function.
const waitForDispatch = () =>
  pollFor(
    () => `dispatchNotify to have been called, last saw ${dispatchNotify.mock.calls.length} call(s)`,
    async () => (dispatchNotify.mock.calls.length > 0 ? true : undefined),
  );

// For a "stays silent" assertion there is no positive signal to poll for — silence is the outcome
// being proven. Wait a fixed budget comfortably above the ~13-18ms measured chain duration (see
// waitForDispatch's comment) before asserting nothing arrived.
const SILENCE_BUDGET_MS = 300;
const waitPastSilenceBudget = () => new Promise((r) => setTimeout(r, SILENCE_BUDGET_MS));

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-hostdup-notify-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  stateStore = new StateStore(cases);
  dispatchNotify = vi.fn();
});

describe("import-time near-duplicate notification", () => {
  it("dispatches one milestone naming both spellings", async () => {
    await seed(["WIN11", "WIN11.windomain.local"]);
    analysis().resynthesizeInBackground("c1");
    await waitForDispatch();
    expect(dispatchNotify).toHaveBeenCalledTimes(1);
    const event = dispatchNotify.mock.calls[0][0];
    expect(event.kind).toBe("milestone");
    expect(JSON.stringify(event)).toContain("win11.windomain.local");
  });

  it("stays silent on a case with no duplicates", async () => {
    await seed(["WIN11", "DC01"]);
    analysis().resynthesizeInBackground("c1");
    await waitPastSilenceBudget();
    expect(dispatchNotify).not.toHaveBeenCalled();
  });

  it("stays silent once the pair is dismissed", async () => {
    await seed(["WIN11", "WIN11.windomain.local"]);
    await new HostDuplicateDismissalStore(cases).append("c1", {
      canonical: "win11.windomain.local",
      other: "win11",
      dismissedAt: "t",
      dismissedBy: "a",
    });
    analysis().resynthesizeInBackground("c1");
    await waitPastSilenceBudget();
    expect(dispatchNotify).not.toHaveBeenCalled();
  });
});
