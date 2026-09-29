// #1866 (item 2): a deleted case's pending synthesis work never touches a same-id successor.
// Before: the debounce timer, the in-flight mark and the deferral waiter were keyed by case id
// alone, so the old case's debounced kick fired for the new case, and the new case's first kick
// waited behind the deleted case's hung run.
import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createCaptureAnalysis } from "../../src/composition/captureAnalysis.js";
import { forgetCaseKeyedState } from "../../src/storage/caseKeyedState.js";
import type { AppOptions } from "../../src/composition/appOptions.js";
import type { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import type { AiControl } from "../../src/analysis/aiControl.js";
import { pollFor } from "../helpers/poll.js";

const ID = "case-1866";

async function harness(debounceMs: number) {
  const root = await mkdtemp(join(tmpdir(), "dfir-1866-synth-"));
  const store = new CaseStore(root);
  const runs: { release: () => void }[] = [];
  const pipeline = {
    hasSynthesisProvider: () => true,
    synthesize: () => new Promise((resolve) => runs.push({ release: () => resolve({}) })),
  } as unknown as AnalysisPipeline;
  const options = {
    pipeline,
    autoSynthesize: true,
    autoSynthesizeDebounceMs: debounceMs,
    synthMetaStore: { markOutOfDate: async () => {} },
  } as unknown as AppOptions;
  const analysis = createCaptureAnalysis({
    store,
    options,
    hasAiProvider: () => true,
    getControl: async () => ({ enabled: true }) as AiControl,
    setControl: async () => ({ enabled: true }) as AiControl,
    recordAiError: () => {},
    autoEnrichIfEnabled: () => {},
    dispatchNotify: () => {},
  });
  const create = () => store.createCase({ caseId: ID, name: "n", investigator: "i", aiProvider: null });
  // What the delete route does: remove the folder, then clear the state that outlives it.
  const deleteCase = async () => {
    await store.updateCaseMeta(ID, { status: "closed" });
    await store.deleteCaseFolder(ID, { afterDelete: async () => forgetCaseKeyedState(root, ID) });
  };
  return { analysis, runs, create, deleteCase };
}

const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

describe("synthesis state across delete + same-id re-create (#1866)", () => {
  it("the deleted case's pending debounce never fires a synthesis for the new case", async () => {
    const { analysis, runs, create, deleteCase } = await harness(40);
    await create();
    analysis.scheduleSynthesis(ID); // debounce pending
    await deleteCase();
    await create();
    await wait(100);
    expect(runs, "the old debounce timer must be cleared on delete").toHaveLength(0);
  });

  it("the new case's kick does not wait behind the deleted case's hung run", async () => {
    const { analysis, runs, create, deleteCase } = await harness(5);
    await create();
    analysis.scheduleSynthesis(ID);
    await pollFor("the old run to start", async () => (runs.length === 1 ? true : undefined));
    await deleteCase(); // the old run is still hung on its model call
    await create();
    analysis.scheduleSynthesis(ID);
    await pollFor("the new case's run to start", async () => (runs.length === 2 ? true : undefined));
    runs[0].release(); // the old run ends; its finally must not clear the new run's mark
    await wait(20);
    analysis.scheduleSynthesis(ID); // so this kick waits for the new run instead of racing it
    await wait(60);
    expect(runs).toHaveLength(2);
    runs[1].release();
    await pollFor("the follow-up run", async () => (runs.length === 3 ? true : undefined));
    runs[2].release();
  });
});
