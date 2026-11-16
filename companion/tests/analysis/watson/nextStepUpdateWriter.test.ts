import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeEach, describe, expect, it } from "vitest";
import { proposalSchema } from "../../../src/analysis/ai/watson/proposalSchema.js";
import { WatsonProposalConflict } from "../../../src/analysis/ai/watson/proposalErrors.js";
import type { WatsonNextStepUpdateProposal } from "../../../src/analysis/ai/watson/types.js";
import {
  nextStepUpdateWriter,
  stepChange,
} from "../../../src/analysis/ai/watson/writers/nextStepUpdateWriter.js";
import type { WriterDeps } from "../../../src/analysis/ai/watson/writers/writerTypes.js";
import { StateStore } from "../../../src/analysis/stateStore.js";
import { emptyState, type NextStep } from "../../../src/analysis/stateTypes.js";
import { CaseStore } from "../../../src/storage/caseStore.js";

// Watson marks a next step done (it leaves the list) or changes its priority (user decision of
// 2026-11-16). Apply and undo never overwrite a step someone changed in between.

const CASE = "c1";
const step = (id: string, priority: NextStep["priority"], action: string): NextStep => ({
  id,
  priority,
  action,
  rationale: "why",
  pointer: "WS-FAKE01",
});
const A = step("ns1", "critical", "Collect Sysmon EID 1 on WS-FAKE01");
const B = step("ns2", "high", "Hash the staging folder");
const C = step("ns3", "low", "Pull Defender logs");

let stateStore: StateStore;
let deps: WriterDeps;
let outOfDate = 0;

beforeEach(async () => {
  const cases = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-watson-step-upd-")));
  await cases.createCase({ caseId: CASE, name: "n", investigator: "i", aiProvider: null });
  stateStore = new StateStore(cases);
  await stateStore.save({ ...emptyState(CASE), nextSteps: [A, B, C] });
  outOfDate = 0;
  deps = { stateStore, markConclusionsOutOfDate: async () => void outOfDate++ } as unknown as WriterDeps;
});

const proposal = (before: NextStep, after: NextStep | null, index: number): WatsonNextStepUpdateProposal => ({
  id: "wp-1",
  turnId: "wt-1",
  kind: "next_step_update",
  targetId: before.id,
  before,
  after,
  why: "the collection showed the parent",
  index,
  status: "pending",
});
const steps = async () => (await stateStore.loadOverview(CASE)).nextSteps.map((s) => `${s.id}:${s.priority}`);

describe("next step changes by Watson", () => {
  it("done: the step leaves the list; undo puts it back where it was", async () => {
    const p = proposal(A, null, 0);
    await nextStepUpdateWriter.apply(deps, CASE, p);
    expect(await steps()).toEqual(["ns2:high", "ns3:low"]);
    expect(outOfDate).toBe(1);
    await nextStepUpdateWriter.undo(deps, CASE, p);
    expect(await steps()).toEqual(["ns1:critical", "ns2:high", "ns3:low"]);
  });

  it("priority: the step keeps its place with the new priority; undo restores the old one", async () => {
    const p = proposal(B, { ...B, priority: "low" }, 1);
    await nextStepUpdateWriter.apply(deps, CASE, p);
    expect(await steps()).toEqual(["ns1:critical", "ns2:low", "ns3:low"]);
    await nextStepUpdateWriter.undo(deps, CASE, p);
    expect(await steps()).toEqual(["ns1:critical", "ns2:high", "ns3:low"]);
  });

  it("apply refuses a step that changed or left since Watson proposed it", async () => {
    const st = await stateStore.loadOverview(CASE);
    await stateStore.saveOverview({ ...st, nextSteps: [{ ...A, action: "Edited by the analyst" }, B, C] });
    await expect(nextStepUpdateWriter.apply(deps, CASE, proposal(A, null, 0))).rejects.toBeInstanceOf(
      WatsonProposalConflict,
    );
    await expect(
      nextStepUpdateWriter.apply(deps, CASE, proposal(step("gone", "low", "x"), null, 0)),
    ).rejects.toBeInstanceOf(WatsonProposalConflict);
  });

  it("undo refuses when the step is back in the case, or someone changed its priority again", async () => {
    const done = proposal(A, null, 0);
    await nextStepUpdateWriter.apply(deps, CASE, done);
    const st = await stateStore.loadOverview(CASE);
    await stateStore.saveOverview({ ...st, nextSteps: [A, ...st.nextSteps] }); // synthesis wrote it again
    await expect(nextStepUpdateWriter.undo(deps, CASE, done)).rejects.toBeInstanceOf(WatsonProposalConflict);
    const prio = proposal(B, { ...B, priority: "medium" }, 1);
    await nextStepUpdateWriter.apply(deps, CASE, prio);
    const st2 = await stateStore.loadOverview(CASE);
    await stateStore.saveOverview({
      ...st2,
      nextSteps: st2.nextSteps.map((s) => (s.id === "ns2" ? { ...s, priority: "critical" as const } : s)),
    });
    await expect(nextStepUpdateWriter.undo(deps, CASE, prio)).rejects.toBeInstanceOf(WatsonProposalConflict);
  });

  it("says the change in words, and a stored proposal parses back", () => {
    expect(stepChange(proposal(A, null, 0))).toBe("next step done: Collect Sysmon EID 1 on WS-FAKE01");
    expect(stepChange(proposal(B, { ...B, priority: "low" }, 1))).toBe(
      "next step priority high -> low: Hash the staging folder",
    );
    const parsed = proposalSchema.safeParse(proposal(A, null, 2));
    expect(parsed.success && parsed.data).toMatchObject({ kind: "next_step_update", after: null, index: 2 });
  });
});
