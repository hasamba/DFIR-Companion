// #2907: an AI Agent Forensics run is collected once every endpoint's collection has ended, not at a
// fixed 30 minutes, and the whole-disk Sigma rules that used up the two-hour limit are opt-in.
import { describe, expect, it, vi } from "vitest";
import { loadAiAgentRuleSet } from "../../../src/analysis/aiAgentRuleSet.js";
import type { VeloHuntJob } from "../../../src/analysis/veloHuntStore.js";
import {
  AI_AGENT_COLLECT_GRACE_SECONDS,
  aiAgentCollectDeadline,
  aiAgentRunReadyToCollect,
} from "../../../src/integrations/velociraptor/aiAgentCollectReady.js";
import {
  buildAiAgentArtifact,
  sigmaWalksWholeDisk,
  WHOLE_DISK_SCOPE,
} from "../../../src/integrations/velociraptor/aiAgentArtifact.js";
import { AI_AGENT_COLLECTION_TIMEOUT_SECONDS } from "../../../src/integrations/velociraptor/aiAgentLaunch.js";
import {
  aiAgentFlowsAllEnded,
  describeAiAgentRunStatus,
  parseHuntFlows,
} from "../../../src/integrations/velociraptor/aiAgentRunStatus.js";
import { pollHuntStatusOnce } from "../../../src/integrations/velociraptor/huntStatusPoller.js";

const LAUNCH = "2026-01-10T08:00:00.000Z";
const T0 = Date.parse(LAUNCH);
const job = (over: Partial<VeloHuntJob> = {}): VeloHuntJob => ({
  bundleId: "ai-agent",
  bundleName: "AI Agent Forensics",
  artifacts: [],
  huntId: "H.TEST1",
  launchedAt: LAUNCH,
  waitMinutes: 30,
  collectAt: LAUNCH,
  status: "running",
  aiAgentRunId: "run-1",
  aiAgentEndpointCount: 2,
  ...over,
});
const clientWith = (rows: unknown[]) => ({ runProgram: vi.fn(async () => ({ rows, reason: "" })) });
const row = (id: string, state: string) => ({ ClientId: id, State: state, Rows: 1, Status: "" });

describe("aiAgentRunReadyToCollect", () => {
  it("waits while an endpoint is still collecting", async () => {
    const c = clientWith([row("C.a1", "FINISHED"), row("C.b2", "IN_PROGRESS")]);
    expect(await aiAgentRunReadyToCollect(c, job(), T0 + 3_600_000)).toBe(false);
  });

  it("waits while an added endpoint has no collection yet", async () => {
    const c = clientWith([row("C.a1", "FINISHED")]);
    expect(await aiAgentRunReadyToCollect(c, job(), T0 + 3_600_000)).toBe(false);
  });

  it("collects once every endpoint's collection has ended, errors included", async () => {
    const c = clientWith([row("C.a1", "FINISHED"), row("C.b2", "ERROR")]);
    expect(await aiAgentRunReadyToCollect(c, job(), T0 + 600_000)).toBe(true);
  });

  it("never collects early on a failed or unreadable answer", async () => {
    const failing = { runProgram: vi.fn(async () => Promise.reject(new Error("down"))) };
    expect(await aiAgentRunReadyToCollect(failing, job(), T0 + 600_000)).toBe(false);
    expect(await aiAgentRunReadyToCollect(clientWith([{ bad: 1 }]), job(), T0 + 600_000)).toBe(false);
    expect(await aiAgentRunReadyToCollect(clientWith([]), job(), T0 + 600_000)).toBe(false);
  });

  it("a run saved without an endpoint count waits for the deadline, never guessing one endpoint", async () => {
    const c = clientWith([row("C.a1", "FINISHED")]);
    const legacy = job({ aiAgentEndpointCount: undefined });
    expect(await aiAgentRunReadyToCollect(c, legacy, T0 + 3_600_000)).toBe(false);
    expect(c.runProgram).not.toHaveBeenCalled();
    expect(await aiAgentRunReadyToCollect(c, legacy, aiAgentCollectDeadline(LAUNCH))).toBe(true);
  });

  it("collects anyway once the per-endpoint limit plus the grace period has passed", async () => {
    const deadline = aiAgentCollectDeadline(LAUNCH);
    expect(deadline - T0).toBe((AI_AGENT_COLLECTION_TIMEOUT_SECONDS + AI_AGENT_COLLECT_GRACE_SECONDS) * 1000);
    const c = clientWith([row("C.a1", "IN_PROGRESS")]);
    expect(await aiAgentRunReadyToCollect(c, job(), deadline)).toBe(true);
    expect(c.runProgram).not.toHaveBeenCalled();
  });
});

describe("the status poll collects a paused AI-agent hunt when its endpoints are done", () => {
  const paused = async () => ({ state: "PAUSED" });

  it("collects when ready, keeps polling when not", async () => {
    const ready = await pollHuntStatusOnce(job(), { getState: paused, aiAgentReady: async () => true });
    expect(ready.action).toBe("collect");
    const notYet = await pollHuntStatusOnce(job(), { getState: paused, aiAgentReady: async () => false });
    expect(notYet.action).toBe("reschedule");
  });

  it("never asks for a hunt that is not an AI-agent run", async () => {
    const aiAgentReady = vi.fn(async () => true);
    const out = await pollHuntStatusOnce(job({ aiAgentRunId: undefined }), {
      getState: paused,
      aiAgentReady,
    });
    expect(out.action).toBe("reschedule");
    expect(aiAgentReady).not.toHaveBeenCalled();
  });
});

describe("run status: collections that ran to the time limit", () => {
  const us = (s: number) => T0 * 1000 + s * 1e6;

  it("reads how long each collection ran from its create and last-active times (microseconds)", () => {
    const [f] = parseHuntFlows([
      { ClientId: "C.a1", State: "FINISHED", Created: us(0), LastActive: us(7200) },
    ])!;
    expect(f.ranSeconds).toBe(7200);
  });

  it("says a collection that ended at the limit may be partial, without claiming why it ended", () => {
    const flows = parseHuntFlows([
      { ClientId: "C.a1", State: "FINISHED", Created: us(0), LastActive: us(7199) },
      { ClientId: "C.b2", State: "FINISHED", Created: us(0), LastActive: us(600) },
    ]);
    const s = describeAiAgentRunStatus("PAUSED", flows, 2);
    expect(s.state).toBe("finished");
    expect(s.summary).toBe(
      "Finished — 2 of 2 endpoint(s) done; 1 ran to the 2-hour time limit, so its results may be partial",
    );
  });

  it("all-ended needs a collection for every endpoint", () => {
    const done = parseHuntFlows([row("C.a1", "FINISHED")]);
    expect(aiAgentFlowsAllEnded(done, 1)).toBe(true);
    expect(aiAgentFlowsAllEnded(done, 2)).toBe(false);
    expect(aiAgentFlowsAllEnded(undefined, 1)).toBe(false);
  });
});

describe("whole-disk Sigma rules are opt-in", () => {
  const set = loadAiAgentRuleSet();
  const wholeDisk = set.sigma.filter((d) => d.mode === "compiled" && sigmaWalksWholeDisk(d.vqlBlocks));
  const allYaml = (b: ReturnType<typeof buildAiAgentArtifact>) => b.artifacts.map((a) => a.yaml).join("\n");

  it("the bundled pack has such rules, and the detector reads only the glob() argument", () => {
    expect(wholeDisk.length).toBeGreaterThan(0);
    expect(sigmaWalksWholeDisk(['glob(globs=["C:/**/x.dll"])'])).toBe(true);
    expect(sigmaWalksWholeDisk(['glob(globs=["C:/Users/*/x"]) WHERE Name =~ "C:/**"'])).toBe(false);
  });

  it("by default they are left out and reported as not run", () => {
    const b = buildAiAgentArtifact(set);
    const yaml = allYaml(b);
    expect(yaml).toContain("- name: SigmaSkipped");
    expect(yaml).not.toContain('"C:/**/');
    expect(b.scopes).not.toContain(WHOLE_DISK_SCOPE);
  });

  it("ticking the whole-disk scope runs them, adds no YARA scope, and names a different artifact", () => {
    const def = buildAiAgentArtifact(set);
    const b = buildAiAgentArtifact(set, { scopes: [...def.scopes, WHOLE_DISK_SCOPE] });
    const yaml = allYaml(b);
    expect(yaml).not.toContain("- name: SigmaSkipped");
    expect(yaml).toContain('"C:/**/');
    expect(b.name).not.toBe(def.name);
    expect(set.scopes.find((s) => s.id === WHOLE_DISK_SCOPE)).toMatchObject({ default: false, globs: [] });
  });
});
