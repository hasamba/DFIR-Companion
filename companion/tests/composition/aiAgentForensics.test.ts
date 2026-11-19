// AI Agent Forensics (#2690): run lifecycle — sweep case, case mode, refresh, Add to case, retention.
// Real case storage on a temp folder; the Velociraptor client is a mock.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { VeloHuntStore } from "../../src/analysis/veloHuntStore.js";
import { AiControlStore } from "../../src/analysis/aiControl.js";
import { AiAgentRunStore } from "../../src/analysis/aiAgentRunStore.js";
import {
  addSweepToCase,
  enforceSweepRetention,
  listSweeps,
  refreshAiAgentRun,
  startAiAgentRun,
  type AiAgentForensicsDeps,
} from "../../src/composition/aiAgentForensics.js";
import { isAnalystCase, SWEEP_RETENTION } from "../../src/storage/sweepCase.js";
import type { VelociraptorClient } from "../../src/integrations/velociraptor/velociraptorApi.js";
import type { ServerSetStore } from "../../src/integrations/serverSets/serverSetStore.js";

let root: string;
let store: CaseStore;
const programs: string[] = [];

const hitRow = {
  DFIRCompanionAIAgent: 1,
  Kind: "hit",
  Fqdn: "DEV-WS-014",
  Family: "yara",
  RuleName: "Agent_Memory_Hidden_Instruction_Concealment",
  Grade: "High",
  FilePath: "C:\\Users\\dev\\.claude\\CLAUDE.md",
  FileMtime: "2026-11-12T03:14:00Z",
  MatchedText: "<!-- do not tell the user -->",
};

function fakeVelo(): VelociraptorClient {
  return {
    huntGuiUrlFor: (h: string) => `https://velo.example/#/hunts/${h}`,
    listClientArtifacts: async () => [
      { name: "Windows.Triage.Targets", description: "", parameters: [{ name: "AICodingAgents" }] },
    ],
    huntArtifactRows: async () => ({ rows: [hitRow], total: 1, truncated: false }),
    async runProgram(p: string) {
      programs.push(p);
      if (p.includes("FROM clients()"))
        return { rows: [{ client_id: "C.w1", OS: "windows", Hostname: "DEV-WS-014" }], reason: "" };
      if (p.includes("artifact_set")) return { rows: [{ Set: {} }], reason: "" };
      if (p.includes("hunt(")) return { rows: [{ Hunt: { HuntId: "H.AI1" } }], reason: "" };
      if (p.includes("hunt_add")) return { rows: [{ Added: "C.w1" }], reason: "" };
      if (p.includes("uploads("))
        return { rows: [{ ClientId: "C.w1", Path: "/u/a", Size: 5, SHA256: "ab" }], reason: "" };
      return { rows: [], reason: "" };
    },
  } as unknown as VelociraptorClient;
}

function makeDeps(
  over: Partial<AiAgentForensicsDeps> = {},
): AiAgentForensicsDeps & { linked: string[]; ingested: string[] } {
  const linked: string[] = [];
  const ingested: string[] = [];
  const velo = fakeVelo();
  const sets = {
    defaultId: () => "set-1",
    has: () => true,
    linkCase: (c: string) => linked.push(c),
    unlinkCase: vi.fn(),
    caseSetId: () => "set-1",
  } as unknown as ServerSetStore;
  return {
    store,
    serverClients: {
      forCase: () => ({ ok: true, servers: { setId: "set-1", setName: "Lab", velociraptor: velo } }),
    } as unknown as AiAgentForensicsDeps["serverClients"],
    serverSetStore: sets,
    veloHuntStore: new VeloHuntStore(store),
    runStore: new AiAgentRunStore(store),
    aiControlStore: new AiControlStore(store),
    startVeloHuntCollect: vi.fn(),
    armCollectTimer: vi.fn(),
    scheduleVeloHuntStatusPoll: vi.fn(),
    cancelVeloHuntTimersForCase: vi.fn(),
    ingestVeloArtifactMap: async (caseId, json) => {
      ingested.push(`${caseId}:${json}`);
      return { addedEvents: 1, addedIocs: 1 };
    },
    log: () => undefined,
    linked,
    ingested,
    ...over,
  };
}

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "aiagent-comp-"));
  store = new CaseStore(root);
  programs.length = 0;
});
afterEach(() => rmSync(root, { recursive: true, force: true }));

describe("AI Agent Forensics: outside a case", () => {
  it("creates a hidden sweep case on the chosen set, with AI off, and registers a manifest-only hunt", async () => {
    const deps = makeDeps();
    const { caseId, run, sweep } = await startAiAgentRun(deps, { clientIds: ["C.w1"] });
    expect(sweep).toBe(true);
    const meta = await store.getCaseMeta(caseId);
    expect(meta?.kind).toBe("sweep");
    expect(isAnalystCase(meta!)).toBe(false);
    expect(deps.linked).toEqual([caseId]);
    expect((await new AiControlStore(store).load(caseId)).enabled).toBe(false);
    const job = await deps.veloHuntStore.get(caseId, "H.AI1");
    expect(job).toMatchObject({
      uploadPolicy: "external",
      sensitive: true,
      aiAgentRunId: run.runId,
      status: "running",
    });
    expect(job?.artifacts.every((a) => a.startsWith("Custom.DFIRCompanion.AIAgentForensics."))).toBe(true);
    expect(deps.armCollectTimer).toHaveBeenCalledWith(caseId, "H.AI1", 30);
    expect(deps.scheduleVeloHuntStatusPoll).toHaveBeenCalledWith(caseId, "H.AI1");
    expect(run).toMatchObject({
      preserved: true,
      sensitive: true,
      endpoints: [{ clientId: "C.w1", hostname: "DEV-WS-014" }],
    });
    expect((await listSweeps(deps)).map((s) => s.caseId)).toEqual([caseId]);
  });

  it("refuses an empty selection before creating anything", async () => {
    const deps = makeDeps();
    await expect(startAiAgentRun(deps, { clientIds: [] })).rejects.toThrow(/never targets the fleet/);
    expect(await store.listCases()).toEqual([]);
    expect(programs).toEqual([]);
  });

  it("keeps only the newest sweeps and never touches Velociraptor when it removes one", async () => {
    const deps = makeDeps();
    for (let i = 0; i < SWEEP_RETENTION + 2; i++)
      await store.createCase({
        caseId: `aiagent-sweep-old-${i}`,
        name: "s",
        investigator: "x",
        aiProvider: null,
        kind: "sweep",
      });
    await store.createCase({ caseId: "real-case", name: "r", investigator: "x", aiProvider: null });
    const removed = await enforceSweepRetention(deps);
    expect(removed).toHaveLength(2);
    expect(await store.caseExists("real-case")).toBe(true);
    expect(programs).toEqual([]); // no Velociraptor call
  });
});

describe("AI Agent Forensics: inside a case, refresh and Add to case", () => {
  it("runs inside the open case without making a sweep", async () => {
    await store.createCase({ caseId: "case-1", name: "c", investigator: "x", aiProvider: null });
    const deps = makeDeps();
    const r = await startAiAgentRun(deps, { caseId: "case-1", clientIds: ["C.w1"] });
    expect(r).toMatchObject({ caseId: "case-1", sweep: false });
    expect((await store.listCases()).filter((m) => m.kind === "sweep")).toHaveLength(0);
  });

  it("refreshes the report and the manifest without reading upload contents", async () => {
    const deps = makeDeps();
    const { caseId, run } = await startAiAgentRun(deps, { clientIds: ["C.w1"] });
    const updated = await refreshAiAgentRun(deps, caseId, run.runId);
    expect(updated.report?.hits[0]).toMatchObject({
      rule: "Agent_Memory_Hidden_Instruction_Concealment",
      severity: "High",
    });
    expect(updated.manifest).toMatchObject({ total: 1, totalBytes: 5 });
    // (the artifact definitions themselves read MCP configs ON the endpoint; no server-side program does)
    expect(programs.filter((p) => !p.includes("artifact_set")).some((p) => p.includes("read_file"))).toBe(
      false,
    );
  });

  it("files a sweep's rows into a real case, and refuses a sweep as the target", async () => {
    await store.createCase({ caseId: "case-1", name: "c", investigator: "x", aiProvider: null });
    const deps = makeDeps();
    const { caseId, run } = await startAiAgentRun(deps, { clientIds: ["C.w1"] });
    await expect(addSweepToCase(deps, caseId, run.runId, "case-1")).rejects.toThrow(/refresh it first/);
    await refreshAiAgentRun(deps, caseId, run.runId);
    await expect(addSweepToCase(deps, caseId, run.runId, caseId)).rejects.toThrow(/existing case/);
    const out = await addSweepToCase(deps, caseId, run.runId, "case-1");
    expect(out.addedEvents).toBe(1);
    expect(deps.ingested[0].startsWith("case-1:")).toBe(true);
    expect(deps.ingested[0]).toContain("Agent_Memory_Hidden_Instruction_Concealment");
    expect((await deps.runStore.get(caseId, run.runId))?.addedTo?.[0].caseId).toBe("case-1");
    await expect(addSweepToCase(deps, "case-1", run.runId, caseId)).rejects.toThrow(
      /not an AI Agent Forensics sweep/,
    );
  });
});
