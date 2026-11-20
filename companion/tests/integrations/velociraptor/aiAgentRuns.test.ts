// AI Agent Forensics (#2690): run lifecycle — sweep case, case mode, refresh, Add to case, retention.
// Real case storage on a temp folder; the Velociraptor client is a mock.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../../src/storage/caseStore.js";
import { VeloHuntStore } from "../../../src/analysis/veloHuntStore.js";
import { AiControlStore } from "../../../src/analysis/aiControl.js";
import { AiAgentRunStore } from "../../../src/analysis/aiAgentRunStore.js";
import {
  addSweepToCase,
  enforceSweepRetention,
  listSweeps,
  refreshAiAgentRun,
  startAiAgentRun,
  type AiAgentForensicsDeps,
} from "../../../src/integrations/velociraptor/aiAgentRuns.js";
import { isAnalystCase, SWEEP_RETENTION } from "../../../src/storage/sweepCase.js";
import { withSilentEndpoints } from "../../../src/integrations/velociraptor/aiAgentRuns.js";
import { buildAiAgentReport } from "../../../src/analysis/aiAgentReport.js";
import { loadAiAgentRuleSet } from "../../../src/analysis/aiAgentRuleSet.js";
import type { VelociraptorClient } from "../../../src/integrations/velociraptor/velociraptorApi.js";
import type { ServerSetStore } from "../../../src/integrations/serverSets/serverSetStore.js";

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
      forSet: () => ({ ok: true, servers: { setId: "set-1", setName: "Lab", velociraptor: velo } }),
      forDefault: () => ({ ok: true, servers: { setId: "set-1", setName: "Lab", velociraptor: velo } }),
    } as unknown as AiAgentForensicsDeps["serverClients"],
    serverSetStore: sets,
    veloHuntStore: new VeloHuntStore(store),
    runStore: new AiAgentRunStore(store),
    disableAi: (c: string) => new AiControlStore(store).save(c, { enabled: false, lastAnalyzedSeq: 0 }),
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

  it("leaves no hidden case behind when the launch fails", async () => {
    const velo = fakeVelo();
    const failing = {
      ...velo,
      runProgram: async (p: string) =>
        p.includes("hunt(")
          ? { rows: [], reason: "PermissionDenied" }
          : (velo as unknown as { runProgram(p: string): Promise<unknown> }).runProgram(p),
    } as unknown as VelociraptorClient;
    const servers = { ok: true, servers: { setId: "set-1", setName: "Lab", velociraptor: failing } };
    const deps = makeDeps({
      serverClients: {
        forCase: () => servers,
        forSet: () => servers,
        forDefault: () => servers,
      } as unknown as AiAgentForensicsDeps["serverClients"],
    });
    await expect(startAiAgentRun(deps, { clientIds: ["C.w1"] })).rejects.toThrow(/START_HUNT/);
    expect(await store.listCases()).toEqual([]);
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

  it("refuses a client id that is not enrolled on the case's Velociraptor server (#2725)", async () => {
    await store.createCase({ caseId: "case-2", name: "c", investigator: "x", aiProvider: null });
    const deps = makeDeps();
    await expect(
      startAiAgentRun(deps, { caseId: "case-2", clientIds: ["C.w1", "C.other9"] }),
    ).rejects.toThrow(/not enrolled on this case's Velociraptor server: C\.other9/);
    expect(programs.some((p) => p.includes("hunt("))).toBe(false); // nothing launched
  });

  it("refreshes the report and the manifest without reading upload contents", async () => {
    const deps = makeDeps();
    const { caseId, run } = await startAiAgentRun(deps, { clientIds: ["C.w1"] });
    const updated = await refreshAiAgentRun(deps, caseId, run.runId);
    expect(deps.startVeloHuntCollect).toHaveBeenCalledWith(caseId, "H.AI1"); // the timeline catches up too
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

describe("AI Agent Forensics: an endpoint with no rows yet", () => {
  it("is listed as 'no results yet', never dropped from the report", () => {
    const report = {
      builtAt: "",
      ruleSetVersion: "v",
      endpoints: [
        {
          host: "dev-ws-014.corp.example",
          tools: [],
          mcpServers: [],
          credentialStores: 0,
          hits: 0,
          coverage: [],
        },
      ],
      hits: [],
      notRun: [],
      unreadableRows: 0,
      provisionalGrades: true as const,
    };
    const out = withSilentEndpoints(report, [
      { clientId: "C.w1", hostname: "DEV-WS-014" },
      { clientId: "C.w2", hostname: "BUILD-01" },
    ]);
    expect(out.endpoints.map((e) => e.host)).toEqual(["dev-ws-014.corp.example", "BUILD-01"]);
    expect(out.endpoints[1].coverage[0].status).toBe("no results yet");
  });

  it("reconciles silent endpoints by client id, so a silent twin of a reporting host name is listed (Codex review)", () => {
    const report = buildAiAgentReport(
      [
        {
          DFIRCompanionAIAgent: 1,
          Hostname: "WS-01",
          ClientId: "C.aaa111",
          Kind: "inventory",
          Tool: "Cursor",
        },
      ],
      loadAiAgentRuleSet(),
    );
    expect(report.endpoints.map((e) => e.host)).toEqual(["WS-01"]);
    const out = withSilentEndpoints(report, [
      { clientId: "C.aaa111", hostname: "WS-01" },
      { clientId: "C.bbb222", hostname: "WS-01" },
    ]);
    expect(out.endpoints.map((e) => [e.host, e.clientId])).toEqual([
      ["WS-01 (C.aaa111)", "C.aaa111"],
      ["WS-01 (C.bbb222)", "C.bbb222"],
    ]);
    expect(out.endpoints[1].coverage[0].status).toBe("no results yet");
  });
});

describe("AI Agent Forensics: Add to case files the complete result set", () => {
  const many = (n: number) =>
    Array.from({ length: n }, (_, i) => ({ ...hitRow, FilePath: `C:\\Users\\dev\\proj${i}\\CLAUDE.md` }));

  function depsReading(read: { rows: unknown[]; truncated: boolean }) {
    const velo = fakeVelo();
    const reading = {
      ...velo,
      huntArtifactRows: async (_h: string, artifact: string) =>
        artifact.includes(".More")
          ? { rows: [], total: 0, truncated: false } // the extra Sigma artifacts returned nothing
          : { ...read, total: read.rows.length },
    } as unknown as VelociraptorClient;
    const servers = { ok: true, servers: { setId: "set-1", setName: "Lab", velociraptor: reading } };
    return makeDeps({
      serverClients: {
        forCase: () => servers,
        forSet: () => servers,
        forDefault: () => servers,
      } as unknown as AiAgentForensicsDeps["serverClients"],
    });
  }

  it("files every row of a large sweep, in bounded batches", async () => {
    await store.createCase({ caseId: "case-1", name: "c", investigator: "x", aiProvider: null });
    const deps = depsReading({ rows: many(25_001), truncated: false });
    const { caseId, run } = await startAiAgentRun(deps, { clientIds: ["C.w1"] });
    const refreshed = await refreshAiAgentRun(deps, caseId, run.runId);
    expect(refreshed.rowCount).toBe(25_001);
    expect(refreshed.rows).toBeUndefined(); // the rows live in their own file, not the run record
    await addSweepToCase(deps, caseId, run.runId, "case-1");
    const filed = deps.ingested.map(
      (x) => Object.values(JSON.parse(x.slice("case-1:".length)) as Record<string, unknown[]>)[0].length,
    );
    expect(filed.reduce((a, b) => a + b, 0)).toBe(25_001);
    expect(Math.max(...filed)).toBeLessThanOrEqual(10_000);
  });

  it("refuses to file a sweep whose results were not read in full, and says how much is missing", async () => {
    await store.createCase({ caseId: "case-1", name: "c", investigator: "x", aiProvider: null });
    const deps = depsReading({ rows: many(500), truncated: true });
    const { caseId, run } = await startAiAgentRun(deps, { clientIds: ["C.w1"] });
    const refreshed = await refreshAiAgentRun(deps, caseId, run.runId);
    expect(refreshed.readIncomplete?.[0]).toMatchObject({ rowsRead: 500 });
    await expect(addSweepToCase(deps, caseId, run.runId, "case-1")).rejects.toThrow(
      /not read in full.*500 rows were read.*at least one more/s,
    );
    expect(deps.ingested).toEqual([]);
  });
});

// #2722: the activity log gets an entry for a run and for Add to case — counts and ids only.
describe("AI Agent Forensics: activity entries", () => {
  it("records a run in its case, and Add to case in the target and the sweep", async () => {
    await store.createCase({ caseId: "case-1", name: "c", investigator: "x", aiProvider: null });
    const entries: { caseId: string; action: string; detail: string }[] = [];
    const deps = makeDeps({ onActivity: (caseId, e) => entries.push({ caseId, ...e }) });
    await startAiAgentRun(deps, { caseId: "case-1", clientIds: ["C.w1"] });
    expect(entries).toEqual([
      {
        caseId: "case-1",
        action: "ai-agent-run",
        detail: expect.stringMatching(
          /^started AI Agent Forensics on 1 endpoint\(s\) \(hunt H\.AI1, rules .+, scopes agent-home, project-instructions, mcp-installs\)$/,
        ),
      },
    ]);
    entries.length = 0;
    const { caseId: sweep, run } = await startAiAgentRun(deps, { clientIds: ["C.w1"] });
    expect(entries.map((e) => [e.caseId, e.action])).toEqual([[sweep, "ai-agent-run"]]);
    await refreshAiAgentRun(deps, sweep, run.runId);
    entries.length = 0;
    await addSweepToCase(deps, sweep, run.runId, "case-1");
    expect(entries).toEqual([
      {
        caseId: "case-1",
        action: "ai-agent-add-to-case",
        detail: `added AI Agent Forensics sweep ${sweep} (hunt H.AI1): +1 event(s), +1 IOC(s)`,
      },
      {
        caseId: sweep,
        action: "ai-agent-add-to-case",
        detail: "filed into case case-1: +1 event(s), +1 IOC(s)",
      },
    ]);
    expect(JSON.stringify(entries)).not.toContain("do not tell the user"); // never the matched text
  });

  it("joins the refreshed report to the uncapped manifest, so an agent-home hit gets its preserved hash", async () => {
    const A = "a".repeat(64);
    const velo = fakeVelo();
    const reading = {
      ...velo,
      huntArtifactRows: async () => ({
        rows: [
          {
            ...hitRow,
            ClientId: "C.w1",
            FileSha256: A,
            Preserved: "kept by the AICodingAgents preservation collection",
          },
        ],
        total: 1,
        truncated: false,
      }),
      runProgram: async (p: string) =>
        p.includes("uploads(")
          ? {
              rows: [
                {
                  ClientId: "C.w1",
                  FlowId: "F.1",
                  Path: "/uploads/auto/C%3A/Users/dev/.claude/CLAUDE.md",
                  Size: 5,
                  SHA256: A,
                },
              ],
              reason: "",
            }
          : (velo as unknown as { runProgram(p: string): Promise<unknown> }).runProgram(p),
    } as unknown as VelociraptorClient;
    const servers = { ok: true, servers: { setId: "set-1", setName: "Lab", velociraptor: reading } };
    const deps = makeDeps({
      serverClients: {
        forCase: () => servers,
        forSet: () => servers,
        forDefault: () => servers,
      } as unknown as AiAgentForensicsDeps["serverClients"],
    });
    const { caseId, run } = await startAiAgentRun(deps, { clientIds: ["C.w1"] });
    const updated = await refreshAiAgentRun(deps, caseId, run.runId);
    expect(updated.report?.hits[0]).toMatchObject({ preservedSha256: A, hashCheck: "same" });
  });
  it("keeps the totals of a manifest read that logged an error, but never joins hashes to it", async () => {
    const A = "a".repeat(64);
    const velo = fakeVelo();
    const reading = {
      ...velo,
      huntArtifactRows: async () => ({
        rows: [
          {
            ...hitRow,
            ClientId: "C.w1",
            FileSha256: A,
            Preserved: "kept by the AICodingAgents preservation collection",
          },
        ],
        total: 1,
        truncated: false,
      }),
      runProgram: async (p: string) =>
        p.includes("uploads(")
          ? {
              rows: [
                {
                  ClientId: "C.w1",
                  FlowId: "F.1",
                  Path: "/uploads/auto/C%3A/Users/dev/.claude/CLAUDE.md",
                  Size: 5,
                  SHA256: A,
                },
              ],
              reason: "PermissionDenied: partial listing",
            }
          : (velo as unknown as { runProgram(p: string): Promise<unknown> }).runProgram(p),
    } as unknown as VelociraptorClient;
    const servers = { ok: true, servers: { setId: "set-1", setName: "Lab", velociraptor: reading } };
    const deps = makeDeps({
      serverClients: {
        forCase: () => servers,
        forSet: () => servers,
        forDefault: () => servers,
      } as unknown as AiAgentForensicsDeps["serverClients"],
    });
    const { caseId, run } = await startAiAgentRun(deps, { clientIds: ["C.w1"] });
    const updated = await refreshAiAgentRun(deps, caseId, run.runId);
    expect(updated.report?.hits[0]).toMatchObject({ preservedSha256: "", hashCheck: "not recorded" });
    expect(updated.manifest?.total).toBe(1);
    expect(updated.reportError).toContain("upload manifest: PermissionDenied: partial listing");
  });
});
