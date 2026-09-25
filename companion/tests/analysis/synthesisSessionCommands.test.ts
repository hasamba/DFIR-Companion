import { describe, it, expect, beforeEach, vi } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { emptyState, type ForensicEvent, type InvestigationState } from "../../src/analysis/stateTypes.js";

// #1594 acceptance, through synthesize(): the model names only the loud step (credential dumping);
// each of the five quiet INC-2026-005 steps (sanitized) must end up named in a finding or listed in
// the session note of one.

let stateStore: StateStore;
let prompts: string[];

const at = (hms: string): string => `2026-05-11T${hms}Z`;

function ev(id: string, over: Partial<ForensicEvent>): ForensicEvent {
  return {
    id,
    timestamp: at("09:00:00"),
    description: `row ${id}`,
    severity: "Low",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset: "WS01",
    ...over,
  };
}

const QUIET: Record<string, Partial<ForensicEvent>> = {
  netsh: {
    timestamp: at("08:58:09"),
    severity: "Medium",
    processName: "netsh.exe",
    commandLine: 'netsh advfirewall firewall set rule group="Network Discovery" new enable=Yes',
  },
  subst: { timestamp: at("08:58:31"), processName: "subst.exe", commandLine: "subst E: C:\\e" },
  startcmd: {
    timestamp: at("08:58:31"),
    severity: "High",
    processName: "powershell.exe",
    path: "c:\\e\\!start.cmd",
    description: "Hayabusa: File Created (EID 11 Sysmon) — TgtFile=C:\\e\\!start.cmd",
  },
  netview: { timestamp: at("09:04:22"), processName: "net.exe", commandLine: "net view /all" },
  tasklist: { timestamp: at("09:04:39"), processName: "tasklist.exe", commandLine: "tasklist /v" },
};
const NAMES: Record<string, string> = {
  netsh: "netsh advfirewall firewall",
  subst: "subst E: C:\\e",
  startcmd: "!start.cmd",
  netview: "net view /all",
  tasklist: "tasklist /v",
};

function pipeline(): AnalysisPipeline {
  const analyze = vi.fn(async (req: { userPrompt?: string }) => {
    prompts.push(req.userPrompt ?? "");
    return {
      rawText: JSON.stringify({
        findings: [
          {
            id: "f1",
            severity: "Critical",
            title: "Credential dumping with Mimikatz",
            description: "mimikatz sekurlsa::logonpasswords ran on WS01.",
            relatedIocs: [],
            mitreTechniques: ["T1003.001"],
            relatedEventIds: ["e-mimi"],
          },
        ],
        iocs: [],
        mitreTechniques: [],
        threadsOpened: [],
        threadsClosed: [],
        timelineNote: "",
        summary: "",
      }),
    };
  });
  return new AnalysisPipeline({
    stateStore,
    synthesisProvider: { name: "fake", analyze } as never,
    retries: 0,
    imageLoader: async () => ({ data: Buffer.from(""), mediaType: "image/png" }) as never,
  });
}

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-session-cmds-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  stateStore = new StateStore(cases);
  prompts = [];
  const s = emptyState("c1");
  s.forensicTimeline.push(
    ev("e-mimi", {
      severity: "Critical",
      processName: "mimikatz.exe",
      commandLine: "mimikatz.exe privilege::debug sekurlsa::logonpasswords exit",
    }),
    ...Object.entries(QUIET).map(([k, over]) => ev(`e-${k}`, over)),
  );
  await stateStore.save(s);
});

function coveredBy(state: InvestigationState, key: string): boolean {
  const name = NAMES[key].toLowerCase();
  return state.findings.some(
    (f) =>
      `${f.title} ${f.description}`.toLowerCase().includes(name) ||
      (f.sessionCommands ?? []).some((c) => c.eventId === `e-${key}`),
  );
}

describe("synthesis notes quiet session commands (#1594)", () => {
  it("each of the five quiet commands is named in a finding or in its session note", async () => {
    await pipeline().synthesize("c1", { force: true });
    const saved = await stateStore.load("c1");
    for (const key of Object.keys(QUIET)) expect(coveredBy(saved, key), key).toBe(true);
    const f1 = saved.findings.find((f) => f.id === "f1");
    // The later two sit nearest the Mimikatz row; netsh and subst sit nearest the High !start.cmd
    // row, whose deterministic backfill finding is the closer anchor.
    expect(f1?.sessionCommands?.map((c) => c.eventId)).toEqual(["e-netview", "e-tasklist"]);
    const noted = saved.findings.flatMap((f) => (f.sessionCommands ?? []).map((c) => c.eventId));
    expect(noted).toEqual(expect.arrayContaining(["e-netsh", "e-subst"]));
    // Not evidence the finding claims: its citations are the model's.
    expect(f1?.relatedEventIds).toEqual(["e-mimi"]);
  });

  it("a dry run (second-opinion model B) carries no note", async () => {
    const out = await pipeline().synthesize("c1", { force: true, dryRun: true });
    expect(out.findings.every((f) => f.sessionCommands === undefined)).toBe(true);
  });
});
