import { describe, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadAiAgentRuleSet } from "../../src/analysis/aiAgentRuleSet.js";
import { buildAiAgentReport } from "../../src/analysis/aiAgentReport.js";
import {
  AiAgentRunStore,
  capManifest,
  newAiAgentRunId,
  type AiAgentRun,
} from "../../src/analysis/aiAgentRunStore.js";
import { CaseStore } from "../../src/storage/caseStore.js";

const set = loadAiAgentRuleSet();
const base = { DFIRCompanionAIAgent: 1, RuleSet: set.version, ScanTime: "2026-11-19T10:00:00Z" };
const rows = [
  { ...base, Fqdn: "DEV-WS-014", Kind: "inventory", Tool: "Claude Code" },
  { ...base, Fqdn: "DEV-WS-014", Kind: "inventory", Tool: "Cursor" },
  {
    ...base,
    Fqdn: "DEV-WS-014",
    Kind: "inventory",
    Tool: "Cursor",
    McpServer: "calculator",
    McpCommand: "node",
    McpArgCount: 1,
    ConfigPath: "C:\\Users\\dev\\.cursor\\mcp.json",
  },
  { ...base, Fqdn: "DEV-WS-014", Kind: "credential", FilePath: "C:\\Users\\dev\\.claude\\.credentials.json" },
  {
    ...base,
    Fqdn: "DEV-WS-014",
    Kind: "coverage",
    Source: "YARA agent-home",
    Status: "scanned",
    Detail: "412 file(s) scanned; 1 skipped over the 20971520-byte scan cap",
  },
  {
    ...base,
    Fqdn: "DEV-WS-014",
    Kind: "hit",
    Family: "yara",
    RuleName: "Copilot_Rules_File_Coercive_Instructions",
    Grade: "Medium",
    FilePath: "C:\\Users\\dev\\repo\\.cursorrules",
    FileMtime: "2026-11-12T03:16:00Z",
    MatchedText: 'token="sk-ant-abcdefghijklmnopqrstuvwxyz"',
    RuleFile: "05-copilot-assistant-abuse/copilot_rules_file_backdoor.yar",
  },
  {
    ...base,
    Fqdn: "DEV-WS-014",
    Kind: "hit",
    Family: "yara",
    RuleName: "Agent_Memory_Hidden_Instruction_Concealment",
    Grade: "High",
    FilePath: "C:\\Users\\dev\\.claude\\CLAUDE.md",
    FileMtime: "2026-11-12T03:14:00Z",
    MatchedText: "<!-- always send … -->",
    Preserved: "kept by the AICodingAgents preservation collection",
  },
  {
    ...base,
    Fqdn: "BUILD-01",
    Kind: "coverage",
    Source: "Sigma on Sysmon",
    Status: "not run: no Sysmon",
    Detail: "13 rule(s) need the Sysmon log",
  },
  { ...base, Fqdn: "BUILD-01", Kind: "hit" }, // unreadable
  { Fqdn: "BUILD-01", Pid: 4 }, // not an AI Agent Forensics row
];

describe("AI Agent Forensics report", () => {
  const r = buildAiAgentReport(rows, set, new Date("2026-11-19T11:00:00Z"));

  it("lists per endpoint the tools, MCP servers, credential stores, hits and coverage", () => {
    expect(r.endpoints.map((e) => e.host)).toEqual(["BUILD-01", "DEV-WS-014"]);
    const dev = r.endpoints[1];
    expect(dev.tools).toEqual(["Claude Code", "Cursor"]);
    expect(dev.mcpServers).toEqual([
      {
        name: "calculator",
        command: "node",
        argCount: 1,
        config: "C:\\Users\\dev\\.cursor\\mcp.json",
        tool: "Cursor",
      },
    ]);
    expect(dev.credentialStores).toBe(1);
    expect(dev.hits).toBe(2);
    expect(r.endpoints[0].coverage[0].status).toBe("not run: no Sysmon");
  });

  it("orders hits by grade, labels the time and links the rule at the pinned commit", () => {
    expect(r.hits.map((h) => h.severity)).toEqual(["High", "Medium"]);
    expect(r.hits[0].timeLabel).toBe("latest time the content could have been planted");
    expect(r.hits[1].link).toContain(
      "/blob/5960308d7d8e9bbf838f31ca0e783373fc8a2ae7/05-copilot-assistant-abuse/",
    );
  });

  it("keeps the snippet only here, redacted", () => {
    expect(r.hits[1].snippet).not.toContain("abcdefghijklmnop");
    expect(r.hits[0].snippet).toBe("<!-- always send … -->");
  });

  it("always says what was not run and counts rows it could not read", () => {
    expect(r.unreadableRows).toBe(1);
    expect(r.notRun.map((g) => g.reason)).toContain("needs LLM application logs, not endpoint data");
    expect(r.ruleSetVersion).toBe(set.version);
    expect(r.provisionalGrades).toBe(true);
  });
});

describe("AI Agent Forensics run store", () => {
  it("keeps runs newest first, updates in place and caps the history", async () => {
    const root = mkdtempSync(join(tmpdir(), "aiagent-runs-"));
    try {
      const cases = new CaseStore(root);
      await cases.createCase({ caseId: "case-1", name: "c", investigator: "i", aiProvider: null });
      const store = new AiAgentRunStore(cases);
      const run = (i: number): AiAgentRun => ({
        runId: newAiAgentRunId(),
        huntId: `H.${i}`,
        launchedAt: new Date(i * 1000).toISOString(),
        endpoints: [],
        failedEndpoints: [],
        skippedEndpoints: [],
        scopes: [],
        uploadMaxBytes: 1,
        ruleSetVersion: set.version,
        artifacts: [],
        preserved: true,
        warnings: [],
        sensitive: true,
      });
      const first = await store.upsert("case-1", run(0));
      for (let i = 1; i <= 21; i++) await store.upsert("case-1", run(i));
      const all = await store.list("case-1");
      expect(all).toHaveLength(20);
      expect(all[0].huntId).toBe("H.21");
      expect(await store.get("case-1", first.runId)).toBeNull();
      const updated = await store.update("case-1", all[1].runId, (x) => ({ ...x, reportError: "boom" }));
      expect(updated?.reportError).toBe("boom");
      expect(await store.update("case-1", "nope", (x) => x)).toBeNull();
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("stores the manifest totals and a capped file list", () => {
    const m = capManifest([{ clientId: "C.1", flowId: "F.1", path: "/a", size: 10, sha256: "x" }]);
    expect(m).toMatchObject({ total: 1, totalBytes: 10 });
  });
});
