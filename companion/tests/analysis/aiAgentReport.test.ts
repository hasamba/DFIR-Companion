import { describe, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadAiAgentRuleSet } from "../../src/analysis/aiAgentRuleSet.js";
import { buildAiAgentReport } from "../../src/analysis/aiAgentReport.js";
import { AI_AGENT_HASH_CAVEAT, hashCheckLabel } from "../../src/analysis/aiAgentHashCheck.js";
import {
  aiAgentReportCsv,
  aiAgentReportMarkdown,
  aiAgentSigmaCoverageCsv,
} from "../../src/reports/aiAgentReportExport.js";
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

// #2722: scan hash vs preserved-copy hash, per matched file.
describe("AI Agent Forensics report: scan hash and preserved hash", () => {
  const A = "a".repeat(64);
  const B = "b".repeat(64);
  const hitRow = (over: Record<string, unknown>) => ({
    ...base,
    Fqdn: "DEV-WS-014",
    ClientId: "C.w1",
    Kind: "hit",
    Family: "yara",
    RuleName: "R",
    FileSha256: A,
    ...over,
  });
  const manifest = [
    {
      clientId: "C.w1",
      flowId: "F.1",
      path: "/clients/C.w1/collections/F.1/uploads/ntfs/%5C%5C.%5CC%3A/Users/dev/.claude/CLAUDE.md",
      size: 5,
      sha256: A,
    },
    {
      clientId: "C.w1",
      flowId: "F.1",
      path: "/clients/C.w1/collections/F.1/uploads/auto/C%3A/Users/dev/.cursor/mcp.json",
      size: 5,
      sha256: B,
    },
  ];
  const check = (row: Record<string, unknown>, m: typeof manifest | null = manifest) =>
    buildAiAgentReport([row], set, new Date(), { manifest: m }).hits[0];

  it("compares the hash the artifact recorded for its own upload", () => {
    expect(check(hitRow({ PreservedSha256: A, Preserved: "uploaded (5 bytes)" }))).toMatchObject({
      sha256: A,
      preservedSha256: A,
      hashCheck: "same",
    });
    expect(check(hitRow({ PreservedSha256: B, Preserved: "uploaded (5 bytes)" }))).toMatchObject({
      preservedSha256: B,
      hashCheck: "differs",
    });
  });

  it("says not preserved only when the artifact itself said so", () => {
    const over = check(
      hitRow({
        Preserved: "match observed; file not preserved (over the upload cap)",
        FilePath: "C:\\x\\big.md",
      }),
    );
    expect(over).toMatchObject({ preservedSha256: "", hashCheck: "not preserved" });
  });

  it("joins an agent-home hit to the upload manifest by client and path", () => {
    const kept = "kept by the AICodingAgents preservation collection";
    expect(check(hitRow({ Preserved: kept, FilePath: "C:\\Users\\dev\\.claude\\CLAUDE.md" }))).toMatchObject({
      preservedSha256: A,
      hashCheck: "same",
    });
    expect(check(hitRow({ Preserved: kept, FilePath: "C:\\Users\\dev\\.cursor\\mcp.json" }))).toMatchObject({
      preservedSha256: B,
      hashCheck: "differs",
    });
  });

  it("says not recorded — never not preserved — when the manifest is missing, truncated or has no match", () => {
    const kept = { Preserved: "kept by the AICodingAgents preservation collection" };
    const path = { FilePath: "C:\\Users\\dev\\.claude\\CLAUDE.md" };
    expect(check(hitRow({ ...kept, ...path }), null).hashCheck).toBe("not recorded");
    expect(check(hitRow({ ...kept, FilePath: "C:\\Users\\dev\\other.md" })).hashCheck).toBe("not recorded");
    expect(check(hitRow({ ...kept, ...path, ClientId: undefined })).hashCheck).toBe("not recorded");
    // The artifact could not confirm its own upload: that is not proof the file was not kept.
    expect(
      check(hitRow({ Preserved: "match observed; upload result not recorded", ...path }), null).hashCheck,
    ).toBe("not recorded");
    // An older run's row: uploaded, but no hash column and no manifest.
    expect(check(hitRow({ Preserved: "uploaded (5 bytes)", ...path }), null).hashCheck).toBe("not recorded");
  });
});

// #2722 (Codex review): the YARA read, the hash and the upload are three separate reads of the file. A
// file replaced after YARA matched it but before it was hashed gives two equal hashes of the
// replacement, so "same" may only ever claim the file did not change between hashing and preservation.
describe("AI Agent Forensics report: a file replaced between the YARA read and the hashing", () => {
  const REPLACEMENT = "c".repeat(64);
  const replaced = {
    ...base,
    Fqdn: "DEV-WS-014",
    ClientId: "C.w1",
    Kind: "hit",
    Family: "yara",
    RuleName: "Agent_Memory_Hidden_Instruction_Concealment",
    FilePath: "C:\\Users\\dev\\.claude\\CLAUDE.md",
    FileSha256: REPLACEMENT, // hashed after the scan: already the replacement
    PreservedSha256: REPLACEMENT, // the upload: also the replacement
    Preserved: "uploaded (5 bytes)",
  };
  const report = buildAiAgentReport([replaced], set, new Date("2026-11-19T11:00:00Z"));
  const run: AiAgentRun = {
    runId: "aar-x",
    huntId: "H.1",
    launchedAt: "2026-11-19T10:00:00Z",
    endpoints: [],
    failedEndpoints: [],
    skippedEndpoints: [],
    scopes: ["agent-home"],
    uploadMaxBytes: 1,
    ruleSetVersion: set.version,
    artifacts: [],
    preserved: true,
    warnings: [],
    sensitive: true,
    report,
  };

  it("reads 'same', and the label claims only that the file did not change between hashing and preservation", () => {
    expect(report.hits[0].hashCheck).toBe("same");
    expect(hashCheckLabel("same")).toBe("same: unchanged between hashing and preservation");
    expect(hashCheckLabel("differs")).toBe("differs: changed between hashing and preservation");
    expect(hashCheckLabel("not recorded")).toBe("not recorded");
    expect(AI_AGENT_HASH_CAVEAT).toContain("not separately hashed");
    expect(AI_AGENT_HASH_CAVEAT).toContain("not proven");
  });

  it("says so in report.md and report.csv, and never calls the after-scan hash the scan hash", () => {
    const md = aiAgentReportMarkdown(run);
    expect(md).toContain(AI_AGENT_HASH_CAVEAT);
    expect(md).toContain("| File SHA-256 (hashed after the scan) | Preserved SHA-256 | Hash check |");
    expect(md).toContain("same: unchanged between hashing and preservation");
    expect(md).not.toContain("Scan SHA-256");
    const [head, first] = aiAgentReportCsv(run).split("\r\n");
    expect(head).toContain(`"file_sha256_after_scan","preserved_sha256","hash_check","hash_note"`);
    expect(head).not.toContain("scan_sha256");
    expect(first).toContain(`"same: unchanged between hashing and preservation","${AI_AGENT_HASH_CAVEAT}"`);
  });
});

// #2722: per-rule, per-endpoint Sigma coverage, keyed by the rule set.
describe("AI Agent Forensics report: Sigma coverage per rule per endpoint", () => {
  const compiled = set.sigma.find((d) => d.mode === "compiled")!;
  const sysmon = set.sigma.find((d) => d.mode === "sysmon")!;
  const cov = (host: string, rule: string, status: string, source = "Sigma") => ({
    ...base,
    Fqdn: host,
    Kind: "coverage",
    Source: source,
    RuleName: rule,
    Status: status,
    Detail: "compiler sentence",
  });
  const report = buildAiAgentReport(
    [
      cov("WS-A", compiled.title, "ran (live state)"),
      { ...base, Fqdn: "WS-A", Kind: "hit", Family: "sigma", RuleName: compiled.title },
      { ...base, Fqdn: "WS-A", Kind: "hit", Family: "sigma", RuleName: compiled.title },
      cov("WS-A", sysmon.title, "ran (Sysmon event history)", "Sigma on Sysmon"),
      cov("WS-B", sysmon.title, "not run: no Sysmon", "Sigma on Sysmon"),
      cov("WS-B", "=HYPERLINK(not a rule)", "ran (live state)"),
    ],
    set,
  );

  it("lists every compiled and Sysmon rule of the rule set with its coverage basis", () => {
    const titles = (report.sigmaRules ?? []).map((r) => r.rule);
    expect(titles).toContain(compiled.title);
    expect(titles).toContain(sysmon.title);
    expect(titles).not.toContain("=HYPERLINK(not a rule)");
    expect((report.sigmaRules ?? []).find((r) => r.rule === sysmon.title)?.basis).toBe(
      "Sysmon event history",
    );
    expect(["live state", "event history"]).toContain(
      (report.sigmaRules ?? []).find((r) => r.rule === compiled.title)?.basis,
    );
  });

  it("gives each endpoint one cell per rule, with hits counted from the hit rows", () => {
    const a = report.endpoints.find((e) => e.host === "WS-A")!;
    const b = report.endpoints.find((e) => e.host === "WS-B")!;
    expect((a.sigma ?? []).find((c) => c.rule === compiled.title)).toEqual({
      rule: compiled.title,
      status: "ran (live state)",
      hits: 2,
    });
    expect((a.sigma ?? []).find((c) => c.rule === sysmon.title)?.status).toBe("ran (Sysmon event history)");
    expect((b.sigma ?? []).find((c) => c.rule === sysmon.title)?.status).toBe("not run: no Sysmon");
    expect((b.sigma ?? []).some((c) => c.rule === "=HYPERLINK(not a rule)")).toBe(false);
    // Per-rule rows are table cells, not endpoint coverage lines.
    expect(a.coverage).toEqual([]);
  });
});

// Codex review of #2722: two Velociraptor clients can share a host name (a re-imaged machine, a cloned
// VM). The run report keys endpoints by client id; the host name is only a display label, made unique.
describe("AI Agent Forensics report: two clients with the same host name", () => {
  const compiled = set.sigma.find((d) => d.mode === "compiled")!;
  const row = (clientId: string, over: Record<string, unknown>) => ({
    ...base,
    Hostname: "WS-01",
    ClientId: clientId,
    ...over,
  });
  const report = buildAiAgentReport(
    [
      row("C.aaa111", { Kind: "inventory", Tool: "Claude Code" }),
      row("C.aaa111", {
        Kind: "coverage",
        Source: "Sigma",
        RuleName: compiled.title,
        Status: "ran (live state)",
      }),
      row("C.aaa111", { Kind: "hit", Family: "sigma", RuleName: compiled.title }),
      row("C.bbb222", { Kind: "inventory", Tool: "Cursor" }),
      row("C.bbb222", {
        Kind: "coverage",
        Source: "Sigma",
        RuleName: compiled.title,
        Status: "not run: no Sysmon",
      }),
    ],
    set,
  );
  const run: AiAgentRun = {
    runId: "aar-dup",
    huntId: "H.1",
    launchedAt: "2026-11-19T10:00:00Z",
    endpoints: [],
    failedEndpoints: [],
    skippedEndpoints: [],
    scopes: ["agent-home"],
    uploadMaxBytes: 1,
    ruleSetVersion: set.version,
    artifacts: [],
    preserved: true,
    warnings: [],
    sensitive: true,
    report,
  };

  it("keeps them as two endpoints, labelled with the client id", () => {
    expect(report.endpoints.map((e) => [e.host, e.clientId])).toEqual([
      ["WS-01 (C.aaa111)", "C.aaa111"],
      ["WS-01 (C.bbb222)", "C.bbb222"],
    ]);
    const [a, b] = report.endpoints;
    expect(a.tools).toEqual(["Claude Code"]);
    expect(b.tools).toEqual(["Cursor"]);
    expect(a.hits).toBe(1);
    expect(b.hits).toBe(0);
    expect(a.sigma).toEqual([{ rule: compiled.title, status: "ran (live state)", hits: 1 }]);
    expect(b.sigma).toEqual([{ rule: compiled.title, status: "not run: no Sysmon", hits: 0 }]);
    expect(report.hits.map((h) => [h.host, h.clientId])).toEqual([["WS-01 (C.aaa111)", "C.aaa111"]]);
  });

  it("gives each its own column in report.md and the Sigma coverage CSV", () => {
    expect(aiAgentReportMarkdown(run)).toContain("| Rule | Basis | WS-01 (C.aaa111) | WS-01 (C.bbb222) |");
    expect(aiAgentSigmaCoverageCsv(run).split("\r\n")[0]).toBe(
      `"rule","basis","WS-01 (C.aaa111)","WS-01 (C.bbb222)"`,
    );
  });

  it("leaves a unique host name as it is", () => {
    const one = buildAiAgentReport([row("C.aaa111", { Kind: "inventory", Tool: "Cursor" })], set);
    expect(one.endpoints.map((e) => e.host)).toEqual(["WS-01"]);
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
