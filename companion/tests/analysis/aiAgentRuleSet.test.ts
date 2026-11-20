import { describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { cpSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  AiAgentRuleSetError,
  aiAgentRuleGrade,
  aiAgentRuleLink,
  aiAgentYaraMeta,
  bundledAiAgentRulesDir,
  loadAiAgentRuleSet,
} from "../../src/analysis/aiAgentRuleSet.js";
import { NOT_RUN_REASONS, classifySigmaFile, parseYaraRules } from "../../src/analysis/aiAgentRuleParse.js";

const set = loadAiAgentRuleSet();
const FIXTURES = join(import.meta.dirname, "..", "fixtures", "aiAgent", "toolkit");

describe("AI-agent rule set: provenance", () => {
  it("pins the upstream commit and labels the version every hit records", () => {
    expect(set.upstreamCommit).toBe("5960308d7d8e9bbf838f31ca0e783373fc8a2ae7");
    expect(set.upstreamDate).toBe("2026-11-18");
    expect(set.version).toBe("ai-dfir-toolkit @ 5960308 (2026-11-18)");
    expect(set.digest).toMatch(/^[0-9a-f]{64}$/);
  });

  it("ships the Apache-2.0 licence next to the vendored rules", () => {
    const lic = readFileSync(join(bundledAiAgentRulesDir(), "LICENSE"), "utf8");
    expect(lic).toContain("Apache License");
  });

  it("links each rule to its file at the pinned commit", () => {
    expect(aiAgentRuleLink(set, "02-mcp-attacks/mcp_tool_poisoning.yar")).toBe(
      "https://github.com/depalmar/ai-dfir-toolkit/blob/5960308d7d8e9bbf838f31ca0e783373fc8a2ae7/02-mcp-attacks/mcp_tool_poisoning.yar",
    );
  });

  it("refuses a folder with no upstream line", () => {
    const tmp = mkdtempSync(join(tmpdir(), "aiagent-rules-"));
    try {
      cpSync(bundledAiAgentRulesDir(), tmp, { recursive: true });
      writeFileSync(join(tmp, "UPSTREAM"), "# nothing here\n");
      expect(() => loadAiAgentRuleSet(tmp)).toThrow(AiAgentRuleSetError);
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });
});

describe("AI-agent rule set: YARA scope + grade map", () => {
  it("assigns every vendored YARA file a scope (none falls into 'no scope assignment')", () => {
    expect(set.yara).toHaveLength(10);
    expect(set.notRun.filter((n) => n.family === "yara")).toEqual([]);
    for (const f of set.yara) expect(f.scopes.length).toBeGreaterThan(0);
  });

  it("gives every vendored rule an explicit grade (the provisional §5.1 table)", () => {
    const rules = set.yara.flatMap((f) => f.rules);
    expect(rules).toHaveLength(26);
    expect(aiAgentRuleGrade(set, "yara", "Agent_Memory_Hidden_Instruction_Concealment")).toBe("High");
    expect(aiAgentRuleGrade(set, "yara", "MCP_Tool_Poisoning_Hidden_Instructions")).toBe("High");
    expect(aiAgentRuleGrade(set, "yara", "Copilot_Rules_File_Coercive_Instructions")).toBe("Medium");
    expect(aiAgentRuleGrade(set, "yara", "Runtime_LLM_API_Prompt_In_Script_Heuristic")).toBe("Medium");
    expect(aiAgentRuleGrade(set, "yara", "PROMPTFLUX_ThinkingRobot_VBScript")).toBe("High");
  });

  it("grades an unknown rule Medium", () => {
    expect(aiAgentRuleGrade(set, "yara", "Brand_New_Upstream_Rule")).toBe("Medium");
    expect(aiAgentRuleGrade(set, "sigma", "Brand new Sigma rule")).toBe("Medium");
  });

  it("reads author, reference and ATLAS ids from the rule meta", () => {
    const m = aiAgentYaraMeta(set, "MCP_Tool_Poisoning_Hidden_Instructions");
    expect(m?.author).toContain("ai-dfir-toolkit");
    expect(m?.atlas).toEqual(["AML.T0115.002", "AML.T0110"]);
  });

  it("puts the slow scopes off by default and the three agent scopes on", () => {
    const on = set.scopes.filter((s) => s.default).map((s) => s.id);
    expect(on).toEqual(["agent-home", "project-instructions", "mcp-installs"]);
    expect(set.scopes.find((s) => s.id === "project-instructions")?.search?.skipDirs).toContain(
      "node_modules",
    );
  });

  it("lists a new upstream rule file with no scope under 'Rules not run'", () => {
    const tmp = mkdtempSync(join(tmpdir(), "aiagent-rules-"));
    try {
      cpSync(bundledAiAgentRulesDir(), tmp, { recursive: true });
      writeFileSync(join(tmp, "yara", "new.yar"), 'rule New_One { meta: author = "x" condition: true }\n');
      const s = loadAiAgentRuleSet(tmp);
      expect(s.notRun).toContainEqual({
        rule: "New_One",
        family: "yara",
        file: "new.yar",
        reason: NOT_RUN_REASONS.noScope,
      });
      expect(s.digest).not.toBe(set.digest);
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("parses rule names even with comments and private modifiers", () => {
    const rules = parseYaraRules(
      '// c\nprivate rule A_B {\n meta:\n  author = "me"\n condition: true }\nrule C { condition: true }',
    );
    expect(rules.map((r) => r.name)).toEqual(["A_B", "C"]);
    expect(rules[0].author).toBe("me");
  });
});

describe("AI-agent rule set: Sigma split (pinned so a re-sync shows coverage drift)", () => {
  it("compiles exactly the 8 rules the existing compiler accepts", () => {
    const compiled = set.sigma.filter((d) => d.mode === "compiled").map((d) => d.title);
    expect(compiled.sort()).toEqual(
      [
        "ARTEX Framework Default Probe File Created",
        "HuggingFace Token Exposure / Leak",
        "ML Library Typosquatting / Dependency Confusion Install",
        "Model File Appearing in Non-Standard Location",
        "PROMPTFLUX Runtime Artifacts (Thinking Robot Log / Startup Self-Copy)",
        "PowerShell Invoking LLM Provider API (Runtime Command Generation)",
        "SesameOp Loader Artifacts (Netapi64 / AppDomainManager Injection)",
        "Vector Database Port Accessed by Non-Application Process",
      ].sort(),
    );
    for (const d of set.sigma.filter((x) => x.mode === "compiled"))
      expect(d.vqlBlocks.length).toBeGreaterThan(0);
  });

  it("sends the 13 refused Windows file_event / dns_query rules to the Sysmon engine", () => {
    const sysmon = set.sigma.filter((d) => d.mode === "sysmon");
    expect(sysmon).toHaveLength(13);
    expect(new Set(sysmon.map((d) => d.category))).toEqual(new Set(["file_event", "dns_query"]));
  });

  it("explains every rule it does not run, by reason group", () => {
    const reasons = (r: string) => set.notRun.filter((n) => n.reason.startsWith(r)).length;
    expect(reasons(NOT_RUN_REASONS.llmLogs)).toBe(7);
    expect(reasons(NOT_RUN_REASONS.cloud)).toBe(18);
    expect(reasons(NOT_RUN_REASONS.fileRead)).toBe(1); // mcp_credential_access: a read, not a write
    expect(reasons(NOT_RUN_REASONS.linux)).toBe(3);
    expect(reasons(NOT_RUN_REASONS.correlation)).toBe(10);
    expect(set.notRun.every((n) => n.reason.length > 0)).toBe(true);
    // 60 documents: 22 endpoint ones (8 compiled + 13 Sysmon + 1 file read) and 38 that are not endpoint rules.
    expect(set.sigma).toHaveLength(60);
    expect(set.notRun.filter((n) => n.family === "sigma")).toHaveLength(39);
  });

  it("keeps a document's YAML verbatim for the Sysmon engine", () => {
    const docs = classifySigmaFile(
      "x.yml",
      "title: A\nlogsource:\n  category: file_event\n  product: windows\ndetection:\n  s:\n    Image|endswith: '\\\\x.exe'\n  filter:\n    TargetFilename|contains: 'y'\n  condition: s and not filter\n",
    );
    expect(docs[0].text).toContain("title: A");
  });
});

describe("AI-agent rule set: self-scan hashes and inventory paths", () => {
  it("lists the toolkit fixtures and the vendored rules by content hash (LF and CRLF)", () => {
    for (const name of readdirSync(FIXTURES)) {
      const lf = readFileSync(join(FIXTURES, name)).toString("utf8").replace(/\r\n/g, "\n");
      expect(set.selfScanHashes.has(createHash("sha256").update(lf).digest("hex"))).toBe(true);
    }
    const rule = set.yara[0].text;
    expect(set.selfScanHashes.has(createHash("sha256").update(rule).digest("hex"))).toBe(true);
    expect(
      set.selfScanHashes.has(createHash("sha256").update(rule.replace(/\n/g, "\r\n")).digest("hex")),
    ).toBe(true);
  });

  it("carries the pinned AICodingAgents globs, MCP config paths and credential stores", () => {
    expect(set.triageGlobs.length).toBeGreaterThan(100);
    expect(set.triageGlobs.every((g) => !g.glob.includes("\\"))).toBe(true);
    expect(set.mcpConfigs.map((m) => m.glob)).toContain("C:/Users/*/.cursor/mcp.json");
    expect(set.credentials).toContain("C:/Users/*/.claude/.credentials.json");
    expect(set.lowInformationTimeFiles).toContain(".claude.json");
  });
});
