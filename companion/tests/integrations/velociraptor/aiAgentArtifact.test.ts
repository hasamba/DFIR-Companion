import { describe, expect, it } from "vitest";
import { cpSync, mkdtempSync, rmSync, writeFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parse as parseYaml } from "yaml";
import { bundledAiAgentRulesDir, loadAiAgentRuleSet } from "../../../src/analysis/aiAgentRuleSet.js";
import {
  AI_AGENT_ARTIFACT_PREFIX,
  AI_AGENT_MAX_PROGRAM_CHARS,
  AiAgentArtifactError,
  buildAiAgentArtifact,
  credentialRegex,
} from "../../../src/integrations/velociraptor/aiAgentArtifact.js";

const set = loadAiAgentRuleSet();

function withRules(edit: (dir: string) => void): ReturnType<typeof loadAiAgentRuleSet> {
  const tmp = mkdtempSync(join(tmpdir(), "aiagent-art-"));
  try {
    cpSync(bundledAiAgentRulesDir(), tmp, { recursive: true });
    edit(tmp);
    return loadAiAgentRuleSet(tmp);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

function decodeConfig(b: ReturnType<typeof buildAiAgentArtifact>): Record<string, unknown> {
  const chunks = b.parts.map((p) => /LET aiagent_part_\d+ = "([A-Za-z0-9+/=]*)"/.exec(p.yaml)![1]);
  return JSON.parse(Buffer.from(chunks.join(""), "base64").toString("utf8")) as Record<string, unknown>;
}

describe("AI Agent Forensics artifact: shape", () => {
  const b = buildAiAgentArtifact(set);
  type Doc = { name: string; imports: string[]; sources: { name: string; query: string }[] };
  const docs = b.artifacts.map((a) => parseYaml(a.yaml) as Doc);
  const doc = { ...docs[0], sources: docs.flatMap((d) => d.sources) };

  it("is a valid CLIENT artifact that imports every rule-data part", () => {
    expect(doc.name).toBe(b.name);
    expect(b.name.startsWith(AI_AGENT_ARTIFACT_PREFIX)).toBe(true);
    for (const d of docs) expect(d.imports).toEqual(b.parts.map((p) => p.name));
    for (const a of b.artifacts) expect(a.name.startsWith(b.name)).toBe(true);
    expect(b.artifacts.map((a) => a.sources).flat()).toEqual(doc.sources.map((s) => s.name));
    for (const p of b.parts)
      expect((parseYaml(p.yaml) as { export: string }).export).toMatch(/^LET aiagent_part_/);
  });

  it("runs YARA, inventory, the 8 compiled Sigma rules and the Sysmon engine", () => {
    const names = doc.sources.map((s) => s.name);
    expect(names[0]).toBe("Yara");
    expect(names).toContain("Inventory");
    expect(names).toContain("SigmaSysmon");
    expect(names.filter((n) => n.startsWith("SigmaG")).length).toBeGreaterThanOrEqual(8);
    expect(doc.sources.every((s) => s.query.includes("DFIRCompanionAIAgent"))).toBe(true);
  });

  it("scans the three default scopes and leaves the slow ones off", () => {
    expect(b.scopes).toEqual(["agent-home", "project-instructions", "mcp-installs"]);
    const cfg = decodeConfig(b);
    expect(cfg.ScanMaxBytes).toBe(20 * 1024 * 1024);
    expect(cfg.UploadMaxBytes).toBe(50 * 1024 * 1024);
    const s1 = cfg.S1 as { Globs: string[]; SkipRegex: string; Upload: boolean };
    expect(s1.Globs.some((g) => g.includes("**6/{") && g.includes("CLAUDE.md"))).toBe(true);
    expect(s1.SkipRegex).toContain("node_modules");
    expect(s1.Upload).toBe(true); // a matched project file is uploaded (decision 4)
    expect((cfg.S0 as { Upload: boolean }).Upload).toBe(false); // agent home: kept by the triage collection
  });

  it("raises the scan cap only when local model files are scanned", () => {
    const m = buildAiAgentArtifact(set, { scopes: ["model-files"] });
    expect(decodeConfig(m).ScanMaxBytes).toBeGreaterThan(1024 * 1024 * 1024);
  });

  it("keeps every launch program under the Windows command-line cap", () => {
    const wrap = (yaml: string) =>
      `LET def = '''${yaml}'''\nLET _set <= artifact_set(definition=def)\nSELECT 1 FROM scope()`;
    for (const a of b.artifacts) expect(wrap(a.yaml).length).toBeLessThan(AI_AGENT_MAX_PROGRAM_CHARS);
    for (const p of b.parts) expect(wrap(p.yaml).length).toBeLessThan(AI_AGENT_MAX_PROGRAM_CHARS);
  });

  it("never writes a rule's text into the VQL — only base64", () => {
    for (const a of b.artifacts) {
      expect(a.yaml).not.toContain("Agent_Memory_Hidden_Instruction_Concealment");
      expect(a.yaml).not.toContain("<!--");
    }
    const cfg = decodeConfig(b);
    expect(String((cfg.S0 as { Rules: string }).Rules)).toContain(
      "rule Agent_Memory_Hidden_Instruction_Concealment",
    );
  });

  it("excludes credential stores from the scan with one anchored regex", () => {
    const re = new RegExp(credentialRegex(set.credentials).replace("(?i)", ""), "i");
    expect(re.test("C:\\Users\\dev\\.claude\\.credentials.json")).toBe(true);
    expect(re.test("C:/Users/dev/AppData/Roaming/Cursor/User/globalStorage/state.vscdb")).toBe(true);
    expect(re.test("C:\\Users\\dev\\.claude\\CLAUDE.md")).toBe(false);
  });
});

describe("AI Agent Forensics artifact: naming and safety", () => {
  it("names the artifact by the rule set and the options, stably", () => {
    expect(buildAiAgentArtifact(set).name).toBe(buildAiAgentArtifact(set).name);
    expect(buildAiAgentArtifact(set, { scopes: ["agent-home"] }).name).not.toBe(
      buildAiAgentArtifact(set).name,
    );
    expect(buildAiAgentArtifact(set, { uploadMaxBytes: 1024 }).name).not.toBe(buildAiAgentArtifact(set).name);
  });

  it("renames on any rule change, so a running hunt's definition is never overwritten", () => {
    const changed = withRules((d) => {
      writeFileSync(
        join(d, "yara", "02-mcp-attacks", "mcp_tool_poisoning.yar"),
        "rule Changed { condition: true }\n",
      );
    });
    expect(buildAiAgentArtifact(changed).name).not.toBe(buildAiAgentArtifact(set).name);
  });

  it("carries adversarial rule text (quotes, ''', newlines, hidden Unicode) without breaking the YAML", () => {
    const evil =
      "rule Evil_Rule {\n meta:\n  author = \"a\\\"b ''' c\"\n strings:\n  $a = \"'''\\n\u{E0041}\u202E\"\n condition: $a }\n";
    const s = withRules((d) =>
      writeFileSync(join(d, "yara", "02-mcp-attacks", "mcp_tool_poisoning.yar"), evil),
    );
    const b = buildAiAgentArtifact(s);
    for (const a of b.artifacts) {
      expect(() => parseYaml(a.yaml)).not.toThrow();
      expect(a.yaml).not.toContain("'''");
    }
    expect(String((decodeConfig(b).S0 as { Rules: string }).Rules)).toContain("\u202E");
  });

  it("refuses an unknown scope and a rule set where nothing can run", () => {
    expect(() => buildAiAgentArtifact(set, { scopes: ["nope"] })).toThrow(AiAgentArtifactError);
    const empty = withRules((d) => {
      rmSync(join(d, "yara"), { recursive: true, force: true });
      for (const f of readdirSync(join(d, "sigma")))
        rmSync(join(d, "sigma", f), { recursive: true, force: true });
    });
    expect(() => buildAiAgentArtifact(empty, { scopes: ["agent-home"] })).toThrow(/no rule that can run/);
  });
});
