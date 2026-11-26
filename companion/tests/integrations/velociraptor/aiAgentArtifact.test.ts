import { describe, expect, it } from "vitest";
import { cpSync, mkdtempSync, rmSync, writeFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parse as parseYaml } from "yaml";
import { bundledAiAgentRulesDir, loadAiAgentRuleSet } from "../../../src/analysis/aiAgentRuleSet.js";
import { yaraScopeVql } from "../../../src/integrations/velociraptor/aiAgentArtifactVql.js";
import {
  AI_AGENT_ARTIFACT_PREFIX,
  AI_AGENT_MAX_PROGRAM_CHARS,
  AI_AGENT_VQL_TEMPLATE_VERSION,
  AiAgentArtifactError,
  aiAgentArtifactDigest,
  aiAgentNameSegment,
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

describe("YARA coverage counts (#2924)", () => {
  it("counts the scanned files with count(), never len() of a subquery, which Velociraptor reads as 0", () => {
    const { lets, coverage } = yaraScopeVql("S0");
    expect(lets).toContain(
      "LET n_in_S0 <= SELECT count() AS N FROM files_S0 WHERE Size <= cfg.ScanMaxBytes GROUP BY 1",
    );
    expect(coverage).toContain("n_in_S0[0].N");
    expect(coverage).not.toContain("len(list={");
  });
});

describe("AI Agent Forensics artifact: names Velociraptor accepts", () => {
  // Velociraptor refuses a name part that starts with a digit ("Name parts can not start with a
  // number"), and a hex digest starts with one 10 times in 16.
  const VALID_PART = /^[A-Za-z_][A-Za-z0-9_]*$/;

  it("turns a digest that starts with a digit into a valid name part", () => {
    expect(aiAgentNameSegment("24210e67d796ca5a")).toMatch(VALID_PART);
    expect(aiAgentNameSegment("abcdef0123456789")).toMatch(VALID_PART);
  });

  it("gives every part of every artifact name a letter first", () => {
    const b = buildAiAgentArtifact(set);
    for (const n of [b.name, ...b.parts.map((p) => p.name), ...b.artifacts.map((a) => a.name)])
      for (const part of n.split(".")) expect(part, n).toMatch(VALID_PART);
  });
});

describe("AI Agent Forensics artifact: VQL Velociraptor can parse", () => {
  // Velociraptor's parser refuses `x || []` ("unexpected token \"||\""), which refused the whole
  // artifact at upload, so no run started. The sources use if() and never ||/&&; checked on every
  // source of a run with every scope on.
  it("uses no || or && in any source query", () => {
    const b = buildAiAgentArtifact(set, { scopes: set.scopes.map((s) => s.id) });
    for (const a of b.artifacts) {
      const doc = parseYaml(a.yaml) as { sources: { name: string; query: string }[] };
      for (const src of doc.sources) expect(src.query, src.name).not.toMatch(/\|\||&&/);
    }
  });
});

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

  // #2907: the compiled rules that walk the whole disk are opt-in, so 4 of the 8 run by default (7 blocks).
  it("runs YARA, inventory, the compiled Sigma rules that stay off the whole disk, and the Sysmon engine", () => {
    const names = doc.sources.map((s) => s.name);
    expect(names[0]).toBe("Yara");
    expect(names).toContain("Inventory");
    expect(names).toContain("SigmaSysmon");
    expect(names.filter((n) => n.startsWith("SigmaG")).length).toBeGreaterThanOrEqual(7);
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

  it("without triage preservation, agent home uploads its matched files too, under its own name (#2920)", () => {
    const off = buildAiAgentArtifact(set, { preserve: false });
    const cfg = decodeConfig(off);
    expect((cfg.S0 as { Upload: boolean }).Upload).toBe(true);
    expect((cfg.S1 as { Upload: boolean }).Upload).toBe(true);
    expect(off.name).not.toBe(b.name);
    expect(buildAiAgentArtifact(set, { preserve: true }).name).toBe(b.name); // preserving runs keep their name
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

  it("uploads each matched file once and keeps that upload's hash beside the scan hash (#2722)", () => {
    const yara = doc.sources.find((x) => x.name === "Yara")!.query;
    const scopes = (yara.match(/LET kept_S\d+ =/g) ?? []).length;
    expect(scopes).toBeGreaterThan(0);
    expect((yara.match(/upload\(/g) ?? []).length).toBe(scopes); // one upload() per scope, read twice
    expect(yara).toContain("hash(path=HitPath).SHA256 AS FileSha256");
    expect(yara).toContain("Up.Sha256 AS PreservedSha256");
  });

  it("emits one coverage row per compiled Sigma rule, with the compiler's own basis (#2722)", () => {
    const cfg = decodeConfig(b);
    const g = Object.entries(cfg).filter(([k]) => /^G\d+_\d+$/.test(k));
    expect(g.length).toBeGreaterThan(0);
    for (const [, v] of g) {
      const c = v as { Basis: string; Coverage: string; Sentence: string };
      expect(["live state", "event history"]).toContain(c.Basis);
      expect(c.Coverage).toBe(`compiled Sigma (${c.Basis})`);
      expect(c.Sentence.length).toBeGreaterThan(0);
    }
    const sigma = doc.sources.find((x) => x.name.startsWith("SigmaG"))!.query;
    expect(sigma).toMatch(/"coverage" AS Kind/);
    expect(sigma).toMatch(/cfg\.G\d+_\d+\.Title AS RuleName/);
  });

  it("emits one Sysmon coverage row per rule, ran or not run, titles from cfg only (#2722)", () => {
    const cfg = decodeConfig(b);
    const titles = cfg.SysmonTitles as { Title: string }[];
    const sysmonDocs = set.sigma.filter((d) => d.mode === "sysmon");
    expect(titles.map((t) => t.Title)).toEqual(sysmonDocs.map((d) => d.title));
    const q = doc.sources.find((x) => x.name === "SigmaSysmon")!.query;
    expect((q.match(/foreach\(row=cfg\.SysmonTitles\)/g) ?? []).length).toBe(2);
    expect(q).toContain('"ran (Sysmon event history)" AS Status');
    expect(q).toContain('"not run: no Sysmon" AS Status');
    for (const d of sysmonDocs) expect(q).not.toContain(d.title);
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

  it("renames when the VQL template changes, even with the same rules (#2722)", () => {
    const one = aiAgentArtifactDigest(set.digest, ["agent-home"], 1024, AI_AGENT_VQL_TEMPLATE_VERSION);
    expect(aiAgentArtifactDigest(set.digest, ["agent-home"], 1024, AI_AGENT_VQL_TEMPLATE_VERSION)).toBe(one);
    expect(
      aiAgentArtifactDigest(set.digest, ["agent-home"], 1024, AI_AGENT_VQL_TEMPLATE_VERSION + 1),
    ).not.toBe(one);
    expect(buildAiAgentArtifact(set).digest).toBe(
      aiAgentArtifactDigest(set.digest, buildAiAgentArtifact(set).scopes, 50 * 1024 * 1024),
    );
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
