// AI Agent Forensics (#2690): builds the Companion-owned Velociraptor CLIENT artifact from the live
// AI-agent rule set, at run time, so a rule update needs no manual Velociraptor change (§4.2).
//
//   Custom.DFIRCompanion.AIAgentRules.D<digest>.PartN — import-only artifacts, each holding one chunk
//       of the base64 JSON config (rule texts, globs, rule meta). Chunked because the launch runs
//       `velociraptor query` with the program as ONE argv element, and Windows caps a command line
//       at 32,767 characters; the rule texts alone are ~50 KB.
//   Custom.DFIRCompanion.AIAgentForensics.D<digest> — imports every part and runs the sources:
//       Yara (the selected scopes), Inventory (tools, MCP servers, credential stores), one source per
//       compiled Sigma rule, and SigmaSysmon (the refused file_event/dns_query rules, §14.4).
//
// The name carries a digest of the rule set AND the run options, so two concurrent runs with
// different options never overwrite each other's definition, and a re-run with the same inputs
// reuses the same immutable name (§13.8).

import { createHash } from "node:crypto";
import type { AiAgentRuleSet, AiAgentScope } from "../../analysis/aiAgentRuleSet.js";
import { aiAgentRuleLink } from "../../analysis/aiAgentRuleSet.js";
import { sigmaLevelGrade } from "../../analysis/aiAgentRuleParse.js";
import { unsafeVqlCharProblem } from "../../analysis/vqlStatements.js";
import {
  cfgPreamble,
  compiledSigmaSourceVql,
  inventorySourceVql,
  sysmonSigmaSourceVql,
  yaraSourceVql,
} from "./aiAgentArtifactVql.js";

export const AI_AGENT_ARTIFACT_PREFIX = "Custom.DFIRCompanion.AIAgentForensics.";
const PART_PREFIX = "Custom.DFIRCompanion.AIAgentRules.";
/** Base64 characters per part: with its YAML wrapper, one launch program stays far under 32,767. */
export const AI_AGENT_PART_CHARS = 20_000;
/** The longest program one artifact_set call may send (Windows command-line cap, with headroom). */
export const AI_AGENT_MAX_PROGRAM_CHARS = 30_000;
export const AI_AGENT_DEFAULT_UPLOAD_MAX_BYTES = 50 * 1024 * 1024; // §11.7: 50 MB per file
const DEFAULT_SCAN_MAX_BYTES = 20 * 1024 * 1024;
const MODEL_SCAN_MAX_BYTES = 2 * 1024 * 1024 * 1024;
/**
 * The version of the generated VQL (aiAgentArtifactVql.ts). It is part of the artifact-name digest, so a
 * changed template gets a new name even when the rules did not change, and an artifact on the server
 * always matches what the runs that named it executed (§13.8). Bump it with every VQL change.
 *   2 — #2722: the preserved copy's hash, and per-rule Sigma coverage rows.
 *   3 — the Inventory source uses if() in place of `||`, which VQL cannot parse.
 */
export const AI_AGENT_VQL_TEMPLATE_VERSION = 3;
const SYSMON_LOG = "C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx";

export interface AiAgentRunOptions {
  /** Scope ids to scan; defaults to the scopes marked default in the scope map. */
  scopes?: string[];
  uploadMaxBytes?: number;
}

export interface AiAgentArtifactDef {
  name: string;
  yaml: string;
  sources: string[];
}

export interface AiAgentArtifactBundle {
  /** The primary artifact's name (Yara + Inventory); every name starts with it. */
  name: string;
  digest: string;
  /** Import-only rule-data artifacts; set first. */
  parts: { name: string; yaml: string }[];
  /** The collected artifacts: the primary, then as many Sigma artifacts as the size cap needs. */
  artifacts: AiAgentArtifactDef[];
  scopes: string[];
  ruleSetVersion: string;
}

export class AiAgentArtifactError extends Error {}

function globToRegex(glob: string): string {
  const body = glob
    .split("")
    .map((ch) => {
      if (ch === "*") return "[^\\\\/]*";
      if (ch === "/" || ch === "\\") return "[\\\\/]";
      return /[.+?^${}()|[\]]/.test(ch) ? `\\${ch}` : ch;
    })
    .join("");
  return body;
}

/** One case-insensitive regex matching every credential glob — excluded from scans and uploads. */
export function credentialRegex(globs: string[]): string {
  if (globs.length === 0) return "^$";
  return `(?i)^(${globs.map(globToRegex).join("|")})$`;
}

function scopeGlobs(set: AiAgentRuleSet, scope: AiAgentScope): string[] {
  const out = [...scope.globs];
  if (scope.includeTriageGlobs) out.push(...set.triageGlobs.map((g) => g.glob));
  if (scope.search) {
    const names = scope.search.names.join(",");
    for (const root of scope.search.roots) out.push(`${root}/**${scope.search.maxDepth}/{${names}}`);
  }
  return [...new Set(out)];
}

function skipRegex(scope: AiAgentScope): string {
  const dirs = scope.search?.skipDirs ?? [];
  if (!dirs.length) return "";
  return `(?i)[\\\\/](${dirs.map((d) => d.replace(/[.+?^${}()|[\]\\*]/g, "\\$&")).join("|")})[\\\\/]`;
}

function selectScopes(set: AiAgentRuleSet, opts: AiAgentRunOptions): AiAgentScope[] {
  const want = opts.scopes?.length ? new Set(opts.scopes) : null;
  const picked = set.scopes.filter((s) => (want ? want.has(s.id) : s.default));
  const unknown = want ? [...want].filter((id) => !set.scopes.some((s) => s.id === id)) : [];
  if (unknown.length) throw new AiAgentArtifactError(`unknown scan scope(s): ${unknown.join(", ")}`);
  return picked;
}

function sigmaFieldMapping(texts: string[]): Record<string, string> {
  const fields = new Set<string>();
  for (const t of texts)
    for (const m of t.matchAll(/^\s+([A-Za-z][A-Za-z0-9_]*)(?:\|[a-z|]+)?\s*:/gm)) fields.add(m[1]);
  for (const k of ["title", "id", "status", "level", "condition", "category", "product", "service"])
    fields.delete(k);
  const map: Record<string, string> = {};
  for (const f of [...fields].sort()) map[f] = `x=>x.EventData.${f}`;
  return map;
}

function buildConfig(set: AiAgentRuleSet, scopes: AiAgentScope[], uploadMaxBytes: number) {
  const ruleMeta: Record<string, Record<string, string>> = {};
  for (const f of set.yara)
    for (const r of f.rules)
      ruleMeta[r.name] = { File: f.path, Author: r.author, Atlas: r.atlas.join(", "), Grade: r.grade };
  const cfg: Record<string, unknown> = {
    RuleSet: set.version,
    ScanMaxBytes: scopes.some((s) => s.id === "model-files") ? MODEL_SCAN_MAX_BYTES : DEFAULT_SCAN_MAX_BYTES,
    UploadMaxBytes: uploadMaxBytes,
    CredentialRegex: credentialRegex(set.credentials),
    CredentialGlobs: set.credentials,
    Disabled: set.yara.flatMap((f) => f.rules.filter((r) => r.disabled).map((r) => r.name)),
    RuleMeta: ruleMeta,
    Tools: set.tools,
    McpConfigs: set.mcpConfigs,
    SysmonLog: SYSMON_LOG,
  };
  const keys: string[] = [];
  scopes.forEach((scope, i) => {
    const rules = set.yara.filter((f) => f.scopes.includes(scope.id)).map((f) => f.text);
    if (!rules.length) return;
    const key = `S${i}`;
    keys.push(key);
    cfg[key] = {
      Id: scope.id,
      Globs: scopeGlobs(set, scope),
      SkipRegex: skipRegex(scope),
      Rules: rules.join("\n"),
      Upload: !scope.includeTriageGlobs, // agent-home files are kept by the triage collection itself
    };
  });
  return { cfg, keys };
}

/** What a compiled rule reads, as the per-rule coverage row says it: the compiler's own call (#2722). */
export function compiledBasis(d: { snapshot?: boolean }): "live state" | "event history" {
  return d.snapshot === false ? "event history" : "live state";
}

/** The artifact-name digest: the rule set, the run options and the VQL template version (#2722). */
export function aiAgentArtifactDigest(
  setDigest: string,
  scopes: readonly string[],
  uploadMaxBytes: number,
  templateVersion = AI_AGENT_VQL_TEMPLATE_VERSION,
): string {
  return createHash("sha256")
    .update(`${setDigest}\0${JSON.stringify({ scopes, uploadMaxBytes, template: templateVersion })}`)
    .digest("hex")
    .slice(0, 16);
}

/**
 * The digest as an artifact-name part. Velociraptor refuses a name part that starts with a digit
 * ("Name parts can not start with a number"), and a hex digest often does, so it gets a letter first.
 */
export function aiAgentNameSegment(digest: string): string {
  return `D${digest}`;
}

function addSigma(set: AiAgentRuleSet, cfg: Record<string, unknown>) {
  const compiled = set.sigma.filter((d) => d.mode === "compiled");
  const sigmaKeys: { key: string; block: string }[] = [];
  compiled.forEach((d, i) => {
    d.vqlBlocks.forEach((block, j) => {
      const key = `G${i}_${j}`;
      sigmaKeys.push({ key, block });
      cfg[key] = {
        Title: d.title,
        File: d.file,
        Author: "",
        Tags: d.tags.join(", "),
        Grade: set.sigmaGrades[d.title] ?? sigmaLevelGrade(d.level),
        Basis: compiledBasis(d),
        Coverage: `compiled Sigma (${compiledBasis(d)})`,
        Sentence: d.coverage || "compiled Sigma",
        Link: aiAgentRuleLink(set, d.file),
      };
    });
  });
  const sysmon = set.sigma.filter((d) => d.mode === "sysmon");
  cfg.SysmonRules = sysmon.map((d) => d.text);
  cfg.SysmonCount = sysmon.length;
  cfg.SysmonTitles = sysmon.map((d) => ({ Title: d.title }));
  cfg.SysmonFieldMapping = sigmaFieldMapping(sysmon.map((d) => d.text));
  cfg.SysmonMeta = Object.fromEntries(
    sysmon.map((d) => [
      d.title,
      { File: d.file, Grade: set.sigmaGrades[d.title] ?? sigmaLevelGrade(d.level), Tags: d.tags.join(", ") },
    ]),
  );
  return { sigmaKeys, sysmonCount: sysmon.length };
}

function indent(vql: string): string {
  return vql
    .split(/\r?\n/)
    .map((l) => (l.trim() ? `      ${l}` : ""))
    .join("\n");
}

function sourceYaml(name: string, vql: string): string {
  return `  - name: ${name}\n    query: |\n${indent(vql)}`;
}

function guard(text: string, what: string): void {
  if (text.includes("'''")) throw new AiAgentArtifactError(`${what} may not contain '''`);
  const unsafe = unsafeVqlCharProblem(text);
  if (unsafe) throw new AiAgentArtifactError(`${what}: ${unsafe}`);
}

function artifactYaml(name: string, version: string, imports: string[], sources: [string, string][]): string {
  return [
    `name: ${name}`,
    `description: "DFIR Companion AI Agent Forensics: YARA and Sigma from ${version}, AI tool and MCP inventory"`,
    "type: CLIENT",
    "precondition: SELECT OS FROM info() WHERE OS = 'windows'",
    "imports:",
    ...imports.map((p) => `  - ${p}`),
    "sources:",
    ...sources.map(([n, v]) => sourceYaml(n, v)),
    "",
  ].join("\n");
}

/** Greedily pack the sources into artifacts that each fit one launch program (Windows argv cap). */
function packArtifacts(
  name: string,
  version: string,
  parts: { name: string }[],
  sources: [string, string][],
): AiAgentArtifactDef[] {
  const imports = parts.map((p) => p.name);
  const budget = AI_AGENT_MAX_PROGRAM_CHARS - 2_000; // the artifact_set wrapper, with headroom
  const groups: [string, string][][] = [];
  for (const src of sources) {
    const cur = groups[groups.length - 1];
    const next = cur ? [...cur, src] : [src];
    if (cur && artifactYaml(name, version, imports, next).length <= budget) groups[groups.length - 1] = next;
    else groups.push([src]);
  }
  return groups.map((g, i) => {
    const n = i === 0 ? name : `${name}.More${i}`;
    const yaml = artifactYaml(n, version, imports, g);
    if (yaml.length > budget)
      throw new AiAgentArtifactError(`source ${g[0][0]} alone exceeds the launch size cap`);
    return { name: n, yaml, sources: g.map(([s]) => s) };
  });
}

/** Build the artifact set for one run. Throws AiAgentArtifactError when nothing would run. */
export function buildAiAgentArtifact(
  set: AiAgentRuleSet,
  opts: AiAgentRunOptions = {},
): AiAgentArtifactBundle {
  const uploadMaxBytes = Math.max(0, Math.floor(opts.uploadMaxBytes ?? AI_AGENT_DEFAULT_UPLOAD_MAX_BYTES));
  const scopes = selectScopes(set, opts);
  const { cfg, keys } = buildConfig(set, scopes, uploadMaxBytes);
  const { sigmaKeys, sysmonCount } = addSigma(set, cfg);
  if (keys.length === 0 && sigmaKeys.length === 0 && sysmonCount === 0)
    throw new AiAgentArtifactError("the AI-agent rule set has no rule that can run");
  const json = JSON.stringify(cfg);
  const digest = aiAgentArtifactDigest(
    set.digest,
    scopes.map((s) => s.id),
    uploadMaxBytes,
  );
  const b64 = Buffer.from(json, "utf8").toString("base64");
  const parts: { name: string; yaml: string }[] = [];
  const vars: string[] = [];
  for (let i = 0; i * AI_AGENT_PART_CHARS < b64.length; i++) {
    const name = `${PART_PREFIX}${aiAgentNameSegment(digest)}.Part${i}`;
    const chunk = b64.slice(i * AI_AGENT_PART_CHARS, (i + 1) * AI_AGENT_PART_CHARS);
    vars.push(`aiagent_part_${i}`);
    parts.push({
      name,
      yaml: `name: ${name}\ndescription: "DFIR Companion AI Agent Forensics rule data, part ${i}"\ntype: CLIENT\nexport: |\n  LET aiagent_part_${i} = "${chunk}"\n`,
    });
  }
  const pre = cfgPreamble(vars);
  const sources: [string, string][] = [];
  if (keys.length) sources.push(["Yara", yaraSourceVql(pre, keys)]);
  sources.push(["Inventory", inventorySourceVql(pre)]);
  for (const s of sigmaKeys) sources.push([`Sigma${s.key}`, compiledSigmaSourceVql(pre, s.block, s.key)]);
  if (sysmonCount) sources.push(["SigmaSysmon", sysmonSigmaSourceVql(pre)]);
  const name = `${AI_AGENT_ARTIFACT_PREFIX}${aiAgentNameSegment(digest)}`;
  const artifacts = packArtifacts(name, set.version, parts, sources);
  for (const a of artifacts) guard(a.yaml, a.name);
  for (const p of parts) guard(p.yaml, p.name);
  return {
    name,
    digest,
    parts,
    artifacts,
    scopes: scopes.map((s) => s.id),
    ruleSetVersion: set.version,
  };
}
