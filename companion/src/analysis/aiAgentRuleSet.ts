// AI Agent Forensics (#2690): loads one AI-agent rule set from a folder — the bundled
// companion/data/ai-agent-rules, or an installed AI-agent rule pack (aiAgentPack.ts) with the same
// layout. Everything the run needs comes from here: which YARA file runs in which scope, each rule's
// provisional grade, the Sigma split, the "Rules not run" list, the inventory and credential paths,
// the pinned AICodingAgents globs, the self-scan hashes and the rule-set version every hit records.
//
// Located like the bundled Sigma rules (sigmaBundledRules.ts): relative to this module in dev and tsc
// builds, next to the binary in the single-executable build.

import { createHash } from "node:crypto";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { parse as parseYaml } from "yaml";
import {
  NOT_RUN_REASONS,
  classifySigmaFile,
  parseGrade,
  parseYaraRules,
  sigmaLevelGrade,
  type AiAgentSigmaDoc,
  type AiAgentYaraRuleMeta,
} from "./aiAgentRuleParse.js";
import type { Severity } from "./stateTypes.js";

export const AI_AGENT_RULES_DIRNAME = "ai-agent-rules";
const UPSTREAM_RE = /^# ai-dfir-toolkit upstream commit: ([0-9a-f]{40}) \((\d{4}-\d{2}-\d{2})\)\s*$/m;
const MAX_RULE_FILE_BYTES = 256 * 1024;

export interface AiAgentScope {
  id: string;
  label: string;
  default: boolean;
  globs: string[];
  includeTriageGlobs: boolean;
  search?: { roots: string[]; maxDepth: number; skipDirs: string[]; names: string[] };
}

export interface AiAgentYaraFile {
  path: string; // under yara/
  text: string; // LF-normalized
  scopes: string[];
  rules: (AiAgentYaraRuleMeta & { grade: Severity; disabled: string })[];
}

export interface AiAgentNotRun {
  rule: string;
  family: "yara" | "sigma";
  file: string;
  reason: string;
}

export interface AiAgentRuleSet {
  dir: string;
  upstreamCommit: string;
  upstreamDate: string;
  /** "ai-dfir-toolkit @ 5960308 (2026-11-18)" — recorded on every hit, shown in the report. */
  version: string;
  /** SHA-256 over every file the run is generated from; names the Velociraptor artifact. */
  digest: string;
  scopes: AiAgentScope[];
  yara: AiAgentYaraFile[];
  sigma: AiAgentSigmaDoc[];
  sigmaGrades: Record<string, Severity>;
  notRun: AiAgentNotRun[];
  triageGlobs: { tool: string; name: string; glob: string }[];
  tools: { name: string; globs: string[] }[];
  mcpConfigs: { tool: string; glob: string }[];
  credentials: string[];
  lowInformationTimeFiles: string[];
  selfScanHashes: Set<string>;
}

export class AiAgentRuleSetError extends Error {}

/** The bundled rule folder (dev/tsc build first, then next to the binary). */
export function bundledAiAgentRulesDir(): string {
  const candidates: string[] = [];
  try {
    candidates.push(fileURLToPath(new URL(`../../data/${AI_AGENT_RULES_DIRNAME}`, import.meta.url)));
  } catch {
    // import.meta.url unavailable (some bundlers)
  }
  candidates.push(join(dirname(process.execPath), "data", AI_AGENT_RULES_DIRNAME));
  return candidates.find(isDir) ?? candidates[0];
}

function isDir(p: string): boolean {
  try {
    return statSync(p).isDirectory();
  } catch {
    return false;
  }
}

const lf = (s: string): string => s.replace(/\r\n/g, "\n");
const sha256 = (s: string | Buffer): string => createHash("sha256").update(s).digest("hex");

function readText(dir: string, rel: string): string {
  return lf(readFileSync(join(dir, rel), "utf8"));
}

function listFiles(root: string, ext: RegExp): string[] {
  const out: string[] = [];
  const walk = (d: string): void => {
    for (const name of readdirSync(d).sort()) {
      const full = join(d, name);
      const st = statSync(full);
      if (st.isDirectory()) walk(full);
      else if (ext.test(name) && st.size <= MAX_RULE_FILE_BYTES)
        out.push(relative(root, full).split(sep).join("/"));
    }
  };
  if (isDir(root)) walk(root);
  return out;
}

function yamlObj(dir: string, rel: string): Record<string, unknown> {
  const v = parseYaml(readText(dir, rel)) as unknown;
  if (!v || typeof v !== "object") throw new AiAgentRuleSetError(`${rel} is not a YAML mapping`);
  return v as Record<string, unknown>;
}

const strs = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x) => typeof x === "string") : []);

function loadScopes(map: Record<string, unknown>): AiAgentScope[] {
  const scopes = (map.scopes ?? {}) as Record<string, Record<string, unknown>>;
  return Object.entries(scopes).map(([id, s]) => {
    const search = s.search as Record<string, unknown> | undefined;
    return {
      id,
      label: typeof s.label === "string" ? s.label : id,
      default: s.default === true,
      globs: strs(s.globs),
      includeTriageGlobs: s.includeTriageGlobs === true,
      ...(search
        ? {
            search: {
              roots: strs(search.roots),
              maxDepth: Number(search.maxDepth) || 4,
              skipDirs: strs(search.skipDirs),
              names: strs(search.names),
            },
          }
        : {}),
    };
  });
}

function loadDisabled(dir: string): Map<string, string> {
  const raw = yamlObj(dir, "disabled.yml").disabled;
  const out = new Map<string, string>();
  for (const d of Array.isArray(raw) ? raw : []) {
    const r = d as Record<string, unknown>;
    if (typeof r.rule === "string") out.set(r.rule, typeof r.reason === "string" ? r.reason : "");
  }
  return out;
}

function loadYara(
  dir: string,
  map: Record<string, unknown>,
  scopeIds: Set<string>,
  disabled: Map<string, string>,
  notRun: AiAgentNotRun[],
): AiAgentYaraFile[] {
  const assigned = (map.yara ?? {}) as Record<string, Record<string, unknown>>;
  const files: AiAgentYaraFile[] = [];
  for (const path of listFiles(join(dir, "yara"), /\.yara?$/i)) {
    const text = readText(join(dir, "yara"), path);
    const metas = parseYaraRules(text);
    const entry = assigned[path];
    const scopes = strs(entry?.scopes).filter((s) => scopeIds.has(s));
    if (!entry || scopes.length === 0) {
      for (const m of metas)
        notRun.push({ rule: m.name, family: "yara", file: path, reason: NOT_RUN_REASONS.noScope });
      continue;
    }
    const grades = (entry.rules ?? {}) as Record<string, unknown>;
    const rules = metas.map((m) => {
      const off = disabled.get(m.name);
      if (off !== undefined)
        notRun.push({ rule: m.name, family: "yara", file: path, reason: off || NOT_RUN_REASONS.disabled });
      return { ...m, grade: parseGrade(grades[m.name]) ?? "Medium", disabled: off ?? "" };
    });
    files.push({ path, text, scopes, rules });
  }
  return files;
}

function loadSigma(dir: string, disabled: Map<string, string>, notRun: AiAgentNotRun[]): AiAgentSigmaDoc[] {
  const docs: AiAgentSigmaDoc[] = [];
  for (const path of listFiles(join(dir, "sigma"), /\.ya?ml$/i)) {
    for (const d of classifySigmaFile(path, readText(join(dir, "sigma"), path))) {
      const off = disabled.get(d.title) ?? (d.id ? disabled.get(d.id) : undefined);
      const doc = off !== undefined ? { ...d, mode: "not-run" as const, reason: off || "disabled" } : d;
      if (doc.mode === "not-run")
        notRun.push({ rule: doc.title, family: "sigma", file: path, reason: doc.reason });
      docs.push(doc);
    }
  }
  return docs;
}

function selfScanSet(dir: string, yara: AiAgentYaraFile[], sigma: AiAgentSigmaDoc[]): Set<string> {
  const set = new Set(strs(yamlObj(dir, "selfscan-hashes.yaml").sha256).map((h) => h.toLowerCase()));
  const own = [
    ...yara.map((y) => y.text),
    ...new Set(sigma.map((s) => readText(join(dir, "sigma"), s.file))),
  ];
  for (const text of own) {
    set.add(sha256(text));
    set.add(sha256(text.replace(/\n/g, "\r\n")));
  }
  return set;
}

/** Load and validate the rule set in `dir`. Throws AiAgentRuleSetError on a broken set. */
export function loadAiAgentRuleSet(dir: string = bundledAiAgentRulesDir()): AiAgentRuleSet {
  if (!isDir(dir)) throw new AiAgentRuleSetError(`AI-agent rule folder not found: ${dir}`);
  const upstream = UPSTREAM_RE.exec(readText(dir, "UPSTREAM"));
  if (!upstream) throw new AiAgentRuleSetError("UPSTREAM has no ai-dfir-toolkit upstream commit line");
  const map = yamlObj(dir, "scope-map.yaml");
  const paths = yamlObj(dir, "paths.yaml");
  const globs = yamlObj(dir, "aicodingagents-globs.yaml");
  const scopes = loadScopes(map);
  const disabled = loadDisabled(dir);
  const notRun: AiAgentNotRun[] = [];
  const yara = loadYara(dir, map, new Set(scopes.map((s) => s.id)), disabled, notRun);
  const sigma = loadSigma(dir, disabled, notRun);
  const sigmaGrades: Record<string, Severity> = {};
  for (const [k, v] of Object.entries((map.sigmaGrades ?? {}) as Record<string, unknown>)) {
    const g = parseGrade(v);
    if (g) sigmaGrades[k] = g;
  }
  const digestInput = [
    "UPSTREAM",
    "scope-map.yaml",
    "paths.yaml",
    "aicodingagents-globs.yaml",
    "disabled.yml",
    ...listFiles(join(dir, "yara"), /\.yara?$/i).map((p) => `yara/${p}`),
    ...listFiles(join(dir, "sigma"), /\.ya?ml$/i).map((p) => `sigma/${p}`),
  ]
    .map((rel) => `${rel}\0${readText(dir, rel)}`)
    .join("\0");
  const [commit, date] = [upstream[1], upstream[2]];
  return {
    dir,
    upstreamCommit: commit,
    upstreamDate: date,
    version: `ai-dfir-toolkit @ ${commit.slice(0, 7)} (${date})`,
    digest: sha256(digestInput),
    scopes,
    yara,
    sigma,
    sigmaGrades,
    notRun,
    triageGlobs: (Array.isArray(globs.globs) ? globs.globs : []) as AiAgentRuleSet["triageGlobs"],
    tools: (Array.isArray(paths.tools) ? paths.tools : []) as AiAgentRuleSet["tools"],
    mcpConfigs: (Array.isArray(paths.mcpConfigs) ? paths.mcpConfigs : []) as AiAgentRuleSet["mcpConfigs"],
    credentials: strs(paths.credentials),
    lowInformationTimeFiles: strs(map.lowInformationTimeFiles),
    selfScanHashes: selfScanSet(dir, yara, sigma),
  };
}

/** A YARA rule's or Sigma rule's provisional baseline grade; an unknown rule is Medium (§5.1). */
export function aiAgentRuleGrade(set: AiAgentRuleSet, family: "yara" | "sigma", rule: string): Severity {
  if (family === "yara") {
    for (const f of set.yara) {
      const r = f.rules.find((x) => x.name === rule);
      if (r) return r.grade;
    }
    return "Medium";
  }
  if (set.sigmaGrades[rule]) return set.sigmaGrades[rule];
  const doc = set.sigma.find((d) => d.title === rule || (d.id && d.id === rule));
  return doc ? sigmaLevelGrade(doc.level) : "Medium";
}

/** The YARA rule's meta (author, reference, ATLAS ids), when the rule is in the set. */
export function aiAgentYaraMeta(set: AiAgentRuleSet, rule: string): AiAgentYaraRuleMeta | undefined {
  for (const f of set.yara) {
    const r = f.rules.find((x) => x.name === rule);
    if (r) return r;
  }
  return undefined;
}

/** Link to a vendored rule file at the pinned upstream commit (every hit names one). */
export function aiAgentRuleLink(set: AiAgentRuleSet, file: string): string {
  return `https://github.com/depalmar/ai-dfir-toolkit/blob/${set.upstreamCommit}/${file}`;
}
