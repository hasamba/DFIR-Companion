// AI Agent Forensics (#2690): the pure half of the rule-set loader. Reads the vendored YARA files'
// rule names + meta, and sorts every vendored Sigma document into how this run treats it:
//   compiled — the Sigma→VQL compiler accepts it; it runs as a source of the generated artifact;
//   sysmon   — refused by the compiler, but a file_event / dns_query rule Velociraptor's own sigma()
//              engine can answer from the Sysmon event log (§14.4), where Sysmon is installed;
//   not-run  — listed under "Rules not run", grouped by a reason the analyst can act on.
// No disk access here; aiAgentRuleSet.ts hands in the text.

import { parseAllDocuments } from "yaml";
import { compileSigmaText } from "./sigmaToVql.js";
import type { Severity } from "./stateTypes.js";

export interface AiAgentYaraRuleMeta {
  name: string;
  author: string;
  description: string;
  reference: string;
  atlas: string[];
}

export type AiAgentSigmaMode = "compiled" | "sysmon" | "not-run";

export interface AiAgentSigmaDoc {
  file: string; // path under sigma/
  index: number; // document index inside the file
  title: string;
  id: string;
  level: string;
  category: string;
  product: string;
  service: string;
  mode: AiAgentSigmaMode;
  reason: string; // why it is not run ("" when it runs)
  vqlBlocks: string[]; // compiled sources (mode "compiled" only)
  text: string; // the document's own YAML, verbatim (mode "sysmon" feeds it to sigma())
  tags: string[];
}

/** The reason groups the panel shows under "Rules not run" (§5.3). */
export const NOT_RUN_REASONS = {
  llmLogs: "needs LLM application logs, not endpoint data",
  correlation: "correlation rule (counts or sequences events over time)",
  cloud: "cloud or network log source, handled by import-time Sigma, not this run",
  linux: "Linux rule; this version runs on Windows endpoints only",
  fileRead: "needs file-read auditing (Security 4663 with an audit SACL); Sysmon does not log reads",
  noScope: "no scope assignment yet (new upstream rule file)",
  disabled: "disabled",
  compiler: "compiler refusal",
} as const;

const META_LINE = /^\s*([A-Za-z_]+)\s*=\s*"((?:[^"\\]|\\.)*)"/;

/** Every `rule NAME { meta: … }` in one YARA file, with the meta keys this run reports. */
export function parseYaraRules(text: string): AiAgentYaraRuleMeta[] {
  const out: AiAgentYaraRuleMeta[] = [];
  const lines = text.split(/\r?\n/);
  let cur: Record<string, string> | null = null;
  let name = "";
  let inMeta = false;
  const flush = (): void => {
    if (!cur || !name) return;
    out.push({
      name,
      author: cur.author ?? "",
      description: cur.description ?? "",
      reference: cur.reference ?? "",
      atlas: (cur.atlas ?? "")
        .split(/[,\s]+/)
        .map((s) => s.trim())
        .filter((s) => /^AML\.T\d{4}(\.\d{3})?$/.test(s)),
    });
  };
  for (const line of lines) {
    const head = /^\s*(?:private\s+|global\s+)*rule\s+([A-Za-z_][A-Za-z0-9_]*)/.exec(line);
    if (head) {
      flush();
      name = head[1];
      cur = {};
      inMeta = false;
      continue;
    }
    if (!cur) continue;
    if (/^\s*meta\s*:/.test(line)) inMeta = true;
    else if (/^\s*(strings|condition)\s*:/.test(line)) inMeta = false;
    else if (inMeta) {
      const m = META_LINE.exec(line);
      if (m && !(m[1] in cur)) cur[m[1]] = m[2];
    }
  }
  flush();
  return out;
}

const SYSMON_CATEGORIES = new Set(["file_event", "dns_query"]);
const CLOUD_PRODUCTS = new Set(["azure", "aws", "gcp", "m365", "mlflow", "nvidia", "vector_db", "okta"]);
const LLM_PRODUCTS = new Set(["llm", "mcp", "agent", "rag_pipeline"]);

function str(v: unknown): string {
  return typeof v === "string" ? v.trim() : "";
}

function notRunReason(
  ls: { category: string; product: string },
  hasTimeframe: boolean,
  compileError: string,
): { mode: AiAgentSigmaMode; reason: string } {
  const { category, product } = ls;
  if (!category && !product) return { mode: "not-run", reason: NOT_RUN_REASONS.correlation };
  if (hasTimeframe) return { mode: "not-run", reason: NOT_RUN_REASONS.correlation };
  if (product === "linux") return { mode: "not-run", reason: NOT_RUN_REASONS.linux };
  if (category === "application" || LLM_PRODUCTS.has(product))
    return { mode: "not-run", reason: NOT_RUN_REASONS.llmLogs };
  if (CLOUD_PRODUCTS.has(product) || category === "proxy" || (!category && product))
    return { mode: "not-run", reason: NOT_RUN_REASONS.cloud };
  if (category === "file_access") return { mode: "not-run", reason: NOT_RUN_REASONS.fileRead };
  if (SYSMON_CATEGORIES.has(category) && (!product || product === "windows"))
    return { mode: "sysmon", reason: "" };
  return { mode: "not-run", reason: `${NOT_RUN_REASONS.compiler}: ${compileError}` };
}

/** Split one vendored Sigma file into its documents and classify each one. */
export function classifySigmaFile(file: string, text: string): AiAgentSigmaDoc[] {
  const hasContent = (c: string): boolean =>
    c.split(/\r?\n/).some((l) => l.trim() && !l.trim().startsWith("#"));
  const chunks = text.split(/^---\s*$/m).filter(hasContent);
  return chunks.map((chunk, index) => {
    const doc = (parseAllDocuments(chunk)[0]?.toJS() ?? {}) as Record<string, unknown>;
    const ls = (doc.logsource ?? {}) as Record<string, unknown>;
    const det = (doc.detection ?? {}) as Record<string, unknown>;
    const logsource = { category: str(ls.category), product: str(ls.product) };
    const compiled = compileSigmaText(chunk);
    const base = {
      file,
      index,
      title: str(doc.title),
      id: str(doc.id),
      level: str(doc.level).toLowerCase(),
      category: logsource.category,
      product: logsource.product,
      service: str(ls.service),
      text: chunk.trim() + "\n",
      tags: Array.isArray(doc.tags) ? doc.tags.map(String) : [],
    };
    if (compiled.ok) {
      const blocks = compiled.vql.split(/\n\s*\n/).filter((b) => b.trim());
      return { ...base, mode: "compiled" as const, reason: "", vqlBlocks: blocks };
    }
    const why = compiled.refusals.map((r) => r.message).join("; ");
    const { mode, reason } = notRunReason(logsource, det.timeframe != null, why);
    return { ...base, mode, reason, vqlBlocks: [] };
  });
}

/** Sigma `level` → the run's baseline grade, capped at High (§5.1 is provisional). */
export function sigmaLevelGrade(level: string): Severity {
  switch (level) {
    case "critical":
    case "high":
      return "High";
    case "medium":
      return "Medium";
    case "low":
      return "Low";
    case "informational":
      return "Info";
    default:
      return "Medium";
  }
}

const GRADES: readonly Severity[] = ["Critical", "High", "Medium", "Low", "Info"];

/** A grade string from the scope map, or null when it is not one of the five. Critical is capped. */
export function parseGrade(v: unknown): Severity | null {
  const s = typeof v === "string" ? v.trim() : "";
  const g = GRADES.find((x) => x.toLowerCase() === s.toLowerCase());
  if (!g) return null;
  return g === "Critical" ? "High" : g;
}
