// AI Agent Forensics (#2690): the results-only report of one run, built from the run's raw result
// rows. This — not the case timeline — is what the panel and the exported reports show, so "0 hits"
// always comes with what was looked at: per-endpoint inventory, coverage, skipped files, the rules
// not run and why, and the rule version. It is also the ONLY place the matched snippet appears
// (redacted), because the snippet never becomes part of an event the AI reads (aiAgentImport.ts).

import { gradeAiAgentHit, hitTime, AI_AGENT_TIME_LABEL } from "./aiAgentImport.js";
import { aiAgentRuleLink, type AiAgentNotRun, type AiAgentRuleSet } from "./aiAgentRuleSet.js";
import { isAiAgentRow, parseAiAgentRow, redactSnippet } from "./aiAgentRows.js";
import type { Severity } from "./stateTypes.js";

export interface AiAgentReportHit {
  host: string;
  rule: string;
  family: "yara" | "sigma";
  ruleFile: string;
  author: string;
  link: string;
  atlas: string;
  scope: string;
  severity: Severity;
  selfScan: boolean;
  path: string;
  sha256: string;
  time: string;
  timeBasis: string;
  timeLabel: string;
  scanTime: string;
  snippet: string; // redacted, length-capped; attacker-controlled — escape on every render
  preserved: string;
}

export interface AiAgentReportEndpoint {
  host: string;
  tools: string[];
  mcpServers: { name: string; command: string; argCount: number; config: string; tool: string }[];
  credentialStores: number;
  hits: number;
  coverage: { source: string; status: string; detail: string }[];
}

export interface AiAgentReport {
  builtAt: string;
  ruleSetVersion: string;
  endpoints: AiAgentReportEndpoint[];
  hits: AiAgentReportHit[];
  notRun: { reason: string; rules: string[] }[];
  unreadableRows: number;
  provisionalGrades: true;
}

type Row = Record<string, unknown>;

function hostOf(row: Row): string {
  for (const k of ["Fqdn", "Hostname", "ClientId", "client_id"]) {
    const v = row[k];
    if (typeof v === "string" && v.trim()) return v.trim();
  }
  return "unknown host";
}

function endpointFor(map: Map<string, AiAgentReportEndpoint>, host: string): AiAgentReportEndpoint {
  let e = map.get(host);
  if (!e) {
    e = { host, tools: [], mcpServers: [], credentialStores: 0, hits: 0, coverage: [] };
    map.set(host, e);
  }
  return e;
}

/** Group the rule set's not-run list by reason (the compiler's own text stays on each refusal). */
export function groupNotRun(notRun: readonly AiAgentNotRun[]): AiAgentReport["notRun"] {
  const groups = new Map<string, string[]>();
  for (const n of notRun) {
    const reason = n.reason.startsWith("compiler refusal") ? "compiler refusal" : n.reason;
    const label = n.reason === reason ? n.rule : `${n.rule} (${n.reason.replace(/^compiler refusal: /, "")})`;
    groups.set(reason, [...(groups.get(reason) ?? []), label]);
  }
  return [...groups.entries()].map(([reason, rules]) => ({ reason, rules }));
}

/** Build the report from every raw row the run's artifacts returned (other rows are ignored). */
export function buildAiAgentReport(
  rows: readonly Row[],
  set: AiAgentRuleSet,
  now = new Date(),
): AiAgentReport {
  const endpoints = new Map<string, AiAgentReportEndpoint>();
  const hits: AiAgentReportHit[] = [];
  let unreadable = 0;
  let version = "";
  for (const raw of rows) {
    if (!isAiAgentRow(raw)) continue;
    const parsed = parseAiAgentRow(raw);
    if (!parsed.ok) {
      unreadable++;
      continue;
    }
    const r = parsed.row;
    const host = hostOf(raw);
    const ep = endpointFor(endpoints, host);
    version ||= r.RuleSet ?? "";
    if (r.Kind === "hit") {
      const { severity, selfScan } = gradeAiAgentHit(set, r);
      const { time, basis } = hitTime(r);
      ep.hits++;
      hits.push({
        host,
        rule: r.RuleName,
        family: r.Family,
        ruleFile: r.RuleFile ?? "",
        author: r.RuleAuthor ?? "",
        link: r.RuleFile ? aiAgentRuleLink(set, r.RuleFile) : "",
        atlas: r.RuleAtlas ?? "",
        scope: r.Scope ?? "",
        severity,
        selfScan,
        path: r.FilePath ?? "",
        sha256: r.FileSha256 ?? "",
        time,
        timeBasis: basis,
        timeLabel: AI_AGENT_TIME_LABEL,
        scanTime: r.ScanTime ?? "",
        snippet: redactSnippet(r.MatchedText),
        preserved: r.Preserved ?? "",
      });
    } else if (r.Kind === "inventory") {
      if (r.McpServer)
        ep.mcpServers.push({
          name: r.McpServer,
          command: r.McpCommand ?? "",
          argCount: r.McpArgCount ?? 0,
          config: r.ConfigPath ?? "",
          tool: r.Tool,
        });
      else if (!ep.tools.includes(r.Tool)) ep.tools.push(r.Tool);
    } else if (r.Kind === "credential") ep.credentialStores++;
    else ep.coverage.push({ source: r.Source, status: r.Status, detail: r.Detail ?? "" });
  }
  const order: Severity[] = ["Critical", "High", "Medium", "Low", "Info"];
  hits.sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity) || a.host.localeCompare(b.host));
  return {
    builtAt: now.toISOString(),
    ruleSetVersion: version || set.version,
    endpoints: [...endpoints.values()].sort((a, b) => a.host.localeCompare(b.host)),
    hits,
    notRun: groupNotRun(set.notRun),
    unreadableRows: unreadable,
    provisionalGrades: true,
  };
}
