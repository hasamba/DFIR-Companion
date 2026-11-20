// AI Agent Forensics (#2690): the results-only report of one run, built from the run's raw result
// rows. This — not the case timeline — is what the panel and the exported reports show, so "0 hits"
// always comes with what was looked at: per-endpoint inventory, coverage, skipped files, the rules
// not run and why, and the rule version. It is also the ONLY place the matched snippet appears
// (redacted), because the snippet never becomes part of an event the AI reads (aiAgentImport.ts).

import { gradeAiAgentHit, hitTime, AI_AGENT_TIME_LABEL } from "./aiAgentImport.js";
import { aiAgentRuleLink, type AiAgentNotRun, type AiAgentRuleSet } from "./aiAgentRuleSet.js";
import { isAiAgentRow, parseAiAgentRow, redactSnippet } from "./aiAgentRows.js";
import { aiAgentHashCheck, type AiAgentHashCheck } from "./aiAgentHashCheck.js";
import type { UploadManifestEntry } from "./aiAgentRunStore.js";
import type { Severity } from "./stateTypes.js";

export interface AiAgentReportHit {
  /** The endpoint's display label (aiAgentEndpointLabels): the host name, plus the client id if shared. */
  host: string;
  /** The Velociraptor client the row came from — the endpoint's key. Absent on older reports. */
  clientId?: string;
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
  /** The file's hash, taken after the YARA scan (not of the bytes YARA read) — the only hash IOC. */
  sha256: string;
  /** The preserved copy's hash, when it is known (#2722). Optional: reports stored before it lack it. */
  preservedSha256?: string;
  hashCheck?: AiAgentHashCheck;
  time: string;
  timeBasis: string;
  timeLabel: string;
  scanTime: string;
  snippet: string; // redacted, length-capped; attacker-controlled — escape on every render
  preserved: string;
}

export interface AiAgentReportEndpoint {
  /** Display label only: the host name, with the client id added when two clients share it. */
  host: string;
  /** The Velociraptor client id — what endpoints are keyed by. Absent on older reports. */
  clientId?: string;
  /** The host name before the label was made unique. Absent on older reports. */
  hostname?: string;
  tools: string[];
  mcpServers: { name: string; command: string; argCount: number; config: string; tool: string }[];
  credentialStores: number;
  hits: number;
  coverage: { source: string; status: string; detail: string }[];
  /** One cell per Sigma rule that reported on this endpoint (#2722); a rule with no cell: not recorded. */
  sigma?: AiAgentSigmaCell[];
}

export interface AiAgentSigmaCell {
  rule: string;
  status: string; // adversary-reachable (an endpoint row) — escape on every render
  hits: number;
}

/** A Sigma rule of the rule set, with what it reads (the rows of the rule-by-endpoint table). */
export interface AiAgentSigmaRule {
  rule: string;
  mode: "compiled" | "sysmon";
  basis: string;
}

export interface AiAgentReport {
  builtAt: string;
  ruleSetVersion: string;
  endpoints: AiAgentReportEndpoint[];
  hits: AiAgentReportHit[];
  /** The rule-by-endpoint Sigma table's rows, from the rule set (#2722). Absent on older reports. */
  sigmaRules?: AiAgentSigmaRule[];
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

function clientOf(row: Row): string {
  for (const k of ["ClientId", "client_id"]) {
    const v = row[k];
    if (typeof v === "string" && v.trim()) return v.trim();
  }
  return "";
}

/**
 * An endpoint's key: its client id, so two clients that share a host name stay two endpoints (Codex
 * review of #2722). The host name is the key only for a row with no client id.
 */
const endpointKey = (e: { clientId?: string; host: string }): string => e.clientId || e.host;

function endpointFor(map: Map<string, AiAgentReportEndpoint>, raw: Row): AiAgentReportEndpoint {
  const host = hostOf(raw);
  const clientId = clientOf(raw);
  const key = clientId || host;
  let e = map.get(key);
  if (!e) {
    e = {
      host,
      hostname: host,
      tools: [],
      mcpServers: [],
      credentialStores: 0,
      hits: 0,
      coverage: [],
      sigma: [],
    };
    if (clientId) e.clientId = clientId;
    map.set(key, e);
  }
  return e;
}

/**
 * Make every endpoint's display label unique: a host name two or more clients share becomes
 * "WS-01 (C.aaa111)". Hits take their endpoint's label. Order is kept. Returns a new report; run it
 * again after endpoints are added (withSilentEndpoints): it labels from `hostname`, never `host`.
 */
export function aiAgentEndpointLabels<R extends Pick<AiAgentReport, "endpoints" | "hits">>(report: R): R {
  const base = (e: AiAgentReportEndpoint): string => e.hostname ?? e.host;
  const keysByName = new Map<string, Set<string>>();
  for (const e of report.endpoints)
    keysByName.set(base(e), (keysByName.get(base(e)) ?? new Set()).add(endpointKey({ ...e, host: base(e) })));
  const label = (e: AiAgentReportEndpoint): string =>
    e.clientId && (keysByName.get(base(e))?.size ?? 0) > 1 ? `${base(e)} (${e.clientId})` : base(e);
  const endpoints = report.endpoints.map((e) => ({ ...e, host: label(e) }));
  const byClient = new Map(endpoints.filter((e) => e.clientId).map((e) => [e.clientId, e.host]));
  const hits = report.hits.map((h) =>
    h.clientId && byClient.has(h.clientId) ? { ...h, host: byClient.get(h.clientId)! } : h,
  );
  return { ...report, endpoints, hits };
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

/** The Sigma rules a run can report on, from the rule set — never from row strings (#2722). */
export function aiAgentSigmaRules(set: AiAgentRuleSet): AiAgentSigmaRule[] {
  const out = new Map<string, AiAgentSigmaRule>();
  for (const d of set.sigma) {
    if (!d.title || out.has(d.title)) continue;
    if (d.mode === "compiled")
      out.set(d.title, {
        rule: d.title,
        mode: "compiled",
        basis: d.snapshot === false ? "event history" : "live state",
      });
    else if (d.mode === "sysmon")
      out.set(d.title, { rule: d.title, mode: "sysmon", basis: "Sysmon event history" });
  }
  return [...out.values()];
}

/** Fill each endpoint's Sigma cells: one per known rule that reported, hits counted from hit rows. */
function sigmaCells(
  endpoints: Map<string, AiAgentReportEndpoint>,
  statuses: Map<string, Map<string, string>>,
  hits: readonly AiAgentReportHit[],
): void {
  for (const [key, byRule] of statuses) {
    const ep = endpoints.get(key);
    if (!ep) continue;
    ep.sigma = [...byRule.entries()].map(([rule, status]) => ({
      rule,
      status,
      hits: hits.filter((h) => endpointKey(h) === key && h.family === "sigma" && h.rule === rule).length,
    }));
  }
}

export interface AiAgentReportOptions {
  /** The hunt's complete upload manifest; null/absent when it could not be read in full (#2722). */
  manifest?: readonly UploadManifestEntry[] | null;
}

/** Build the report from every raw row the run's artifacts returned (other rows are ignored). */
export function buildAiAgentReport(
  rows: readonly Row[],
  set: AiAgentRuleSet,
  now = new Date(),
  opts: AiAgentReportOptions = {},
): AiAgentReport {
  const sigmaRules = aiAgentSigmaRules(set);
  const known = new Set(sigmaRules.map((r) => r.rule));
  const statuses = new Map<string, Map<string, string>>();
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
    const ep = endpointFor(endpoints, raw);
    const key = endpointKey(ep);
    version ||= r.RuleSet ?? "";
    if (r.Kind === "hit") {
      const { severity, selfScan } = gradeAiAgentHit(set, r);
      const { time, basis } = hitTime(r);
      ep.hits++;
      hits.push({
        host: ep.host,
        ...(ep.clientId ? { clientId: ep.clientId } : {}),
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
        ...aiAgentHashCheck(r, clientOf(raw), opts.manifest),
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
    else if (r.RuleName && known.has(r.RuleName)) {
      // A per-rule Sigma row: a table cell. Several compiled blocks of one rule share one cell.
      const byRule = statuses.get(key) ?? new Map<string, string>();
      if (!byRule.has(r.RuleName) || !r.Status.startsWith("ran")) byRule.set(r.RuleName, r.Status);
      statuses.set(key, byRule);
    } else if (!r.RuleName) ep.coverage.push({ source: r.Source, status: r.Status, detail: r.Detail ?? "" });
  }
  sigmaCells(endpoints, statuses, hits);
  const order: Severity[] = ["Critical", "High", "Medium", "Low", "Info"];
  hits.sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity) || a.host.localeCompare(b.host));
  return aiAgentEndpointLabels({
    builtAt: now.toISOString(),
    ruleSetVersion: version || set.version,
    endpoints: [...endpoints.values()].sort(
      (a, b) => a.host.localeCompare(b.host) || (a.clientId ?? "").localeCompare(b.clientId ?? ""),
    ),
    hits,
    sigmaRules,
    notRun: groupNotRun(set.notRun),
    unreadableRows: unreadable,
    provisionalGrades: true,
  });
}
