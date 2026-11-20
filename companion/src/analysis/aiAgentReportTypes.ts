// The shapes of an AI Agent Forensics run report (#2690, #2722) and of the read-time projection the
// case report carries (#2721). Types only, in the shared layer, so stateTypes.ts can name that
// projection without reaching up into the code that builds it (aiAgentReport.ts, aiAgentRunStore.ts).

import type { Severity } from "./stateTypes.js";

export type AiAgentHashCheck = "same" | "differs" | "not preserved" | "not recorded";

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

export interface AiAgentSigmaCell {
  rule: string;
  status: string; // adversary-reachable (an endpoint row) — escape on every render
  hits: number;
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

/**
 * What a run's Markdown report reads (#2721): the stored run's report-safe fields. A stored run is one
 * of these; the case report carries ONLY these fields, never the raw rows (which hold the unredacted
 * matched text) or the manifest's file list.
 */
export interface AiAgentRunView {
  runId: string;
  huntId: string;
  guiUrl?: string;
  launchedAt: string;
  scopes: string[];
  ruleSetVersion: string;
  preserved: boolean;
  warnings: string[];
  failedEndpoints: { clientId: string; error: string }[];
  skippedEndpoints: { clientId: string; hostname: string; reason: string }[];
  readIncomplete?: { artifact: string; rowsRead: number }[];
  reportError?: string;
  manifest?: { total: number; totalBytes: number };
  report?: AiAgentReport;
}

/** One run in the case report: launched in the case, or a sweep filed into it with "Add to case". */
export interface AiAgentCaseRun {
  run: AiAgentRunView;
  /** Set for a sweep filed into this case: the sweep case and when it was last filed here. */
  filedFrom?: { sweepCaseId: string; at: string };
}

/** The case report's AI Agent Forensics input. Read-time only: built per report, never saved. */
export interface AiAgentCaseRuns {
  runs: AiAgentCaseRun[];
  /** Records that could not be read, in words (never a filesystem path). */
  unreadable: string[];
}
