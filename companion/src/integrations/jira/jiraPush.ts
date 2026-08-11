// Orchestrates a Companion finding → Jira issue push. Re-push is idempotent by remembering the
// created issue key per (caseId, findingId) in a per-case store.

import type { Finding } from "../../analysis/stateTypes.js";
import type { JiraClientLike, JiraIssueRef } from "./jiraClient.js";

export interface JiraPushInput {
  caseId: string;
  projectKey: string;
  issueType?: string;
  finding: Finding;
}

export interface JiraPushResult {
  created: boolean;
  updated: boolean;
  issue: JiraIssueRef;
  warnings: string[];
}

export interface JiraExportStoreLike {
  load(caseId: string): Promise<{ issueRefs: Record<string, JiraIssueRef>; lastExportedAt: string }>;
  save(caseId: string, refs: Record<string, JiraIssueRef>): Promise<void>;
}

// Map Companion severity to Jira priority names.
function jiraPriority(severity: string): string | undefined {
  switch (severity.toLowerCase()) {
    case "critical":
      return "Highest";
    case "high":
      return "High";
    case "medium":
      return "Medium";
    case "low":
      return "Low";
    default:
      return undefined;
  }
}

function issueSummary(caseId: string, finding: Finding): string {
  return `[DFIR ${caseId}] ${finding.title}`.slice(0, 255);
}

function issueDescription(finding: Finding, _caseId: string): string {
  const lines = [
    `Finding ID: ${finding.id}`,
    `Severity: ${finding.severity}`,
    `Confidence: ${finding.confidence ?? "unknown"}`,
    `MITRE: ${finding.mitreTechniques.join(", ") || "none"}`,
    `IOCs: ${finding.relatedIocs.join(", ") || "none"}`,
    "",
    finding.description,
  ];
  return lines.join("\n");
}

export async function pushFindingToJira(
  client: JiraClientLike,
  store: JiraExportStoreLike,
  input: JiraPushInput,
): Promise<JiraPushResult> {
  const warnings: string[] = [];
  const existing = await store.load(input.caseId);
  const previous = existing.issueRefs[input.finding.id];

  // Auth check.
  await client.me();

  const body = {
    projectKey: input.projectKey,
    issueType: input.issueType,
    summary: issueSummary(input.caseId, input.finding),
    description: issueDescription(input.finding, input.caseId),
    priority: jiraPriority(input.finding.severity),
    labels: ["dfir-companion", input.caseId],
  };

  // Re-push UPDATES the issue we created for this finding (by remembered key) instead of
  // duplicating it — the same contract as the ClickUp playbook push.
  const target = previous ? previous.key || previous.id : "";
  if (previous && target) {
    const ref = await client.updateIssue(target, body);
    // The edit endpoint answers 204, so keep whatever the create response told us.
    const issue: JiraIssueRef = {
      id: ref.id || previous.id,
      key: ref.key || previous.key,
      url: ref.url ?? previous.url,
    };
    await store.save(input.caseId, { ...existing.issueRefs, [input.finding.id]: issue });
    return { created: false, updated: true, issue, warnings };
  }

  const issue = await client.createIssue(body);
  await store.save(input.caseId, { ...existing.issueRefs, [input.finding.id]: issue });
  return { created: true, updated: false, issue, warnings };
}

export interface JiraBulkPushInput {
  caseId: string;
  projectKey: string;
  issueType?: string;
  findings: Finding[];
}

export interface JiraBulkPushResult {
  created: number;
  updated: number;
  skipped: number;
  issues: Array<JiraIssueRef & { findingId: string }>;
  issueUrl?: string; // first issue url, for an "Open in Jira" link on the batch
  warnings: string[];
}

// Push a batch of findings, one issue each. Sequential on purpose: every push loads and rewrites
// the same per-case export store, so overlapping writes would lose issue keys. A finding the API
// refuses is counted as skipped with the reason kept — the batch never aborts on one bad ticket,
// the same contract as the ClickUp playbook push.
export async function pushFindingsToJira(
  client: JiraClientLike,
  store: JiraExportStoreLike,
  input: JiraBulkPushInput,
): Promise<JiraBulkPushResult> {
  const warnings: string[] = [];
  const issues: Array<JiraIssueRef & { findingId: string }> = [];
  let created = 0,
    updated = 0,
    skipped = 0;
  let issueUrl: string | undefined;

  for (const finding of input.findings) {
    try {
      const result = await pushFindingToJira(client, store, {
        caseId: input.caseId,
        projectKey: input.projectKey,
        issueType: input.issueType,
        finding,
      });
      if (result.created) created += 1;
      else updated += 1;
      issues.push({ ...result.issue, findingId: finding.id });
      issueUrl ??= result.issue.url;
      warnings.push(...result.warnings);
    } catch (err) {
      skipped += 1;
      warnings.push(`finding "${finding.title}": ${(err as Error).message}`);
    }
  }

  return { created, updated, skipped, issues, issueUrl, warnings };
}
