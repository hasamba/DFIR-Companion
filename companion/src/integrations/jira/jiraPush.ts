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
    case "critical": return "Highest";
    case "high": return "High";
    case "medium": return "Medium";
    case "low": return "Low";
    default: return undefined;
  }
}

function issueSummary(caseId: string, finding: Finding): string {
  return `[DFIR ${caseId}] ${finding.title}`.slice(0, 255);
}

function issueDescription(finding: Finding, caseId: string): string {
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
