// Orchestrates a Companion finding → ServiceNow incident push. Re-push is idempotent by
// remembering the created incident number per (caseId, findingId).

import type { Finding } from "../../analysis/stateTypes.js";
import type { ServiceNowClientLike, ServiceNowIncidentRef } from "./servicenowClient.js";

export interface ServiceNowPushInput {
  caseId: string;
  finding: Finding;
  caller?: string;
  category?: string;
  subcategory?: string;
}

export interface ServiceNowPushResult {
  created: boolean;
  updated: boolean;
  incident: ServiceNowIncidentRef;
  warnings: string[];
}

export interface ServiceNowExportStoreLike {
  load(caseId: string): Promise<{ incidentRefs: Record<string, ServiceNowIncidentRef>; lastExportedAt: string }>;
  save(caseId: string, refs: Record<string, ServiceNowIncidentRef>): Promise<void>;
}

function snowUrgency(severity: string): number | undefined {
  switch (severity.toLowerCase()) {
    case "critical": return 1;
    case "high": return 1;
    case "medium": return 2;
    case "low": return 3;
    default: return undefined;
  }
}

function snowImpact(severity: string): number | undefined {
  switch (severity.toLowerCase()) {
    case "critical": return 1;
    case "high": return 1;
    case "medium": return 2;
    case "low": return 3;
    default: return undefined;
  }
}

function shortDescription(caseId: string, finding: Finding): string {
  return `[DFIR ${caseId}] ${finding.title}`.slice(0, 160);
}

function description(finding: Finding, caseId: string): string {
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

export async function pushFindingToServiceNow(
  client: ServiceNowClientLike,
  store: ServiceNowExportStoreLike,
  input: ServiceNowPushInput,
): Promise<ServiceNowPushResult> {
  const warnings: string[] = [];
  const existing = await store.load(input.caseId);
  const previous = existing.incidentRefs[input.finding.id];

  await client.me();

  const body = {
    shortDescription: shortDescription(input.caseId, input.finding),
    description: description(input.finding, input.caseId),
    urgency: snowUrgency(input.finding.severity),
    impact: snowImpact(input.finding.severity),
    caller: input.caller,
    category: input.category,
    subcategory: input.subcategory,
  };

  // Re-push UPDATES the incident we opened for this finding (by remembered sys_id) instead of
  // opening a duplicate — the same contract as the ClickUp playbook push.
  if (previous?.id) {
    const ref = await client.updateIncident(previous.id, body);
    const incident: ServiceNowIncidentRef = {
      id: ref.id || previous.id,
      number: ref.number || previous.number,
      url: ref.url ?? previous.url,
    };
    await store.save(input.caseId, { ...existing.incidentRefs, [input.finding.id]: incident });
    return { created: false, updated: true, incident, warnings };
  }

  const incident = await client.createIncident(body);
  await store.save(input.caseId, { ...existing.incidentRefs, [input.finding.id]: incident });
  return { created: true, updated: false, incident, warnings };
}
