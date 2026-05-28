import type { InvestigationState, Severity } from "../analysis/stateTypes.js";

function cellMd(value: string): string {
  return value.replace(/\|/g, "\\|");
}

const SEVERITY_ORDER: Record<Severity, number> = {
  Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4,
};

export function renderMarkdownReport(state: InvestigationState): string {
  const lines: string[] = [];
  lines.push(`# Incident Report — ${state.caseId}`, "");

  lines.push("## Executive Summary", "");
  lines.push(state.lastSummary.trim().length > 0 ? state.lastSummary : "_No summary yet._", "");

  lines.push("## Timeline", "");
  if (state.timeline.length === 0) {
    lines.push("_No timeline entries yet._", "");
  } else {
    for (const t of state.timeline) {
      const shots = t.sourceScreenshots.length ? ` (evidence: ${t.sourceScreenshots.join(", ")})` : "";
      lines.push(`- **${t.timestamp}** — ${t.description}${shots}`);
    }
    lines.push("");
  }

  lines.push("## Findings", "");
  if (state.findings.length === 0) {
    lines.push("_No findings yet._", "");
  } else {
    const sorted = [...state.findings].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
    for (const f of sorted) {
      lines.push(`### [${f.severity}] ${f.title} (${f.id})`);
      lines.push(f.description || "_no description_");
      if (f.relatedIocs.length) lines.push(`- IOCs: ${f.relatedIocs.join(", ")}`);
      if (f.mitreTechniques.length) lines.push(`- MITRE: ${f.mitreTechniques.join(", ")}`);
      if (f.sourceScreenshots.length) lines.push(`- Evidence: ${f.sourceScreenshots.join(", ")}`);
      lines.push(`- Status: ${f.status} | First seen: ${f.firstSeen} | Updated: ${f.lastUpdated}`, "");
    }
  }

  lines.push("## MITRE ATT&CK", "");
  if (state.mitreTechniques.length === 0) {
    lines.push("_No techniques mapped yet._", "");
  } else {
    lines.push("| Technique | Name | Findings |", "| --- | --- | --- |");
    for (const t of state.mitreTechniques) {
      lines.push(`| ${cellMd(t.id)} | ${cellMd(t.name)} | ${cellMd(t.findingIds.join(", "))} |`);
    }
    lines.push("");
  }

  return lines.join("\n");
}
