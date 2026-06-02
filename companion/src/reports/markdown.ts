import type { InvestigationState, Severity, ForensicEvent } from "../analysis/stateTypes.js";
import { byEventTime } from "../analysis/forensicSort.js";

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

  lines.push("## Attacker Path", "");
  lines.push(state.attackerPath.trim().length > 0 ? state.attackerPath : "_Attacker path not yet reconstructed._", "");

  lines.push("## Key Investigative Questions", "");
  if (state.keyQuestions.length === 0) {
    lines.push("_Not assessed yet — run synthesis._", "");
  } else {
    const mark = (s: string) => (s === "answered" ? "✅" : s === "partial" ? "🟡" : "❓");
    lines.push("| | Question | Answer | Where to find it |", "| --- | --- | --- | --- |");
    for (const q of state.keyQuestions) {
      lines.push(`| ${mark(q.status)} | ${cellMd(q.question)} | ${cellMd(q.answer || "_unknown_")} | ${cellMd(q.pointer || "—")} |`);
    }
    lines.push("");
  }

  lines.push("## Recommended Next Steps", "");
  if (state.nextSteps.length === 0) {
    lines.push("_None recommended yet — run synthesis._", "");
  } else {
    lines.push("| Priority | Action | Why it matters | Where / what to collect |", "| --- | --- | --- | --- |");
    for (const s of state.nextSteps) {
      lines.push(`| ${s.priority.toUpperCase()} | ${cellMd(s.action)} | ${cellMd(s.rationale || "—")} | ${cellMd(s.pointer || "—")} |`);
    }
    lines.push("");
  }

  lines.push("## Forensic Timeline", "");
  lines.push("_Real incident events, ordered by when they actually happened._", "");
  if (state.forensicTimeline.length === 0) {
    lines.push("_No dated forensic events extracted yet._", "");
  } else {
    lines.push("| Time | Count | Severity | Event | MITRE | Findings | Evidence |", "| --- | --- | --- | --- | --- | --- | --- |");
    const ordered: ForensicEvent[] = [...state.forensicTimeline].sort(byEventTime);
    for (const e of ordered) {
      // Show a time span for aggregated events, and ×N when more than one occurrence.
      const time = e.endTimestamp && e.endTimestamp !== e.timestamp
        ? `${e.timestamp || "(undated)"} → ${e.endTimestamp}`
        : (e.timestamp || "(undated)");
      const count = e.count && e.count > 1 ? `×${e.count}` : "";
      lines.push(
        `| ${cellMd(time)} | ${count} | ${e.severity} | ${cellMd(e.description)} | ` +
        `${cellMd(e.mitreTechniques.join(", "))} | ${cellMd(e.relatedFindingIds.join(", "))} | ` +
        `${cellMd(e.sourceScreenshots.join(", "))} |`,
      );
    }
    lines.push("");
  }

  lines.push("## Investigation Log", "");
  lines.push("_Order in which evidence was reviewed during the investigation._", "");
  if (state.timeline.length === 0) {
    lines.push("_No review entries yet._", "");
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

  lines.push("## Indicators of Compromise (IOCs)", "");
  if (state.iocs.length === 0) {
    lines.push("_No IOCs extracted yet._", "");
  } else {
    lines.push("| ID | Type | Value | First seen |", "| --- | --- | --- | --- |");
    for (const i of state.iocs) {
      lines.push(`| ${cellMd(i.id)} | ${cellMd(i.type)} | ${cellMd(i.value)} | ${cellMd(i.firstSeen)} |`);
    }
    lines.push("");
  }

  lines.push("## Investigation Threads", "");
  const openT = state.openThreads.filter((t) => t.status === "open");
  const closedT = state.openThreads.filter((t) => t.status === "closed");
  if (openT.length === 0 && closedT.length === 0) {
    lines.push("_No threads opened._", "");
  } else {
    lines.push("**Open (still being chased):**");
    if (openT.length === 0) lines.push("- _none_");
    else for (const t of openT) lines.push(`- [${t.id}] ${t.description} (opened ${t.openedAt})`);
    lines.push("", "**Closed (resolved):**");
    if (closedT.length === 0) lines.push("- _none_");
    else for (const t of closedT) lines.push(`- [${t.id}] ${t.description} (opened ${t.openedAt}, closed ${t.closedAt})`);
    lines.push("");
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
