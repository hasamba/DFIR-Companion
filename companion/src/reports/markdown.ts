import type { InvestigationState, Severity, ForensicEvent } from "../analysis/stateTypes.js";
import { byEventTime } from "../analysis/forensicSort.js";
import { emptyReportMeta, type ReportMeta, type ReportRevision } from "./reportMeta.js";
import { deriveGlossary } from "./glossary.js";
import { buildAssetGraph } from "../analysis/assetGraph.js";
import { attackTechniqueMd } from "../analysis/attack.js";

// Renders report.md following the AnttiKurittu incident-report-template structure
// (https://github.com/AnttiKurittu/incident-report-template). Technical sections are
// auto-filled from the investigation state; human-authored sections come from ReportMeta
// (edited in the dashboard) and override/supplement the derived content. Where neither a
// human value nor derivable data exists, a clearly marked placeholder shows what to fill.

function cellMd(value: string): string {
  return value.replace(/\|/g, "\\|");
}

const SEVERITY_ORDER: Record<Severity, number> = {
  Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4,
};

const TODO = "> _To be completed by the investigator — edit in the dashboard → **Case details**._";

// A human value if present, otherwise a fallback (a derived value or the TODO placeholder).
function humanOr(value: string, fallback = TODO): string {
  const v = value.trim();
  return v.length > 0 ? v : fallback;
}

const DEFAULT_AUDIENCE =
  "This report is written for a *technical audience* such as system administrators, security " +
  "personnel and others working in roles related to the technical environment. The executive " +
  "summary, conclusions and recommendations are written for all stakeholders.";

function trimmedList(values: string[]): string[] {
  return values.map((v) => v.trim()).filter((v) => v.length > 0);
}

function titlePage(state: InvestigationState, meta: ReportMeta, lines: string[]): void {
  lines.push("# Incident Investigation Report", "");
  lines.push(`**Organization:** ${humanOr(meta.organization, "_(organization not set)_")}`, "");
  // Incident ID is optional — omit the line entirely when blank.
  if (meta.incidentId.trim().length > 0) lines.push(`**Incident ID:** ${meta.incidentId.trim()}`, "");
  const investigators = trimmedList(meta.investigators);
  const label = investigators.length > 1 ? "Investigators" : "Investigator";
  lines.push(`**${label}:** ${investigators.length > 0 ? investigators.join(", ") : "_(investigator not set)_"}`, "");
  if (meta.reviewer.trim().length > 0) lines.push(`**Reviewer:** ${meta.reviewer.trim()}`, "");
  if (meta.incidentManager.trim().length > 0) lines.push(`**Incident manager:** ${meta.incidentManager.trim()}`, "");
  lines.push(`**Restrictions:** ${humanOr(meta.restrictions, "CONFIDENTIAL / TLP:AMBER")}`, "");
}

// 1.1 — human revisions when provided; otherwise auto-seed a single "1.0" row dated from the
// case's last update and authored by the investigators, so the report always has a version line.
function defaultRevision(state: InvestigationState, meta: ReportMeta): ReportRevision {
  // Treat the epoch default (a case with no recorded activity yet) as "no date".
  const date = state.updatedAt && !state.updatedAt.startsWith("1970-01-01") ? state.updatedAt.slice(0, 10) : "";
  return { version: "1.0", date, author: trimmedList(meta.investigators).join(", "), comments: "Initial report" };
}

function revisions(state: InvestigationState, meta: ReportMeta, lines: string[]): void {
  lines.push("## 1.1 Report revisions", "");
  const rows = meta.revisions.length > 0 ? meta.revisions : [defaultRevision(state, meta)];
  lines.push("| Version | Published date | Author | Comments |", "| --- | --- | --- | --- |");
  for (const r of rows) {
    lines.push(`| ${cellMd(r.version)} | ${cellMd(r.date)} | ${cellMd(r.author)} | ${cellMd(r.comments)} |`);
  }
  lines.push("");
}

// 1.2 — optional: when no recipients are listed the whole section is omitted.
function distribution(meta: ReportMeta, lines: string[]): void {
  if (meta.distribution.length === 0) return;
  lines.push("## 1.2 Distribution list", "");
  lines.push("| Name | Role | Method |", "| --- | --- | --- |");
  for (const d of meta.distribution) {
    lines.push(`| ${cellMd(d.name)} | ${cellMd(d.role)} | ${cellMd(d.method)} |`);
  }
  lines.push("");
}

function disclaimer(lines: string[]): void {
  lines.push("## 1.3 Disclaimer and reading guide", "");
  lines.push(
    "This report has been written based on the facts found during an investigation into a cyber " +
    "security incident. All findings are based on the materials delivered for inspection and " +
    "discovered during the investigation, and are subject to change if new evidence is found.",
    "",
  );
  lines.push("### Timestamps", "");
  lines.push(
    "Unless otherwise stated, all timestamps are in Coordinated Universal Time (UTC) following the " +
    "ISO 8601 format (`YYYY-MM-DDTHH:MM:SSZ`). A trailing `Z` denotes UTC; deviations are shown " +
    "explicitly (e.g. `UTC+2`).",
    "",
  );
  lines.push("### Statements of probability", "");
  lines.push("| Chance | Wording |", "| --- | --- |");
  lines.push("| 1–10% | Very Unlikely / Almost certainly not |");
  lines.push("| 11–40% | Unlikely / Improbable |");
  lines.push("| 41–60% | Even Chance |");
  lines.push("| 61–90% | Probably / Likely |");
  lines.push("| 90–99% | Very Likely / Almost Certainly |", "");
  lines.push("### Statements of confidence", "");
  lines.push("| Confidence | Meaning |", "| --- | --- |");
  lines.push("| High | Strong, plentiful evidence; nothing contradicts the conclusion. |");
  lines.push("| Medium | Sufficient evidence, but other evidence could question it. |");
  lines.push("| Low | Missing evidence and open questions; logical but easily disproven. |", "");
  lines.push(
    "Conclusions, theories and interpretations of fact are presented separately from material " +
    "findings as the investigator's educated opinion, not as material fact.",
    "",
  );
}

function intendedAudience(meta: ReportMeta, lines: string[]): void {
  lines.push("## 1.4 Intended audience", "");
  lines.push(humanOr(meta.intendedAudience, DEFAULT_AUDIENCE), "");
}

function executiveSummary(state: InvestigationState, meta: ReportMeta, lines: string[]): void {
  lines.push("## 2 Executive summary", "");
  const derived = state.lastSummary.trim();
  lines.push(humanOr(meta.executiveSummary, derived.length > 0 ? derived : TODO), "");
}

// 2.1 — human-only and optional: omitted entirely when the investigator hasn't written one.
function businessImpact(meta: ReportMeta, lines: string[]): void {
  if (meta.businessImpact.trim().length === 0) return;
  lines.push("## 2.1 Business Impact Analysis", "");
  lines.push(meta.businessImpact.trim(), "");
}

function investigationLimitations(meta: ReportMeta, lines: string[]): void {
  lines.push("## 2.2 Investigation limitations", "");
  lines.push(humanOr(meta.investigationLimitations), "");
}

// 2.3 — human research questions if provided, else derive a starter list from the standard
// DFIR key questions the synthesis pass tracks.
function investigationGoals(state: InvestigationState, meta: ReportMeta, lines: string[]): void {
  lines.push("## 2.3 Investigation goals and targets", "");
  if (meta.investigationGoals.trim().length > 0) {
    lines.push(meta.investigationGoals.trim(), "");
    return;
  }
  if (state.keyQuestions.length > 0) {
    lines.push("Derived from the investigation's key questions:", "");
    for (const q of state.keyQuestions) lines.push(`- ${q.question}`);
    lines.push("");
    return;
  }
  lines.push(TODO, "");
}

// 2.4 — auto-derived from the report text; a human-authored glossary overrides it.
function glossary(state: InvestigationState, meta: ReportMeta, lines: string[]): void {
  lines.push("## 2.4 Glossary of terms", "");
  const entries = meta.glossary.length > 0 ? meta.glossary : deriveGlossary(state);
  if (entries.length === 0) {
    lines.push(TODO, "");
    return;
  }
  lines.push("| Term | Explanation |", "| --- | --- |");
  for (const g of entries) {
    lines.push(`| ${cellMd(g.term)} | ${cellMd(g.explanation)} |`);
  }
  lines.push("");
}

function incidentTimeline(state: InvestigationState, lines: string[]): void {
  lines.push("### 3.1 Incident timeline", "");
  lines.push("_Real incident events, ordered by when they actually happened._", "");
  if (state.forensicTimeline.length === 0) {
    lines.push("_No dated forensic events extracted yet._", "");
    return;
  }
  lines.push("| Time | Count | Severity | Event | MITRE | Findings |", "| --- | --- | --- | --- | --- | --- |");
  const ordered: ForensicEvent[] = [...state.forensicTimeline].sort(byEventTime);
  for (const e of ordered) {
    const time = e.endTimestamp && e.endTimestamp !== e.timestamp
      ? `${e.timestamp || "(undated)"} → ${e.endTimestamp}`
      : (e.timestamp || "(undated)");
    const count = e.count && e.count > 1 ? `×${e.count}` : "";
    lines.push(
      `| ${cellMd(time)} | ${count} | ${e.severity} | ${cellMd(e.description)} | ` +
      `${e.mitreTechniques.map(attackTechniqueMd).join(", ")} | ${cellMd(e.relatedFindingIds.join(", "))} |`,
    );
  }
  lines.push("");
}

function investigation(state: InvestigationState, lines: string[]): void {
  lines.push("## 4 Investigation", "");

  lines.push("### 4.1 Attacker path", "");
  lines.push(state.attackerPath.trim().length > 0 ? state.attackerPath : "_Attacker path not yet reconstructed._", "");

  // 4.2 Compromised assets — the victim hosts/accounts and the IoCs that touched each.
  lines.push("### 4.2 Compromised assets", "");
  const graph = buildAssetGraph(state);
  const compromised = graph.assets.filter((a) => a.compromised);
  if (compromised.length === 0) {
    lines.push("_No compromised assets identified yet._", "");
  } else {
    const iocValue = new Map(graph.iocs.map((i) => [i.id, i.value] as const));
    lines.push("| Asset | Type | Max severity | Related IoCs |", "| --- | --- | --- | --- |");
    for (const a of compromised) {
      const iocs = a.iocIds.map((id) => iocValue.get(id) ?? id).join(", ") || "—";
      lines.push(`| ${cellMd(a.name)} | ${a.type} | ${a.maxSeverity} | ${cellMd(iocs)} |`);
    }
    lines.push("");
  }

  lines.push("### 4.3 Findings", "");
  if (state.findings.length === 0) {
    lines.push("_No findings yet._", "");
  } else {
    const sorted = [...state.findings].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
    for (const f of sorted) {
      lines.push(`#### [${f.severity}] ${f.title} (${f.id})`);
      lines.push(f.description || "_no description_");
      if (f.relatedIocs.length) lines.push(`- IOCs: ${f.relatedIocs.join(", ")}`);
      if (f.mitreTechniques.length) lines.push(`- MITRE: ${f.mitreTechniques.map(attackTechniqueMd).join(", ")}`);
      if (f.sourceScreenshots.length) lines.push(`- Evidence: ${f.sourceScreenshots.join(", ")}`);
      lines.push(`- Status: ${f.status} | First seen: ${f.firstSeen} | Updated: ${f.lastUpdated}`, "");
    }
  }

  lines.push("### 4.4 Indicators of compromise", "");
  if (state.iocs.length === 0) {
    lines.push("_No IOCs extracted yet._", "");
  } else {
    lines.push("| ID | Type | Value | First seen |", "| --- | --- | --- | --- |");
    for (const i of state.iocs) {
      lines.push(`| ${cellMd(i.id)} | ${cellMd(i.type)} | ${cellMd(i.value)} | ${cellMd(i.firstSeen)} |`);
    }
    lines.push("");
  }

  lines.push("### 4.5 MITRE ATT&CK", "");
  if (state.mitreTechniques.length === 0) {
    lines.push("_No techniques mapped yet._", "");
  } else {
    lines.push("| Technique | Name | Findings |", "| --- | --- | --- |");
    for (const t of state.mitreTechniques) {
      lines.push(`| ${attackTechniqueMd(t.id)} | ${cellMd(t.name)} | ${cellMd(t.findingIds.join(", "))} |`);
    }
    lines.push("");
  }

  lines.push("### 4.6 Key investigative questions", "");
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
}

function conclusions(state: InvestigationState, meta: ReportMeta, lines: string[]): void {
  lines.push("## 5 Conclusions and recommendations", "");

  if (meta.conclusions.trim().length > 0) {
    lines.push(meta.conclusions.trim(), "");
  } else if (state.attackerPath.trim().length > 0) {
    // Derive a starting conclusion from the reconstructed attacker path.
    lines.push(state.attackerPath.trim(), "");
  } else {
    lines.push(TODO, "");
  }

  lines.push("### Recommendations", "");
  const recs = meta.recommendations.map((r) => r.trim()).filter((r) => r.length > 0);
  if (recs.length > 0) {
    lines.push("| Recommendation |", "| --- |");
    for (const r of recs) lines.push(`| ${cellMd(r)} |`);
    lines.push("");
  } else if (state.nextSteps.length > 0) {
    // Fall back to the AI-recommended next steps as draft recommendations.
    lines.push("_Draft recommendations from the recommended next steps — review and finalize._", "");
    lines.push("| Priority | Action | Why it matters | Where / what to collect |", "| --- | --- | --- | --- |");
    for (const s of state.nextSteps) {
      lines.push(`| ${s.priority.toUpperCase()} | ${cellMd(s.action)} | ${cellMd(s.rationale || "—")} | ${cellMd(s.pointer || "—")} |`);
    }
    lines.push("");
  } else {
    lines.push(TODO, "");
  }
}

export function renderMarkdownReport(state: InvestigationState, meta: ReportMeta = emptyReportMeta()): string {
  const lines: string[] = [];

  titlePage(state, meta, lines);
  revisions(state, meta, lines);
  distribution(meta, lines);
  if (meta.includeDisclaimer) disclaimer(lines);
  intendedAudience(meta, lines);

  executiveSummary(state, meta, lines);
  businessImpact(meta, lines);
  investigationLimitations(meta, lines);
  investigationGoals(state, meta, lines);
  glossary(state, meta, lines);

  lines.push("## 3 Timeline of events", "");
  incidentTimeline(state, lines);

  investigation(state, lines);
  conclusions(state, meta, lines);

  return lines.join("\n");
}
