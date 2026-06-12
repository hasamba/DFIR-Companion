import type { InvestigationState, Severity, ForensicEvent } from "../analysis/stateTypes.js";
import { byEventTime } from "../analysis/forensicSort.js";
import { emptyReportMeta, type ReportMeta, type ReportRevision } from "./reportMeta.js";
import { deriveGlossary } from "./glossary.js";
import { buildAssetGraph, type AssetGraph } from "../analysis/assetGraph.js";
import { buildEvidenceGraph } from "../analysis/evidenceGraph.js";
import { buildAttackPhases, DEFAULT_GAP_SECONDS } from "../analysis/burstDetect.js";
import { deriveIocSources } from "../analysis/iocCorroboration.js";
import { attackTechniqueMd } from "../analysis/attack.js";
import { buildAdversaryHintsResult } from "../analysis/adversaryHints.js";
import { loadAdversaryGroupsDataset, adversaryHintEnvOptions } from "../analysis/adversaryGroupsData.js";
import type { CustomerExposureSummary } from "../analysis/customerExposure.js";
import type { NotebookEntry } from "../analysis/notebookStore.js";
import { playbookStats, type PlaybookStatus, type PlaybookTask } from "../analysis/playbook.js";
import {
  DEFAULT_COVER_TITLE,
  buildBrandingContext,
  defaultReportTemplate,
  orderedEnabledSections,
  renderTemplateString,
  type ReportSectionKey,
  type ReportTemplate,
} from "./reportTemplate.js";

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

function titlePage(
  state: InvestigationState,
  meta: ReportMeta,
  template: ReportTemplate,
  ctx: Record<string, string>,
  lines: string[],
): void {
  // Optional report branding — the investigating firm's logo and name above the title. The report
  // template can hide either (showLogo / showCompanyName) for a layout that supplies its own
  // branding. companyLogo is a validated raster data URI (see reportMeta.ts); the alt text strips
  // brackets so an analyst-supplied company name can't break the Markdown image syntax.
  const company = meta.companyName.trim();
  if (template.showLogo && meta.companyLogo.trim().length > 0) {
    const alt = (company.length > 0 ? `${company} logo` : "Company logo").replace(/[[\]]/g, "");
    lines.push(`![${alt}](${meta.companyLogo.trim()})`, "");
  }
  if (template.showCompanyName && company.length > 0) lines.push(`**${company}**`, "");
  // Cover title/subtitle come from the template's branding strings, interpolated with the case's
  // report metadata ({{organization}}, {{incidentId}}, …). The default template's coverTitle is
  // the historical "Incident Investigation Report" with no subtitle, so output is unchanged.
  const title = renderTemplateString(template.coverTitle, ctx).trim() || DEFAULT_COVER_TITLE;
  lines.push(`# ${title}`, "");
  const subtitle = renderTemplateString(template.coverSubtitle, ctx).trim();
  if (subtitle.length > 0) lines.push(`_${subtitle}_`, "");
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
  lines.push("### 1.3.1 Timestamps", "");
  lines.push(
    "Unless otherwise stated, all timestamps are in Coordinated Universal Time (UTC) following the " +
    "ISO 8601 format (`YYYY-MM-DDTHH:MM:SSZ`). A trailing `Z` denotes UTC; deviations are shown " +
    "explicitly (e.g. `UTC+2`).",
    "",
  );
  lines.push("### 1.3.2 Statements of probability", "");
  lines.push("| Chance | Wording |", "| --- | --- |");
  lines.push("| 1–10% | Very Unlikely / Almost certainly not |");
  lines.push("| 11–40% | Unlikely / Improbable |");
  lines.push("| 41–60% | Even Chance |");
  lines.push("| 61–90% | Probably / Likely |");
  lines.push("| 90–99% | Very Likely / Almost Certainly |", "");
  lines.push("### 1.3.3 Statements of confidence", "");
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

function narrativeTimeline(state: InvestigationState, lines: string[]): void {
  lines.push("### 3.2 Narrative timeline", "");
  lines.push("_Chronological prose account of the incident for management and stakeholders._", "");
  if (!state.narrativeTimeline || state.narrativeTimeline.trim().length === 0) {
    lines.push("_Narrative not yet generated — run Synthesize or use the Generate button in the dashboard._", "");
    return;
  }
  lines.push(state.narrativeTimeline, "");
}

function incidentTimeline(state: InvestigationState, lines: string[]): void {
  lines.push("### 3.1 Incident timeline", "");
  lines.push("_Real incident events, ordered by when they actually happened._", "");
  if (state.forensicTimeline.length === 0) {
    lines.push("_No dated forensic events extracted yet._", "");
    return;
  }
  lines.push("| Time | Host | Count | Severity | Event | MITRE | Findings |", "| --- | --- | --- | --- | --- | --- | --- |");
  const ordered: ForensicEvent[] = [...state.forensicTimeline].sort(byEventTime);
  for (const e of ordered) {
    const time = e.endTimestamp && e.endTimestamp !== e.timestamp
      ? `${e.timestamp || "(undated)"} → ${e.endTimestamp}`
      : (e.timestamp || "(undated)");
    const count = e.count && e.count > 1 ? `×${e.count}` : "";
    lines.push(
      `| ${cellMd(time)} | ${cellMd(e.asset || "")} | ${count} | ${e.severity} | ${cellMd(e.description)} | ` +
      `${e.mitreTechniques.map(attackTechniqueMd).join(", ")} | ${cellMd(e.relatedFindingIds.join(", "))} |`,
    );
  }
  lines.push("");
}

// 3.2 — temporal attack phases: the timeline grouped into bursts of activity by time gap, each
// labelled with its dominant ATT&CK tactic (deterministic, no AI). Gives the reader the
// kill-chain at a glance — when each stage happened and how dense it was.
function attackPhases(state: InvestigationState, lines: string[]): void {
  lines.push("### 3.2 Attack phases", "");
  lines.push("_Timeline grouped into temporal bursts; each phase labelled by its dominant ATT&CK tactic._", "");
  const gapSeconds = Number(process.env.DFIR_PHASE_GAP_S) || DEFAULT_GAP_SECONDS;
  const phases = buildAttackPhases(state.forensicTimeline, { gapSeconds });
  if (phases.length === 0) {
    lines.push("_No dated forensic events to group into phases yet._", "");
    return;
  }
  lines.push("| Phase | When | Severity | Events | MITRE |", "| --- | --- | --- | --- | --- |");
  phases.forEach((p, i) => {
    const when = p.endTimestamp && p.endTimestamp !== p.startTimestamp
      ? `${p.startTimestamp} → ${p.endTimestamp}`
      : (p.startTimestamp || "(undated)");
    lines.push(
      `| ${i + 1}. ${cellMd(p.label)} | ${cellMd(when)} | ${p.maxSeverity} | ${p.eventCount} | ` +
      `${p.inferredTechniques.map(attackTechniqueMd).join(", ")} |`,
    );
  });
  lines.push("");
}

// 4.6 (appendix) — adversary group hints: known ATT&CK groups ranked by how much their technique
// set overlaps the case's identified techniques. Offline hypothesis fuel from the bundled MITRE
// Groups dataset — NOT attribution (every row shows the group's total technique count so a 4-of-150
// diffuse match reads differently from a 4-of-12 focused one, and the caveat is stated up front).
function adversaryHints(state: InvestigationState, lines: string[]): void {
  lines.push("#### 4.6.1 Adversary group hints", "");
  const result = buildAdversaryHintsResult(state, loadAdversaryGroupsDataset(), adversaryHintEnvOptions());
  lines.push(`_${result.caveat}_`, "");
  if (result.groupCount === 0) {
    lines.push("_Adversary-group dataset not available — run `npm run data:update-attack`._", "");
    return;
  }
  if (result.caseTechniqueCount === 0) {
    lines.push("_No techniques identified yet — adversary hints need at least one ATT&CK technique._", "");
    return;
  }
  if (result.hints.length === 0) {
    lines.push(
      `_No group reaches the ${result.minOverlap}-technique overlap threshold across the case's ` +
        `${result.caseTechniqueCount} identified technique(s)._`,
      "",
    );
    return;
  }
  lines.push(
    `Scored against ${result.caseTechniqueCount} case technique(s) over ${result.groupCount} groups ` +
      `(MITRE ATT&CK v${result.attackVersion}); ≥${result.minOverlap} overlapping techniques. ` +
      `**Bold** = exact sub-technique match (stronger signal); plain = base-technique match.`,
    "",
  );
  lines.push("| Group | Aliases | Overlap (exact) | Overlapping techniques |", "| --- | --- | --- | --- |");
  for (const h of result.hints) {
    // Escape [] in the link text so a group name containing a bracket can't truncate the Markdown link.
    const name = `[${cellMd(`${h.id} ${h.name}`).replace(/[[\]]/g, "\\$&")}](${h.url})`;
    const overlap = `${h.overlapCount} of ${h.groupTechniqueCount}${h.exactCount ? ` (${h.exactCount} exact)` : ""}`;
    const exactSet = new Set(h.exactTechniques);
    const techniques = h.overlapTechniques
      .map((t) => (exactSet.has(t) ? `**${attackTechniqueMd(t)}**` : attackTechniqueMd(t)))
      .join(", ");
    lines.push(
      `| ${cellMd(name)} | ${cellMd(h.aliases.join(", ") || "—")} | ${overlap} | ${techniques} |`,
    );
  }
  lines.push("");
}

function customerExposure(exposure: CustomerExposureSummary | undefined, lines: string[]): void {
  // Always present (like 4.7 Key questions) so the section numbering stays consistent whether or
  // not a leak/breach check was run; a placeholder makes "not assessed" explicit to the reader.
  lines.push("### 4.5 Customer exposure", "");
  if (!exposure || !exposure.checkedAt) {
    lines.push("_Not assessed — configure a leak/breach provider and run the customer exposure check from the dashboard._", "");
    return;
  }
  lines.push(`Checked: ${exposure.checkedAt}`, "");
  lines.push(`Providers: ${exposure.providers.join(", ") || "none"}`, "");
  lines.push(`Customer domains: ${exposure.targets.domains.join(", ") || "none"}`, "");
  lines.push(`Customer emails: ${exposure.targets.emails.join(", ") || "none"}`, "");
  if (exposure.results.length === 0) {
    lines.push("_No customer exposure results returned._", "");
  } else {
    lines.push("| Provider | Target | Email | Breach/source | Date | Data |", "| --- | --- | --- | --- | --- | --- |");
    for (const r of exposure.results) {
      lines.push(`| ${cellMd(r.provider)} | ${cellMd(`${r.targetType}:${r.target}`)} | ${cellMd(r.email ?? "")} | ${cellMd(r.breach ?? "")} | ${cellMd(r.breachDate ?? "")} | ${cellMd([...(r.exposedData ?? []), ...(r.secretPresent ? ["credential material present"] : [])].join(", "))} |`);
    }
    lines.push("");
  }
  if (exposure.errors.length > 0) {
    lines.push("_Provider errors:_", "");
    for (const e of exposure.errors) lines.push(`- ${e.provider} ${e.targetType}:${e.target} — ${e.error}`);
    lines.push("");
  }
}

function investigation(state: InvestigationState, lines: string[], exposure?: CustomerExposureSummary, prebuiltGraph?: AssetGraph): void {
  lines.push("## 4 Investigation", "");

  lines.push("### 4.1 Attack path", "");
  lines.push(state.attackerPath.trim().length > 0 ? state.attackerPath : "_Attack path not yet reconstructed._", "");

  // 4.2 Compromised assets — the victim hosts/accounts and the IoCs that touched each.
  // A prebuiltGraph (with analyst overrides applied) is used when available.
  lines.push("### 4.2 Compromised assets", "");
  const graph = prebuiltGraph ?? buildAssetGraph(state);
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
      const confLabel = f.confidence !== undefined ? ` [${f.confidence}% confidence]` : "";
      lines.push(`#### [${f.severity}]${confLabel} ${f.title} (${f.id})`);
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
    // Corroboration: tools that observed each indicator (derived from the events' sources).
    const iocSrc = deriveIocSources(state.iocs, state.forensicTimeline);
    lines.push("| ID | Type | Value | First seen | Sources |", "| --- | --- | --- | --- | --- |");
    for (const i of state.iocs) {
      const src = iocSrc[i.id];
      const srcCell = src && src.length ? `${src.join(", ")}${src.length > 1 ? ` (⊕ ${src.length})` : ""}` : "—";
      lines.push(`| ${cellMd(i.id)} | ${cellMd(i.type)} | ${cellMd(i.value)} | ${cellMd(i.firstSeen)} | ${cellMd(srcCell)} |`);
    }
    lines.push("");
  }

  customerExposure(exposure, lines);

  lines.push("### 4.6 MITRE ATT&CK", "");
  if (state.mitreTechniques.length === 0) {
    lines.push("_No techniques mapped yet._", "");
  } else {
    lines.push("| Technique | Name | Findings |", "| --- | --- | --- |");
    for (const t of state.mitreTechniques) {
      lines.push(`| ${attackTechniqueMd(t.id)} | ${cellMd(t.name)} | ${cellMd(t.findingIds.join(", "))} |`);
    }
    lines.push("");
  }

  adversaryHints(state, lines);

  lines.push("### 4.7 Key investigative questions", "");
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

  chainOfEvidence(state, lines);
}

// 4.8 Chain of evidence — the causal view derived from the forensic timeline: which process
// spawned which (process execution chains), which binary/account moved between hosts
// (lateral movement), file write→execute lineage, and network flows (src→dst).
function chainOfEvidence(state: InvestigationState, lines: string[]): void {
  lines.push("### 4.8 Chain of evidence", "");
  const graph = buildEvidenceGraph(state);
  if (graph.edges.length === 0) {
    lines.push("_No causal chains derived yet — import process-creation events or evidence spanning multiple hosts._", "");
    return;
  }
  const label = new Map(graph.nodes.map((n) => [n.id, n] as const));
  const name = (id: string) => label.get(id)?.label ?? id;
  const host = (id: string) => label.get(id)?.asset ?? "—";

  const spawned = graph.edges.filter((e) => e.type === "spawned");
  if (spawned.length > 0) {
    lines.push("**Process execution chains**", "");
    lines.push("| Parent process | Child process | Host | Confidence |", "| --- | --- | --- | --- |");
    for (const e of spawned) {
      lines.push(`| ${cellMd(name(e.source))} | ${cellMd(name(e.target))} | ${cellMd(host(e.target))} | ${e.confidence} |`);
    }
    lines.push("");
  }

  const lateral = graph.edges.filter((e) => e.type === "lateral_move");
  if (lateral.length > 0) {
    lines.push("**Lateral movement**", "");
    lines.push("| From | To | Basis | Confidence |", "| --- | --- | --- | --- |");
    for (const e of lateral) {
      lines.push(`| ${cellMd(name(e.source))} | ${cellMd(name(e.target))} | ${cellMd(e.basis)} | ${e.confidence} |`);
    }
    lines.push("");
  }

  const fileLineage = graph.edges.filter((e) => e.type === "file_lineage");
  if (fileLineage.length > 0) {
    lines.push("**File lineage (wrote → executed)**", "");
    lines.push("| From | To | Basis | Confidence |", "| --- | --- | --- | --- |");
    for (const e of fileLineage) {
      lines.push(`| ${cellMd(name(e.source))} | ${cellMd(name(e.target))} | ${cellMd(e.basis)} | ${e.confidence} |`);
    }
    lines.push("");
  }

  const netFlows = graph.edges.filter((e) => e.type === "network_flow");
  if (netFlows.length > 0) {
    lines.push("**Network flows (src → dst)**", "");
    lines.push("| Source | Destination | Basis | Confidence |", "| --- | --- | --- | --- |");
    for (const e of netFlows) {
      lines.push(`| ${cellMd(name(e.source))} | ${cellMd(name(e.target))} | ${cellMd(e.basis)} | ${e.confidence} |`);
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

const PLAYBOOK_STATUS_LABEL: Record<PlaybookStatus, string> = {
  todo: "To do",
  in_progress: "In progress",
  done: "Done",
  skipped: "Skipped",
};

function playbookSection(tasks: PlaybookTask[], lines: string[]): void {
  lines.push("## Response Playbook", "");
  const stats = playbookStats(tasks);
  lines.push(
    `_Actionable remediation/investigation checklist derived from the recommended next steps and high-severity findings, tracked by the analyst. **${stats.done}/${stats.total} complete (${stats.completionPct}%)**._`,
    "",
  );
  lines.push("| # | Status | Priority | Task | Assignee | Due | Notes |", "| --- | --- | --- | --- | --- | --- | --- |");
  tasks.forEach((t, i) => {
    const status = PLAYBOOK_STATUS_LABEL[t.status] ?? t.status;
    lines.push(
      `| ${i + 1} | ${status} | ${t.priority.toUpperCase()} | ${cellMd(t.title)} | ${cellMd(t.assignee || "—")} | ${cellMd(t.dueDate || "—")} | ${cellMd(t.notes || "—")} |`,
    );
  });
  lines.push("");
}

function analystNotebook(entries: NotebookEntry[], lines: string[]): void {
  lines.push("## Analyst Notebook", "");
  lines.push("_Investigator working notes — hypotheses, open questions, and observations recorded during the investigation._", "");
  if (!entries.length) {
    lines.push("_(no notebook entries)_", "");
    return;
  }
  const TYPE_LABEL: Record<NotebookEntry["type"], string> = {
    hypothesis: "Hypothesis",
    note: "Note",
    question: "Question",
  };
  for (const e of entries) {
    const label = TYPE_LABEL[e.type] ?? e.type;
    const who = e.author ? ` — ${e.author}` : "";
    const ts = e.timestamp ? ` _(${e.timestamp.slice(0, 16).replace("T", " ")} UTC)_` : "";
    lines.push(`**[${label}]**${who}${ts}`, "");
    lines.push(e.text, "");
  }
}

export function renderMarkdownReport(
  state: InvestigationState,
  meta: ReportMeta = emptyReportMeta(),
  exposure?: CustomerExposureSummary,
  assetGraph?: AssetGraph,
  notebookEntries?: NotebookEntry[],
  playbookTasks?: PlaybookTask[],
  template: ReportTemplate = defaultReportTemplate(),
): string {
  const lines: string[] = [];
  const ctx = buildBrandingContext(state, meta);

  // Optional running header banner (branding) — interpolated; empty in the default template.
  const header = renderTemplateString(template.headerText, ctx).trim();
  if (header.length > 0) lines.push(`> ${header}`, "");

  // Each canonical report section is a keyed builder; the template decides which appear and in
  // what order. The default template enables them all in the canonical order, so the default
  // report is byte-identical to the historical fixed-format one.
  const builders: Record<ReportSectionKey, () => void> = {
    titlePage: () => titlePage(state, meta, template, ctx, lines),
    // Section 1 — report metadata. The major heading is rendered explicitly so the AnttiKurittu
    // template's section structure is complete: "1 Report metadata" sits above 1.1 / 1.2 / 1.3 / 1.4.
    reportMetadata: () => {
      lines.push("## 1 Report metadata", "");
      revisions(state, meta, lines);
      distribution(meta, lines);
      if (meta.includeDisclaimer) disclaimer(lines);
      intendedAudience(meta, lines);
    },
    executiveSummary: () => executiveSummary(state, meta, lines),
    businessImpact: () => businessImpact(meta, lines),
    investigationLimitations: () => investigationLimitations(meta, lines),
    investigationGoals: () => investigationGoals(state, meta, lines),
    glossary: () => glossary(state, meta, lines),
    timeline: () => {
      lines.push("## 3 Timeline of events", "");
      incidentTimeline(state, lines);
      narrativeTimeline(state, lines);
      attackPhases(state, lines);
    },
    investigation: () => investigation(state, lines, exposure, assetGraph),
    conclusions: () => conclusions(state, meta, lines),
    playbook: () => {
      if (playbookTasks && playbookTasks.length > 0) playbookSection(playbookTasks, lines);
    },
    notebook: () => {
      if (notebookEntries && notebookEntries.length > 0) analystNotebook(notebookEntries, lines);
    },
  };

  for (const key of orderedEnabledSections(template)) builders[key]();

  // Optional footer / confidentiality banner (branding) — interpolated; empty in the default template.
  const footer = renderTemplateString(template.footerText, ctx).trim();
  if (footer.length > 0) lines.push("---", "", `_${footer}_`, "");

  return lines.join("\n");
}
