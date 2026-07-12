import type { InvestigationState, Severity, ForensicEvent } from "../analysis/stateTypes.js";
import { byEventTime } from "../analysis/forensicSort.js";
import { emptyReportMeta, type ReportMeta, type ReportRevision } from "./reportMeta.js";
import { deriveGlossary } from "./glossary.js";
import { buildAssetGraph, type AssetGraph } from "../analysis/assetGraph.js";
import { buildEvidenceGraph } from "../analysis/evidenceGraph.js";
import { buildAttackPhases, DEFAULT_GAP_SECONDS } from "../analysis/burstDetect.js";
import { detectBeacons, beaconEnvOptions, BEACON_CAVEAT } from "../analysis/beaconDetect.js";
import { buildGeoMap } from "../analysis/geoMap.js";
import { detectTimelineGaps, gapEnvOptions, GAP_CAVEAT } from "../analysis/gapDetect.js";
import { detectTimelineAnomalies, anomalyEnvOptions } from "../analysis/timelineAnomalies.js";
import { deriveIocSources } from "../analysis/iocCorroboration.js";
import { attackTechniqueMd } from "../analysis/attack.js";
import { buildAdversaryHintsResult } from "../analysis/adversaryHints.js";
import { ADVERSARY_EMULATION_CAVEAT } from "../analysis/adversaryEmulation.js";
import { loadAdversaryGroupsDataset, adversaryHintEnvOptions } from "../analysis/adversaryGroupsData.js";
import { buildD3fendResult, D3FEND_ACTION_INFO } from "../analysis/d3fendMap.js";
import { loadD3fendDataset, d3fendEnvOptions } from "../analysis/d3fendData.js";
import { buildMitigationsResult } from "../analysis/attackMitigations.js";
import { loadMitigationsDataset } from "../analysis/attackMitigationsData.js";
import { hasExposureFinding, type CustomerExposureSummary } from "../analysis/customerExposure.js";
import { extractCveIds, matchKevEntries, type KevCatalog } from "../analysis/kev.js";
import type { NotebookEntry } from "../analysis/notebookStore.js";
import type { Hypothesis } from "../analysis/hypothesis.js";
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

// 3.3 — timeline coverage: suspiciously long silent periods in the forensic timeline. A COMPLETE gap
// (every source dark) is the classic signature of cleared logs / a stopped collector; a PARTIAL gap is
// a single-tool coverage blindspot. Deterministic, no AI — a lead, not proof of tampering. Thresholds:
// DFIR_GAP_MIN_MINUTES / DFIR_GAP_DENSITY_FACTOR / DFIR_GAP_ACTIVE_HOURS.
function timelineCoverage(state: InvestigationState, lines: string[]): void {
  lines.push("### 3.3 Timeline coverage", "");
  lines.push(`_${GAP_CAVEAT}_`, "");
  const gaps = detectTimelineGaps(state.forensicTimeline, gapEnvOptions());
  if (gaps.length === 0) {
    lines.push("_No suspicious silent periods detected in the forensic timeline._", "");
    return;
  }
  lines.push("| Severity | Gap | Duration | Silent sources | Still active |", "| --- | --- | --- | --- | --- |");
  for (const g of gaps) {
    const kind = g.complete ? "complete silence" : "partial";
    const silent = g.silentSources.length ? g.silentSources.join(", ") : "all sources";
    const active = g.activeSources.length ? g.activeSources.join(", ") : "—";
    lines.push(
      `| ${g.severity} (${kind}) | ${cellMd(`${g.startTimestamp} → ${g.endTimestamp}`)} | ${cellMd(g.durationLabel)} | ` +
      `${cellMd(silent)} | ${cellMd(active)} |`,
    );
  }
  lines.push("");
}

// 3.4 — timeline anomalies: per-asset event-rate spikes relative to the per-bucket median across all
// assets. Flags the "host that went crazy" signal in large timelines. Deterministic, no AI. Thresholds:
// DFIR_ANOMALY_BUCKET_MINUTES / DFIR_ANOMALY_SPIKE_FACTOR / DFIR_ANOMALY_MIN_EVENTS.
function timelineAnomalies(state: InvestigationState, lines: string[]): void {
  lines.push("### 3.4 Timeline anomalies", "");
  lines.push(
    "_Per-asset event-rate spikes, two baselines: **peer** = an asset far busier than other assets in the same bucket; **self** = an asset bursting above its own typical rate. A lead, not proof — verify each anomaly against the raw timeline._",
    "",
  );
  const result = detectTimelineAnomalies(state.forensicTimeline, anomalyEnvOptions());
  if (result.anomalies.length === 0) {
    lines.push(
      result.assetCount < 2
        ? `_No event-rate spikes detected (only ${result.assetCount} asset; bucket ${result.bucketMinutes} min, peer ${result.spikeFactor}× / self ${result.selfFactor}×)._`
        : `_No event-rate spikes detected (bucket ${result.bucketMinutes} min, peer ${result.spikeFactor}× / self ${result.selfFactor}×)._`,
      "",
    );
    return;
  }
  lines.push("| Severity | Asset | Type | Bucket | Events | Baseline | Ratio |", "| --- | --- | --- | --- | --- | --- | --- |");
  for (const a of result.anomalies) {
    const window = `${a.bucketStart} → ${a.bucketEnd}`;
    lines.push(
      `| ${a.severity} | ${cellMd(a.asset)} | ${a.methods.join(" + ")} | ${cellMd(window)} | ${a.eventCount} | ${a.medianCount} | ${a.ratio}× |`,
    );
  }
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

  // Emulation (#121): from those matched groups, the techniques the case hasn't observed yet —
  // predictive hunt priorities. Only rendered when at least one group matched.
  if (result.nextTechniques.length > 0) {
    lines.push(
      "**Likely next techniques (hunt priorities).** Techniques the matched groups above are known " +
        "to use that this case has not yet observed, ranked by **distinctiveness** — how many matched " +
        "groups use each weighted by how rare it is across all known groups, so generic tradecraft " +
        "(recon, tooling) is filtered out. The _global %_ is how many of all known groups use it " +
        "(lower = more distinctive to this actor profile).",
      "",
      `_${ADVERSARY_EMULATION_CAVEAT}_`,
      "",
      "| Technique | Tactic | Global % | Matched groups |",
      "| --- | --- | --- | --- |",
    );
    for (const n of result.nextTechniques) {
      const used = `${n.groupCount} — ${n.groups.map((g) => `${g.id} ${g.name}`).join(", ")}`;
      const pct = `${Math.round(n.prevalence * 100)}%`;
      const tech = attackTechniqueMd(n.id) + (n.name ? ` — ${n.name}` : "");
      lines.push(`| ${cellMd(tech)} | ${cellMd(n.tactic)} | ${pct} | ${cellMd(used)} |`);
    }
    lines.push("");
  }
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
  // Show only rows where a provider actually found something — clean "checked, no breach"
  // rows are dropped (the providers/targets lines above already record what was checked).
  const found = exposure.results.filter(hasExposureFinding);
  if (found.length === 0) {
    lines.push("_No customer exposures found._", "");
  } else {
    lines.push("| Provider | Target | Email | Breach/source | Date | Data |", "| --- | --- | --- | --- | --- | --- |");
    for (const r of found) {
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

// Scan the forensic timeline events and Shodan exposure CVEs against the KEV catalog.
// Returns CVE ids found in the case data that CISA confirms are actively exploited.
function gatherCaseCveIds(state: InvestigationState, exposure?: CustomerExposureSummary): string[] {
  const ids = new Set<string>();
  for (const e of state.forensicTimeline) extractCveIds(e.description).forEach((id) => ids.add(id));
  for (const ioc of state.iocs) extractCveIds(ioc.value).forEach((id) => ids.add(id));
  // Shodan exposure: CVEs come through as "vuln:CVE-xxxx-xxxx" in exposedData.
  if (exposure) {
    for (const r of exposure.results) {
      for (const d of r.exposedData ?? []) extractCveIds(d).forEach((id) => ids.add(id));
    }
  }
  return [...ids];
}

function kevCorrelation(state: InvestigationState, exposure: CustomerExposureSummary | undefined, catalog: KevCatalog, lines: string[]): void {
  lines.push("### 4.5.1 CISA KEV correlation", "");
  if (!catalog.size) {
    lines.push("_KEV catalog not loaded — go to Settings → KEV to load the CISA Known Exploited Vulnerabilities feed._", "");
    return;
  }
  const cveIds = gatherCaseCveIds(state, exposure);
  const matches = matchKevEntries(cveIds, catalog);
  if (matches.length === 0) {
    lines.push("_No CVEs found in this case match the CISA Known Exploited Vulnerabilities catalog._", "");
    return;
  }
  lines.push(
    `**${matches.length} CVE(s) in this case match the CISA KEV catalog — actively exploited in the wild.**`,
    "",
    "| CVE | Vendor / Product | Vulnerability | Date added | Ransomware | Remediation |",
    "| --- | --- | --- | --- | --- | --- |",
  );
  for (const e of matches) {
    const ransomware = e.knownRansomwareCampaignUse === "Known" ? "**Yes**" : "No";
    lines.push(
      `| ${cellMd(e.cveID)} | ${cellMd(`${e.vendorProject} ${e.product}`)} | ${cellMd(e.vulnerabilityName)} | ${cellMd(e.dateAdded)} | ${ransomware} | ${cellMd(e.requiredAction)} |`,
    );
  }
  lines.push("");
}

function investigation(state: InvestigationState, lines: string[], exposure?: CustomerExposureSummary, prebuiltGraph?: AssetGraph, kevCatalog?: KevCatalog): void {
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
    // Citations (#222): which events each finding cites as its supporting evidence. Prefer the
    // finding's own relatedEventIds (set by synthesis); fall back to the reverse relatedFindingIds
    // link on the events themselves for findings persisted before that field existed.
    const eventsByFinding = new Map<string, ForensicEvent[]>();
    for (const e of state.forensicTimeline) {
      for (const fid of e.relatedFindingIds) {
        const arr = eventsByFinding.get(fid) ?? [];
        arr.push(e);
        eventsByFinding.set(fid, arr);
      }
    }
    const eventById = new Map(state.forensicTimeline.map((e) => [e.id, e] as const));
    for (const f of sorted) {
      const confLabel = f.confidence !== undefined ? ` [${f.confidence}% confidence]` : "";
      lines.push(`#### [${f.severity}]${confLabel} ${f.title} (${f.id})`);
      lines.push(f.description || "_no description_");
      if (f.relatedIocs.length) lines.push(`- IOCs: ${f.relatedIocs.join(", ")}`);
      if (f.mitreTechniques.length) lines.push(`- MITRE: ${f.mitreTechniques.map(attackTechniqueMd).join(", ")}`);
      if (f.sourceScreenshots.length) lines.push(`- Evidence: ${f.sourceScreenshots.join(", ")}`);
      const citedIds = (f.relatedEventIds && f.relatedEventIds.length) ? f.relatedEventIds : (eventsByFinding.get(f.id) ?? []).map((e) => e.id);
      if (citedIds.length) {
        lines.push(`- Cited events: ${citedIds.map((id, i) => `[${i + 1}] ${cellMd(id)}`).join(", ")}`);
        for (const [i, id] of citedIds.entries()) {
          const ev = eventById.get(id);
          if (ev) lines.push(`  - [${i + 1}] ${ev.timestamp || "(undated)"} [${ev.severity}] ${cellMd(ev.description.slice(0, 200))}`);
        }
      }
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
  if (kevCatalog) kevCorrelation(state, exposure, kevCatalog, lines);

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
      // A ⚠️ contradiction badge (investigation-guidance #3): the negative answer conflicts with
      // ATT&CK-tagged events in the timeline — surface it so a wrong "no" is never read as settled.
      const contra = q.contradicted?.techniques?.length
        ? ` ⚠️ contradicted by timeline (${q.contradicted.techniques.join(", ")})`
        : "";
      const answerCell = (q.answer || "_unknown_") + contra;
      lines.push(`| ${mark(q.status)} | ${cellMd(q.question)} | ${cellMd(answerCell)} | ${cellMd(q.pointer || "—")} |`);
    }
    lines.push("");
  }

  chainOfEvidence(state, lines);
  beaconCandidates(state, lines);
  geographicDistribution(state, lines);
}

// 4.9 Beacon candidates — outbound connection channels (source host → destination IP:port) whose
// inter-arrival intervals are too regular to be human traffic, the classic C2 callback signature.
// Derived from the forensic timeline's network events; a hunting lead, NOT a verdict (legitimate
// software also polls on a timer). Thresholds: DFIR_BEACON_MIN_COUNT / DFIR_BEACON_MAX_JITTER_PCT.
function beaconCandidates(state: InvestigationState, lines: string[]): void {
  lines.push("### 4.9 Beacon candidates", "");
  lines.push(`_${BEACON_CAVEAT}_`, "");
  const beacons = detectBeacons(state.forensicTimeline, beaconEnvOptions());
  if (beacons.length === 0) {
    lines.push("_No periodic outbound channels detected in the network events._", "");
    return;
  }
  lines.push(
    "| Severity | Source | Destination | Interval | Jitter | Events | When |",
    "| --- | --- | --- | --- | --- | --- | --- |",
  );
  for (const b of beacons) {
    const dest = b.destPort !== undefined ? `${b.destIp}:${b.destPort}` : b.destIp;
    const when = b.firstSeen !== b.lastSeen ? `${b.firstSeen} → ${b.lastSeen}` : b.firstSeen;
    lines.push(
      `| ${b.severity}${b.external ? " (external)" : ""} | ${cellMd(b.source)} | ${cellMd(dest)} | ` +
        `~${b.intervalSeconds}s | ±${b.jitterSeconds}s (${b.jitterPct}%) | ${b.eventCount} | ${cellMd(when)} |`,
    );
  }
  lines.push("");
}

// §4.10 Geographic distribution (#133): a textual companion to the dashboard's interactive map —
// top countries and a per-IP table. Always rendered (placeholder when empty) so section numbering
// stays stable. The live map lives in the dashboard; the report carries the data.
function geographicDistribution(state: InvestigationState, lines: string[]): void {
  lines.push("### 4.10 Geographic distribution", "");
  const geo = buildGeoMap(state);
  if (geo.markers.length === 0) {
    lines.push("_No geo-located IP addresses — enrich IP IOCs with the GeoIP provider to populate this._", "");
    return;
  }
  const s = geo.stats;
  lines.push(
    `${s.resolved} of ${s.totalIps} IP indicator(s) geo-located across ${s.distinctCountries} ` +
      `countr${s.distinctCountries === 1 ? "y" : "ies"} (${s.external} external, ${s.internal} internal).`,
    "",
  );
  if (geo.countries.length > 0) {
    lines.push("**Top countries.**", "", "| Country | IPs | Worst severity |", "| --- | --- | --- |");
    for (const c of geo.countries) lines.push(`| ${cellMd(c.country)} | ${c.count} | ${c.severity} |`);
    lines.push("");
  }
  lines.push("| IP | Country | City | ASN | Severity | Verdict |", "| --- | --- | --- | --- | --- | --- |");
  for (const m of geo.markers) {
    lines.push(
      `| ${cellMd(m.ip)} | ${cellMd(m.country ?? "—")} | ${cellMd(m.city ?? (m.approximate ? "— (country-level)" : "—"))} | ` +
        `${cellMd(m.asn ?? "—")} | ${m.severity}${m.falsePositive ? " (false positive)" : ""} | ${cellMd(m.verdict ?? "—")} |`,
    );
  }
  lines.push("");
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

// ATT&CK Mitigations (#178) — the actionable layer: the concrete mitigations MITRE ATT&CK
// recommends for the case's techniques, ranked by how many techniques each addresses (so the
// highest-leverage actions lead), each with its technique-specific detail. Offline (no AI).
function mitigationsReportBlock(state: InvestigationState, lines: string[]): void {
  lines.push("### Recommended mitigations (MITRE ATT&CK)", "");
  const result = buildMitigationsResult(state, loadMitigationsDataset());
  lines.push(`_${result.note}_`, "");
  if (!result.mitigationCount) {
    lines.push("_ATT&CK mitigations not available — run `npm run data:update-attack-mitigations`._", "");
    return;
  }
  if (!result.coveredTechniqueCount) {
    lines.push("_No identified technique has a mapped ATT&CK mitigation yet._", "");
    return;
  }
  lines.push(
    `${result.byMitigation.length} mitigation(s) cover ${result.coveredTechniqueCount} of ` +
      `${result.caseTechniqueCount} identified technique(s) (MITRE ATT&CK v${result.attackVersion}), ` +
      `ordered by how many of this case's techniques each one addresses — start at the top.`,
    "",
  );
  // Top-leverage mitigations: the general action, then per-technique specifics.
  for (const m of result.byMitigation) {
    lines.push(`#### [${m.id} · ${m.name}](${m.url}) — covers ${m.techniques.length} technique(s)`, "");
    if (m.description) lines.push(m.description, "");
    const tech = result.techniques.find((t) => t.mitigations.some((x) => x.id === m.id));
    const detail = tech?.mitigations.find((x) => x.id === m.id)?.detail;
    if (detail && detail !== m.description) lines.push(`_Specifics:_ ${detail}`, "");
    lines.push(`_Applies to:_ ${m.techniques.join(", ")}`, "");
  }
}

// Defensive countermeasures (#178) — for each identified ATT&CK technique, the MITRE D3FEND
// countermeasures that harden against / detect / isolate it. Offline + deterministic (no AI),
// resolved from the bundled D3FEND mapping. Turns the incident's technique list into concrete
// hardening guidance for the defensive team — a toggleable appendix section.
function d3fendSection(state: InvestigationState, lines: string[]): void {
  lines.push("## Mitigation & defensive countermeasures", "");
  // The actionable layer first: concrete ATT&CK mitigations ranked by coverage.
  mitigationsReportBlock(state, lines);
  // Then the D3FEND defensive-technique catalog (sensors / hardening categories).
  lines.push("### Defensive techniques & sensors (D3FEND)", "");
  const result = buildD3fendResult(state, loadD3fendDataset(), d3fendEnvOptions());
  lines.push(`_${result.note}_`, "");
  if (!result.mappedTechniqueCount) {
    lines.push("_D3FEND mapping not available — run `npm run data:update-d3fend`._", "");
    return;
  }
  if (!result.caseTechniqueCount) {
    lines.push("_No techniques identified yet — countermeasures need at least one ATT&CK technique._", "");
    return;
  }
  if (!result.coveredTechniqueCount) {
    lines.push(
      `_None of the case's ${result.caseTechniqueCount} identified technique(s) have a D3FEND countermeasure mapping._`,
      "",
    );
    return;
  }
  lines.push(
    `Countermeasures for ${result.coveredTechniqueCount} of ${result.caseTechniqueCount} identified ` +
      `technique(s), from MITRE D3FEND v${result.d3fendVersion}. Grouped by defensive action, in two ` +
      `bands: the **hardening to implement now** (Prevent / Detect / Contain), then **this-incident ` +
      `response and prerequisite context** (Evict / Restore / Model / Deceive). Each countermeasure ` +
      `is glossed in plain English and lists the case technique(s) it addresses.`,
    "",
  );

  // One sub-block per defensive action: a plain-language heading + the concrete "what to do", then the
  // countermeasures (each with its D3FEND definition inline, since a report can't hover) + coverage.
  const renderAction = (g: (typeof result.byTactic)[number]): void => {
    const info = D3FEND_ACTION_INFO[g.tactic];
    const heading = info ? `${info.label} — ${info.blurb}` : g.tactic;
    lines.push(`#### ${heading}`, "");
    if (info?.guidance) lines.push(`_${info.guidance}_`, "");
    for (const c of g.countermeasures) {
      const gloss = c.definition ? ` — ${c.definition}` : "";
      lines.push(`- [${c.name}](${c.url})${gloss} _(covers ${c.techniques.join(", ")})_`);
    }
    lines.push("");
  };

  // Split the actions into the two bands (by D3FEND tier), preserving a sensible order within each.
  const BAND1 = ["Harden", "Detect", "Isolate"];
  const BAND2 = ["Evict", "Restore", "Model", "Deceive"];
  const ordIdx = (arr: string[], t: string): number => (arr.indexOf(t) < 0 ? 99 : arr.indexOf(t));
  const band1 = result.byTactic.filter((g) => BAND1.includes(g.tactic)).sort((a, b) => ordIdx(BAND1, a.tactic) - ordIdx(BAND1, b.tactic));
  const band2 = result.byTactic.filter((g) => !BAND1.includes(g.tactic)).sort((a, b) => ordIdx(BAND2, a.tactic) - ordIdx(BAND2, b.tactic));

  if (band1.length) {
    lines.push("### Harden now — implement these", "");
    band1.forEach(renderAction);
  }
  if (band2.length) {
    lines.push("### This incident & context", "");
    band2.forEach(renderAction);
  }
}

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

function hypothesesSection(hypotheses: Hypothesis[], lines: string[]): void {
  lines.push("## Hypotheses", "");
  lines.push(
    "_What we investigated and concluded. Each hypothesis is a testable claim about the incident, " +
    "tracked from open to supported / refuted / unknown — a lead to test, not a verdict._",
    "",
  );
  const STATUS_LABEL: Record<Hypothesis["status"], string> = {
    supported: "Supported", refuted: "Refuted", open: "Open", unknown: "Unknown",
  };
  // Concluded hypotheses first (supported, then refuted), then the outstanding ones (open, unknown).
  const order: Hypothesis["status"][] = ["supported", "refuted", "open", "unknown"];
  const sorted = [...hypotheses].sort((a, b) => order.indexOf(a.status) - order.indexOf(b.status));
  for (const h of sorted) {
    lines.push(`### ${h.title} — ${STATUS_LABEL[h.status] ?? h.status}`, "");
    if (h.description) lines.push(h.description, "");
    if (h.expectedOutcome) lines.push(`**Expected outcome (what would prove or disprove this):** ${h.expectedOutcome}`, "");
    const bits: string[] = [];
    if (h.relatedTechniques.length) bits.push(`ATT&CK: ${h.relatedTechniques.join(", ")}`);
    if (h.relatedEventIds.length) bits.push(`${h.relatedEventIds.length} supporting event${h.relatedEventIds.length === 1 ? "" : "s"}`);
    if (h.relatedIocIds.length) bits.push(`${h.relatedIocIds.length} related IOC${h.relatedIocIds.length === 1 ? "" : "s"}`);
    if (bits.length) lines.push(`_${bits.join(" · ")}._`, "");
    if (h.notes) lines.push(`**Analyst notes:** ${h.notes}`, "");
  }
}

function analystNotebook(entries: NotebookEntry[], lines: string[]): void {
  lines.push("## Analyst Notebook", "");
  lines.push("_Investigator working notes and open questions recorded during the investigation. Tracked hypotheses are in the Hypotheses section._", "");
  if (!entries.length) {
    lines.push("_(no notebook entries)_", "");
    return;
  }
  const TYPE_LABEL: Record<NotebookEntry["type"], string> = {
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
  kevCatalog?: KevCatalog,
  hypotheses?: Hypothesis[],
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
      timelineCoverage(state, lines);
      timelineAnomalies(state, lines);
    },
    investigation: () => investigation(state, lines, exposure, assetGraph, kevCatalog),
    conclusions: () => conclusions(state, meta, lines),
    hypotheses: () => {
      if (hypotheses && hypotheses.length > 0) hypothesesSection(hypotheses, lines);
    },
    playbook: () => {
      if (playbookTasks && playbookTasks.length > 0) playbookSection(playbookTasks, lines);
    },
    d3fend: () => d3fendSection(state, lines),
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
