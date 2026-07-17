import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";
import type { StateStore } from "../analysis/stateStore.js";
import { NO_SCOPE, type ScopeStore } from "../analysis/scope.js";
import { projectScope } from "../analysis/scopeProject.js";
import { applyFalsePositive, filterFalsePositiveEvents, type FalsePositiveStore } from "../analysis/falsePositive.js";
import { renderMarkdownReport } from "./markdown.js";
import { renderHtmlReport } from "./html.js";
import { renderDocxReport } from "./docx.js";
import { emptyReportMeta, type ReportMetaStore } from "./reportMeta.js";
import { findingsCsv, iocsCsv, timelineCsv, forensicTimelineCsv, geoMapCsv } from "./csv.js";
import { buildAttackLayer, type NavigatorLayer } from "./attackLayer.js";
import { toTimesketchJsonl } from "../integrations/timesketch/timesketchMap.js";
import { buildAssetGraph, type AssetGraph, type TimeWindow } from "../analysis/assetGraph.js";
import { buildEvidenceGraph, type EvidenceGraph } from "../analysis/evidenceGraph.js";
import { buildAttackPhases, DEFAULT_GAP_SECONDS, type AttackPhase } from "../analysis/burstDetect.js";
import { detectBeacons, beaconEnvOptions, type BeaconCandidate } from "../analysis/beaconDetect.js";
import { detectTimelineGaps, gapEnvOptions, type TimelineGap } from "../analysis/gapDetect.js";
import { buildSwimlaneData, type SwimlaneData, type SwimlaneGroupBy } from "../analysis/swimlane.js";
import { deriveIocSources } from "../analysis/iocCorroboration.js";
import { buildAdversaryHintsResult, type AdversaryHintsResult } from "../analysis/adversaryHints.js";
import { rankHosts, type HostRankingResult } from "../analysis/hostRanking.js";
import { buildMobileSummary, mobileSummaryEnvOptions, type MobileCaseSummary } from "../analysis/mobileSummary.js";
import {
  buildPresentationDeck,
  presentationEnvOptions,
  type PresentationBranding,
  type PresentationDeck,
} from "../analysis/presentation.js";
import { buildGeoMap, geoMapEnvOptions, type GeoMapData } from "../analysis/geoMap.js";
import { detectTimelineAnomalies, anomalyEnvOptions, type TimelineAnomalyResult } from "../analysis/timelineAnomalies.js";
import { loadAdversaryGroupsDataset, adversaryHintEnvOptions } from "../analysis/adversaryGroupsData.js";
import { buildD3fendResult, type D3fendResult } from "../analysis/d3fendMap.js";
import { loadD3fendDataset, d3fendEnvOptions } from "../analysis/d3fendData.js";
import { buildMitigationsResult, type MitigationsResult } from "../analysis/attackMitigations.js";
import { loadMitigationsDataset } from "../analysis/attackMitigationsData.js";
import { buildStixBundle, type StixBundle } from "./stix.js";
import {
  buildIocBlocklistTxt,
  buildIocBlocklistCsv,
  buildIocBlocklistStix,
  type IocBlocklistFormat,
  type IocBlocklistOptions,
} from "./iocBlocklist.js";
import type { InvestigationState, Severity } from "../analysis/stateTypes.js";
import { CustomerExposureStore, type CustomerExposureSummary } from "../analysis/customerExposure.js";
import type { NotebookStore, NotebookEntry } from "../analysis/notebookStore.js";
import type { HypothesisStore } from "../analysis/hypothesisStore.js";
import type { Hypothesis } from "../analysis/hypothesis.js";
import type { SynthMetaStore, SynthesisCoverage } from "../analysis/synthMeta.js";
import type { PlaybookStore } from "../analysis/playbookStore.js";
import type { PlaybookTask } from "../analysis/playbook.js";
import { AssetOverridesStore, applyAssetOverrides, emptyOverrides } from "../analysis/assetOverrides.js";
import { buildBrandingContext, defaultReportTemplate, renderTemplateString, type ReportTemplate } from "./reportTemplate.js";
import type { ReportTemplateStore } from "./reportTemplateStore.js";
import type { ReportTemplateControlStore } from "./reportTemplateControl.js";
import { applyAnonDeep, type RedactedReportContents } from "../analysis/redactedExport.js";
import type { ReportMeta } from "./reportMeta.js";
import type { KevStore } from "../analysis/kevStore.js";
import type { KevCatalog } from "../analysis/kev.js";
import type { ReportVersionStore } from "./reportVersionStore.js";

export interface ReportPaths {
  markdown: string;
  html: string;
  findingsCsv: string;
  iocsCsv: string;
  timelineCsv: string;
  forensicTimelineCsv: string;
  stateJson: string;
}

export class ReportWriter {
  constructor(
    private readonly cases: CaseStore,
    private readonly state: StateStore,
    private readonly scope?: ScopeStore,
    private readonly falsePositives?: FalsePositiveStore,
    private readonly reportMeta?: ReportMetaStore,
    private readonly customerExposure?: CustomerExposureStore,
    private readonly notebook?: NotebookStore,
    private readonly assetOverrides?: AssetOverridesStore,
    private readonly playbook?: PlaybookStore,
    private readonly reportTemplates?: ReportTemplateStore,
    private readonly reportTemplateControl?: ReportTemplateControlStore,
    private readonly kevStore?: KevStore,
    private readonly hypothesisStore?: HypothesisStore,
    private readonly synthMeta?: SynthMetaStore,   // #11 deferred: second-look collection leads in the report
    private readonly reportVersions?: ReportVersionStore,   // #77 report versioning (diff & rollback)
  ) {}

  // Second-look collection leads (investigation-guidance #11, deferred): requests the raw re-query made
  // that matched NOTHING — each an actionable "collect this next" gap. Lives in synth-meta, not state, so
  // it's loaded here on demand for the report. [] when unavailable.
  private async loadSecondLookLeads(caseId: string): Promise<string[]> {
    if (!this.synthMeta) return [];
    try { return (await this.synthMeta.load(caseId)).secondLook?.leads ?? []; } catch { return []; }
  }

  // Synthesis coverage footnote (#62) — OPT-IN via DFIR_REPORT_SYNTH_COVERAGE. Off by default (the
  // footnote adds internal methodology detail not every report should carry); returns null unless the
  // flag is truthy and a coverage snapshot was recorded on the last run.
  private async loadCoverage(caseId: string): Promise<SynthesisCoverage | null> {
    const flag = (process.env.DFIR_REPORT_SYNTH_COVERAGE ?? "").trim().toLowerCase();
    if (!this.synthMeta || flag === "" || flag === "0" || flag === "false" || flag === "off") return null;
    try { return (await this.synthMeta.load(caseId)).coverage ?? null; } catch { return null; }
  }

  // Resolve the report template selected for the case (issue #60). Falls back to the default
  // "standard" template when no selection is stored, the stores aren't wired, or the selected
  // template was since deleted — so report generation never breaks on a dangling id.
  private async loadTemplate(caseId: string): Promise<ReportTemplate> {
    if (!this.reportTemplates || !this.reportTemplateControl) return defaultReportTemplate();
    const { templateId } = await this.reportTemplateControl.load(caseId);
    const tpl = await this.reportTemplates.get(templateId);
    return tpl ?? defaultReportTemplate();
  }

  // Load the case state with the same deterministic report filters applied: drop
  // out-of-scope events (and the findings/IOCs/MITRE supported only by them) and exclude
  // client-confirmed false-positive items — so every export is scope/false-positive-consistent
  // even if AI re-synthesis hasn't run. Shared by the full report and single-section exports.
  private async loadFilteredState(caseId: string): Promise<InvestigationState> {
    const loaded = await this.state.load(caseId);
    const scoped = projectScope(loaded, this.scope ? await this.scope.load(caseId) : NO_SCOPE);
    const markers = this.falsePositives ? await this.falsePositives.load(caseId) : [];
    return applyFalsePositive(
      { ...scoped, forensicTimeline: filterFalsePositiveEvents(scoped.forensicTimeline, markers) },
      markers,
    );
  }

  private async loadNotebook(caseId: string): Promise<NotebookEntry[] | undefined> {
    if (!this.notebook) return undefined;
    const entries = await this.notebook.load(caseId);
    return entries.length ? entries : undefined;
  }

  private async loadPlaybook(caseId: string): Promise<PlaybookTask[] | undefined> {
    if (!this.playbook) return undefined;
    const tasks = await this.playbook.load(caseId);
    return tasks.length ? tasks : undefined;
  }

  private async loadHypotheses(caseId: string): Promise<Hypothesis[] | undefined> {
    if (!this.hypothesisStore) return undefined;
    const list = await this.hypothesisStore.load(caseId);
    return list.length ? list : undefined;
  }

  // Build the Word (.docx) export on demand. Uses the same scope/legitimate filtering as
  // the canonical report so the .docx matches report.md and report.html exactly. NOT added
  // to writeAll: the .docx is a snapshot deliverable, and writing a binary into the
  // (often-Dropbox-synced) cases/ folder on every report regeneration causes sync churn.
  async docx(caseId: string): Promise<Buffer> {
    const state = await this.loadFilteredState(caseId);
    const meta = this.reportMeta ? await this.reportMeta.load(caseId) : emptyReportMeta();
    return renderDocxReport(state, meta, await this.loadExposure(caseId), await this.loadTemplate(caseId));
  }

  private async loadExposure(caseId: string): Promise<CustomerExposureSummary | undefined> {
    if (!this.customerExposure) return undefined;
    const exposure = await this.customerExposure.load(caseId);
    return exposure.checkedAt ? exposure : undefined;
  }

  private async loadKevCatalog(): Promise<KevCatalog | undefined> {
    if (!this.kevStore) return undefined;
    const catalog = await this.kevStore.loadCatalog();
    return catalog.size > 0 ? catalog : undefined;
  }

  // Export just the incident (forensic) timeline as CSV, on demand — without writing the
  // full report. Uses the same scope/legitimate filtering so it matches the report's 3.1.
  async incidentTimelineCsv(caseId: string): Promise<string> {
    return forensicTimelineCsv(await this.loadFilteredState(caseId));
  }

  // Build a MITRE ATT&CK Navigator layer for the case (same scope/legitimate filtering as the
  // report) — the JSON drops straight into the Navigator's "Open Existing Layer" upload. The
  // stamped ATT&CK version follows DFIR_ATTACK_VERSION (default DEFAULT_ATTACK_VERSION) so a new
  // ATT&CK release doesn't make the Navigator prompt to upgrade every exported layer.
  async attackLayer(caseId: string): Promise<NavigatorLayer> {
    const attackVersion = process.env.DFIR_ATTACK_VERSION?.trim() || undefined;
    return buildAttackLayer(await this.loadFilteredState(caseId), attackVersion ? { attackVersion } : {});
  }

  // Export the forensic timeline as Timesketch-compatible JSONL (same scope/legitimate filtering).
  // Used by the "Export Timesketch JSONL" download and as the payload for the Timesketch push.
  async timesketchJsonl(caseId: string): Promise<string> {
    return toTimesketchJsonl(await this.loadFilteredState(caseId));
  }

  // The case state with the report's scope/legitimate filters applied — so the Timesketch push
  // uploads exactly the timeline the report (and the JSONL export) show.
  async filteredState(caseId: string): Promise<InvestigationState> {
    return this.loadFilteredState(caseId);
  }

  // The asset ↔ IoC graph for the case (same scope/legitimate filtering as the report),
  // with any analyst overrides (renames, additions, suppressions) applied on top. An optional
  // time `window` (#83) further narrows the graph to events in that range before overrides apply.
  async assetGraph(caseId: string, window?: TimeWindow): Promise<AssetGraph> {
    const state = await this.loadFilteredState(caseId);
    const graph = buildAssetGraph(state, window);
    const overrides = this.assetOverrides ? await this.assetOverrides.load(caseId) : emptyOverrides();
    return applyAssetOverrides(graph, overrides);
  }

  // The causal evidence chain graph (process trees + lateral movement) for the case, derived on
  // demand with the same scope/legitimate filtering as the report. An optional time `window` (#83)
  // narrows it to events in that range.
  async evidenceGraph(caseId: string, window?: TimeWindow): Promise<EvidenceGraph> {
    return buildEvidenceGraph(await this.loadFilteredState(caseId), window);
  }

  // Temporal attack phases (bursts of activity grouped by time gap) for the case, derived on
  // demand with the same scope/legitimate filtering as the report. The burst gap threshold is
  // configurable via DFIR_PHASE_GAP_S (seconds; default 5 min).
  async phases(caseId: string): Promise<AttackPhase[]> {
    const state = await this.loadFilteredState(caseId);
    const gapSeconds = Number(process.env.DFIR_PHASE_GAP_S) || DEFAULT_GAP_SECONDS;
    return buildAttackPhases(state.forensicTimeline, { gapSeconds });
  }

  // Beacon / C2 candidates (#82): outbound connection channels whose inter-arrival intervals are too
  // regular to be human traffic, derived on demand with the same scope/legitimate filtering as the
  // report. Thresholds from DFIR_BEACON_MIN_COUNT / DFIR_BEACON_MAX_JITTER_PCT. No AI call.
  async beaconCandidates(caseId: string): Promise<BeaconCandidate[]> {
    const state = await this.loadFilteredState(caseId);
    return detectBeacons(state.forensicTimeline, beaconEnvOptions());
  }

  // Timeline gaps (#83): suspiciously long silent periods in the forensic timeline — a complete gap
  // (every source dark) is the classic log-tampering signature, a partial gap is a single-tool
  // coverage blindspot. Derived on demand with the same scope/legitimate filtering as the report.
  // Thresholds from DFIR_GAP_MIN_MINUTES / DFIR_GAP_DENSITY_FACTOR / DFIR_GAP_ACTIVE_HOURS. No AI call.
  async timelineGaps(caseId: string): Promise<TimelineGap[]> {
    const state = await this.loadFilteredState(caseId);
    return detectTimelineGaps(state.forensicTimeline, gapEnvOptions());
  }

  // Timeline anomalies (#175): per-asset event-rate spikes relative to the per-bucket median.
  // Derived on demand with the same scope/legitimate filtering as the report. Thresholds from
  // DFIR_ANOMALY_BUCKET_MINUTES / DFIR_ANOMALY_SPIKE_FACTOR / DFIR_ANOMALY_MIN_EVENTS.
  async anomalies(caseId: string): Promise<TimelineAnomalyResult> {
    const state = await this.loadFilteredState(caseId);
    return detectTimelineAnomalies(state.forensicTimeline, anomalyEnvOptions());
  }

  // Swimlane data for the visual timeline chart — events grouped into lanes by the chosen
  // groupBy axis (asset | severity | tactic). Same scope/legitimate filtering as the report.
  async swimlane(caseId: string, groupBy: SwimlaneGroupBy = "asset"): Promise<SwimlaneData> {
    const state = await this.loadFilteredState(caseId);
    return buildSwimlaneData(state.forensicTimeline, groupBy);
  }

  // Per-IOC corroboration: iocId → distinct tools that observed the indicator (derived by matching
  // the IOC value against the forensic events' `sources`). Same scope/legitimate filtering as the
  // report. Powers the dashboard's "⊕ N sources" badge on IOCs.
  async iocSources(caseId: string): Promise<Record<string, string[]>> {
    const state = await this.loadFilteredState(caseId);
    return deriveIocSources(state.iocs, state.forensicTimeline);
  }

  // Adversary group hints (#46): rank known ATT&CK groups by how much their technique set overlaps
  // the case's identified techniques — offline hypothesis fuel, NOT attribution. Derived on demand
  // from the bundled dataset with the same scope/legitimate filtering as the report.
  async adversaryHints(caseId: string): Promise<AdversaryHintsResult> {
    const state = await this.loadFilteredState(caseId);
    return buildAdversaryHintsResult(state, loadAdversaryGroupsDataset(), adversaryHintEnvOptions());
  }

  // Suspicious host/account ranking (#202): score each entity by signal (not volume) so the analyst
  // sees which hosts carry the attack, plus a suggested auto-scope time window. Derived on read from
  // the same scope/legitimate-filtered state as the report.
  async hostRanking(caseId: string): Promise<HostRankingResult> {
    const state = await this.loadFilteredState(caseId);
    return rankHosts(state);
  }

  // D3FEND defensive countermeasures (#178): for each ATT&CK technique the case identified, the
  // bundled MITRE D3FEND mapping's hardening/detection/isolation countermeasures. Offline + derived
  // on read from the same scope/legitimate-filtered state, so the dashboard and report agree.
  async d3fendCountermeasures(caseId: string): Promise<D3fendResult> {
    const state = await this.loadFilteredState(caseId);
    return buildD3fendResult(state, loadD3fendDataset(), d3fendEnvOptions());
  }

  // ATT&CK Mitigations (#178): the concrete, actionable mitigations MITRE ATT&CK recommends for the
  // case's identified techniques, ranked by coverage. Offline + derived on read from the same
  // scope/legitimate-filtered state, so the dashboard and report agree.
  async attackMitigations(caseId: string): Promise<MitigationsResult> {
    const state = await this.loadFilteredState(caseId);
    return buildMitigationsResult(state, loadMitigationsDataset());
  }

  // Compact, READ-ONLY case summary for the mobile companion PWA (#59): case status, the worst
  // findings, the most severe/recent timeline events, and the IOC list with verdicts. Derived on
  // demand with the same scope/legitimate filtering as the report so the phone view agrees with
  // the desktop dashboard. Per-list caps come from DFIR_MOBILE_MAX_* (defaults in mobileSummary).
  async mobileSummary(caseId: string): Promise<MobileCaseSummary> {
    const state = await this.loadFilteredState(caseId);
    const meta = await this.cases.getCaseMeta(caseId);
    return buildMobileSummary(state, { ...mobileSummaryEnvOptions(), caseName: meta?.name });
  }

  // Presentation / timeline-replay deck (#177): a read-only, step-through slide deck for handoff
  // briefings and executive walkthroughs. Same scope/legitimate filtering as the report so the deck
  // agrees with the dashboard; branding (cover title/subtitle, accent, company name) is inherited
  // from the case's report template (issue #60). `minSeverity` lets the presenter floor the
  // findings/events shown (respecting the dashboard's severity filter). The deck is rendered by the
  // slide viewer (public/present.html) and embedded into the standalone-HTML export.
  async presentation(caseId: string, opts: { minSeverity?: Severity } = {}): Promise<PresentationDeck> {
    const state = await this.loadFilteredState(caseId);
    const caseMeta = await this.cases.getCaseMeta(caseId);
    const template = await this.loadTemplate(caseId);
    const reportMeta = this.reportMeta ? await this.reportMeta.load(caseId) : emptyReportMeta();
    const ctx = buildBrandingContext(state, reportMeta);
    const branding: PresentationBranding = {
      title: renderTemplateString(template.coverTitle, ctx).trim() || (caseMeta?.name ?? caseId),
      subtitle: renderTemplateString(template.coverSubtitle, ctx).trim(),
      accentColor: template.accentColor,
      companyName: template.showCompanyName ? reportMeta.companyName.trim() : "",
    };
    return buildPresentationDeck(state, {
      ...presentationEnvOptions(),
      branding,
      caseName: caseMeta?.name,
      generatedAt: new Date().toISOString(),
      minSeverity: opts.minSeverity,
    });
  }

  // Geographic IP map (#133): markers for the case's geo-located IP IOCs (derived on read).
  // Scope filter + false-positive-EVENT + false-positive-FINDING filters applied, but
  // false-positive IOCs are KEPT and rendered gray (so whitelisted infra still shows). This
  // prevents a false-positive Critical/High finding from inflating a whitelisted IP's severity
  // label on the map.
  async geoMap(caseId: string): Promise<GeoMapData> {
    const loaded = await this.state.load(caseId);
    const scoped = projectScope(loaded, this.scope ? await this.scope.load(caseId) : NO_SCOPE);
    const markers = this.falsePositives ? await this.falsePositives.load(caseId) : [];
    const falsePositiveValues = markers.filter((m) => m.kind === "ioc").map((m) => m.ref);
    // applyFalsePositive drops false-positive events (via the timeline we pass) + findings + IOCs.
    // We then RESTORE the scoped IOCs so whitelisted IPs still appear — rendered gray by
    // `falsePositiveValues` — instead of vanishing. (Their severity no longer reflects a
    // false-positive finding.)
    const filtered = applyFalsePositive(
      { ...scoped, forensicTimeline: filterFalsePositiveEvents(scoped.forensicTimeline, markers) },
      markers,
    );
    const state: InvestigationState = { ...filtered, iocs: scoped.iocs };
    return buildGeoMap(state, { ...geoMapEnvOptions(), falsePositiveValues });
  }

  async geoMapCsv(caseId: string): Promise<string> {
    return geoMapCsv(await this.geoMap(caseId));
  }

  // Build a clean IOC block-list for network/firewall teams (same scope/legitimate filtering as
  // the report). Supports three formats: plain text (one value per line, grouped by type),
  // minimal CSV (type, value, severity, verdict, description), and STIX-indicators-only
  // (a stripped-down STIX 2.1 bundle with only `indicator` objects — no identities, report,
  // or relationship objects). Severity is derived from the worst enrichment verdict.
  async iocBlocklist(
    caseId: string,
    format: IocBlocklistFormat = "txt",
    opts: IocBlocklistOptions = {},
  ): Promise<string | StixBundle> {
    const state = await this.loadFilteredState(caseId);
    const caseMeta = await this.cases.getCaseMeta(caseId);
    const resolvedOpts: IocBlocklistOptions = { ...opts, caseName: opts.caseName ?? caseMeta?.name };
    if (format === "csv") return buildIocBlocklistCsv(state, resolvedOpts);
    if (format === "stix") return buildIocBlocklistStix(state, resolvedOpts);
    return buildIocBlocklistTxt(state, resolvedOpts);
  }

  // Build a STIX 2.1 bundle for the case (same scope/legitimate filtering as the report) — the
  // portable, vendor-neutral export every TIP (OpenCTI, MISP, Anomali…) ingests. The victim
  // identity, producing firm, and incident id come from the human-authored report metadata.
  async stixBundle(caseId: string): Promise<StixBundle> {
    const state = await this.loadFilteredState(caseId);
    const meta = this.reportMeta ? await this.reportMeta.load(caseId) : emptyReportMeta();
    return buildStixBundle(state, {
      organization: meta.organization,
      producer: meta.companyName,
      incidentId: meta.incidentId,
    });
  }

  // Render every report artifact (as strings) from an already-loaded state + its metadata/graph.
  // Shared by writeAll (persists the REAL report) and redactedReportContents (renders an
  // anonymized copy in-memory) so both stay byte-for-byte consistent in structure.
  private renderContents(
    state: InvestigationState,
    meta: ReportMeta,
    exposure: CustomerExposureSummary | undefined,
    graph: AssetGraph,
    notebookEntries: NotebookEntry[] | undefined,
    playbookTasks: PlaybookTask[] | undefined,
    template: ReportTemplate = defaultReportTemplate(),
    kevCatalog?: KevCatalog,
    hypotheses?: Hypothesis[],
    secondLookLeads?: string[],
    coverage?: SynthesisCoverage | null,
  ): RedactedReportContents {
    return {
      markdown: renderMarkdownReport(state, meta, exposure, graph, notebookEntries, playbookTasks, template, kevCatalog, hypotheses, secondLookLeads, coverage),
      html: renderHtmlReport(state, meta, exposure, graph, notebookEntries, playbookTasks, template, hypotheses),
      findingsCsv: findingsCsv(state),
      iocsCsv: iocsCsv(state),
      timelineCsv: timelineCsv(state),
      forensicTimelineCsv: forensicTimelineCsv(state),
      stateJson: JSON.stringify(state, null, 2),
    };
  }

  async writeAll(caseId: string): Promise<ReportPaths> {
    const state = await this.loadFilteredState(caseId);
    const dir = this.cases.reportsDir(caseId);
    const paths: ReportPaths = {
      markdown: join(dir, "report.md"),
      html: join(dir, "report.html"),
      findingsCsv: join(dir, "findings.csv"),
      iocsCsv: join(dir, "iocs.csv"),
      timelineCsv: join(dir, "timeline.csv"),
      forensicTimelineCsv: join(dir, "forensic-timeline.csv"),
      stateJson: join(dir, "state-export.json"),
    };
    const meta = this.reportMeta ? await this.reportMeta.load(caseId) : emptyReportMeta();
    const exposure = await this.loadExposure(caseId);
    const notebookEntries = await this.loadNotebook(caseId);
    const playbookTasks = await this.loadPlaybook(caseId);
    const hypotheses = await this.loadHypotheses(caseId);
    const template = await this.loadTemplate(caseId);
    const overrides = this.assetOverrides ? await this.assetOverrides.load(caseId) : emptyOverrides();
    const graph = applyAssetOverrides(buildAssetGraph(state), overrides);
    const kevCatalog = await this.loadKevCatalog();
    const secondLookLeads = await this.loadSecondLookLeads(caseId);
    const coverage = await this.loadCoverage(caseId);
    const c = this.renderContents(state, meta, exposure, graph, notebookEntries, playbookTasks, template, kevCatalog, hypotheses, secondLookLeads, coverage);
    await writeFile(paths.markdown, c.markdown, "utf8");
    await writeFile(paths.html, c.html, "utf8");
    await writeFile(paths.findingsCsv, c.findingsCsv, "utf8");
    await writeFile(paths.iocsCsv, c.iocsCsv, "utf8");
    await writeFile(paths.timelineCsv, c.timelineCsv, "utf8");
    await writeFile(paths.forensicTimelineCsv, c.forensicTimelineCsv, "utf8");
    await writeFile(paths.stateJson, c.stateJson, "utf8");
    // #77 report versioning: snapshot markdown + meta + the diff-relevant slice of state so the
    // dashboard can diff two generations and roll back to a prior version's editable meta.
    // Best-effort — a version-store failure must never break report generation itself.
    if (this.reportVersions) {
      try {
        await this.reportVersions.snapshot(caseId, {
          markdown: c.markdown,
          meta,
          state: { findings: state.findings, iocs: state.iocs, forensicTimeline: state.forensicTimeline },
        });
      } catch { /* best-effort — see comment above */ }
    }
    return paths;
  }

  // Render the report artifacts from an ANONYMIZED copy of the case (for the redacted export, #54).
  // `redact` is the anonymizer's apply(): the loaded state, metadata, and asset overrides are
  // deep-walked so internal indicators become tokens (the same value -> same token, since one
  // anonymizer instance is used across all artifacts). The asset/IoC graph is derived from the
  // already-anonymized state so its labels are tokenized too. The on-disk report is never touched.
  // The investigating firm's logo (a base64 data URI) is left intact — it is branding, not victim PII.
  async redactedReportContents(caseId: string, redact: (s: string) => string): Promise<RedactedReportContents> {
    const state = applyAnonDeep(await this.loadFilteredState(caseId), redact);
    const rawMeta = this.reportMeta ? await this.reportMeta.load(caseId) : emptyReportMeta();
    const meta: ReportMeta = { ...applyAnonDeep(rawMeta, redact), companyLogo: rawMeta.companyLogo };
    const exposure = applyAnonDeep(await this.loadExposure(caseId), redact);
    const notebookEntries = applyAnonDeep(await this.loadNotebook(caseId), redact);
    const playbookTasks = applyAnonDeep(await this.loadPlaybook(caseId), redact);
    const hypotheses = applyAnonDeep(await this.loadHypotheses(caseId), redact);
    const overrides = applyAnonDeep(
      this.assetOverrides ? await this.assetOverrides.load(caseId) : emptyOverrides(),
      redact,
    );
    const graph = applyAssetOverrides(buildAssetGraph(state), overrides);
    // The redacted export honors the per-case report template too (branding/section layout).
    const template = await this.loadTemplate(caseId);
    const kevCatalog = await this.loadKevCatalog();
    const secondLookLeads = applyAnonDeep(await this.loadSecondLookLeads(caseId), redact);
    return this.renderContents(state, meta, exposure, graph, notebookEntries, playbookTasks, template, kevCatalog, hypotheses, secondLookLeads);
  }
}
