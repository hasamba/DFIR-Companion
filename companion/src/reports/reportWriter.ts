import { join } from "node:path";
import { ReportGeneration } from "./reportGeneration.js";
import type { CaseStore } from "../storage/caseStore.js";
import type { StateStore } from "../analysis/stateStore.js";
import { NO_SCOPE, type ScopeStore } from "../analysis/scope.js";
import { projectScope } from "../analysis/scopeProject.js";
import {
  applyFalsePositive,
  filterFalsePositiveEvents,
  type FalsePositiveStore,
} from "../analysis/falsePositive.js";
import { renderReportContents } from "./reportContents.js";
import type { HostScopeLedger } from "../analysis/hostScope.js";
import { assembleCustodyManifest } from "../analysis/custodyManifest.js";
import { renderDocxReport } from "./docx.js";
import { emptyReportMeta, type ReportMetaStore } from "./reportMeta.js";
import type { CustodyStore } from "../analysis/custody.js";
import { forensicTimelineCsv, geoMapCsv } from "./csv.js";
import { buildAttackLayer, type NavigatorLayer } from "./attackLayer.js";
import { toTimesketchJsonl } from "../integrations/timesketch/timesketchMap.js";
import { buildAssetGraph, type AssetGraph, type TimeWindow } from "../analysis/assetGraph.js";
import {
  buildEvidenceGraph,
  buildLateralPaths,
  type EvidenceGraph,
  type LateralPath,
} from "../analysis/evidenceGraph.js";
import { projectAlignment } from "../analysis/clockSkew.js";
import type { ClockSkewStore } from "../analysis/clockSkewStore.js";
import { buildAttackPhases, DEFAULT_GAP_SECONDS, type AttackPhase } from "../analysis/burstDetect.js";
import { detectBeacons, beaconEnvOptions, type BeaconCandidate } from "../analysis/beaconDetect.js";
import { gapEnvOptions, type TimelineGap } from "../analysis/gapDetect.js";
import { detectGapsWithWaves } from "../analysis/activityWaves.js";
import { buildSwimlaneData, type SwimlaneData, type SwimlaneGroupBy } from "../analysis/swimlane.js";
import { deriveIocSources } from "../analysis/iocCorroboration.js";
import { buildAdversaryHintsResult, type AdversaryHintsResult } from "../analysis/adversaryHints.js";
import { rankHosts, type HostRankingResult } from "../analysis/hostRanking.js";
import { loadHostAliasIndex } from "../analysis/hostScopeLoad.js";
import { VelociraptorClientStore } from "../analysis/velociraptorClientStore.js";
import {
  buildMobileSummary,
  mobileSummaryEnvOptions,
  type MobileCaseSummary,
} from "../analysis/mobileSummary.js";
import {
  buildPresentationDeck,
  presentationEnvOptions,
  type PresentationBranding,
  type PresentationDeck,
} from "../analysis/presentation.js";
import { buildGeoMap, geoMapEnvOptions, type GeoMapData } from "../analysis/geoMap.js";
import {
  detectTimelineAnomalies,
  anomalyEnvOptions,
  type TimelineAnomalyResult,
} from "../analysis/timelineAnomalies.js";
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
import type { SynthMetaStore, SynthesisCoverage, ModelPerfSnapshot } from "../analysis/synthMeta.js";
import type { PlaybookStore } from "../analysis/playbookStore.js";
import type { PlaybookTask } from "../analysis/playbook.js";
import { AssetOverridesStore, applyAssetOverrides, emptyOverrides } from "../analysis/assetOverrides.js";
import {
  LateralPathDismissStore,
  filterDismissedPaths,
  annotateDismissedPaths,
  type LateralPathDismissal,
  type AnnotatedLateralPath,
} from "../analysis/lateralPathDismiss.js";
import {
  buildBrandingContext,
  defaultReportTemplate,
  renderTemplateString,
  type ReportTemplate,
} from "./reportTemplate.js";
import type { ReportTemplateStore } from "./reportTemplateStore.js";
import type { ReportTemplateControlStore } from "./reportTemplateControl.js";
import type { ComplianceControlStore } from "../analysis/complianceControl.js";
import {
  applyAnonDeep,
  redactCustodyRecords,
  type RedactedReportContents,
} from "../analysis/redactedExport.js";
import type { ReportMeta } from "./reportMeta.js";
import type { KevStore } from "../analysis/kevStore.js";
import type { KevCatalog } from "../analysis/kev.js";
import type { ReportVersionStore } from "./reportVersionStore.js";
import type { AnalysisRunStore } from "../analysis/analysisRunStore.js";
import { claimSnapshot, hashManifestValue } from "../analysis/analysisRunHash.js";
import { createHash } from "node:crypto";

export interface ReportPaths {
  markdown: string;
  html: string;
  findingsCsv: string;
  iocsCsv: string;
  timelineCsv: string;
  forensicTimelineCsv: string;
  stateJson: string;
  analysisRuns: string;
}

// The optional stores ReportWriter draws on for report sections. Named fields instead of a long
// positional tail (#176): two branches each appending a new store to the constructor's end used to
// collide on the same slot, silently leaving one store `undefined` with no type error — see #176 for
// the incident that motivated this.
export interface ReportWriterOptions {
  scope?: ScopeStore;
  // Builds the case's scope ledger. A callback, not the three stores it needs: the writer's job is
  // to render what it is handed, and holding a super-timeline store here only to assemble one
  // object put ingest plumbing inside the reporting layer.
  hostScope?: (caseId: string) => Promise<HostScopeLedger | null>;
  falsePositives?: FalsePositiveStore;
  reportMeta?: ReportMetaStore;
  customerExposure?: CustomerExposureStore;
  notebook?: NotebookStore;
  assetOverrides?: AssetOverridesStore;
  // Fleet (Velociraptor) inventory. Paired with assetOverrides to resolve a host's short-name/FQDN
  // spellings onto one canonical name for hostRanking, the same recipe loadHostAliasIndex's other
  // callers (caseAppliers.syncPlaybook, the hostScope callback below) use. Optional: when absent,
  // hostRanking still honours any explicit analyst merges, just not fleet-derived pairing.
  fleet?: VelociraptorClientStore;
  playbook?: PlaybookStore;
  reportTemplates?: ReportTemplateStore;
  reportTemplateControl?: ReportTemplateControlStore;
  kevStore?: KevStore;
  hypothesisStore?: HypothesisStore;
  synthMeta?: SynthMetaStore; // #11 deferred: second-look collection leads in the report
  lateralPathDismissals?: LateralPathDismissStore; // analyst-rejected lateral chains
  reportVersions?: ReportVersionStore; // #77 report versioning (diff & rollback)
  analysisRuns?: AnalysisRunStore; // #377 reproducible analysis manifests + report pinning
  complianceControl?: ComplianceControlStore; // #336 discovery date + framework filter
  clockSkew?: ClockSkewStore; // #228 per-host clock offsets + the alignment toggle
  custodyStore?: CustodyStore; // #231 chain-of-custody appendix
  /** Signs the custody manifest that travels with a redacted package. Without it, none is produced. */
  instanceSecret?: Buffer;
}

export class ReportWriter {
  private readonly scope?: ScopeStore;
  private readonly hostScope?: (caseId: string) => Promise<HostScopeLedger | null>;
  private readonly falsePositives?: FalsePositiveStore;
  private readonly reportMeta?: ReportMetaStore;
  private readonly customerExposure?: CustomerExposureStore;
  private readonly notebook?: NotebookStore;
  private readonly assetOverrides?: AssetOverridesStore;
  private readonly fleet?: VelociraptorClientStore;
  private readonly playbook?: PlaybookStore;
  private readonly reportTemplates?: ReportTemplateStore;
  private readonly reportTemplateControl?: ReportTemplateControlStore;
  private readonly kevStore?: KevStore;
  private readonly hypothesisStore?: HypothesisStore;
  private readonly synthMeta?: SynthMetaStore;
  private readonly clockSkew?: ClockSkewStore;
  private readonly lateralPathDismissals?: LateralPathDismissStore;
  private readonly reportVersions?: ReportVersionStore;
  private readonly analysisRuns?: AnalysisRunStore;
  private readonly complianceControl?: ComplianceControlStore;
  private readonly custodyStore?: CustodyStore;
  private readonly instanceSecret?: Buffer;

  constructor(
    private readonly cases: CaseStore,
    private readonly state: StateStore,
    opts: ReportWriterOptions = {},
  ) {
    this.scope = opts.scope;
    this.hostScope = opts.hostScope;
    this.custodyStore = opts.custodyStore;
    this.instanceSecret = opts.instanceSecret;
    this.falsePositives = opts.falsePositives;
    this.reportMeta = opts.reportMeta;
    this.customerExposure = opts.customerExposure;
    this.notebook = opts.notebook;
    this.assetOverrides = opts.assetOverrides;
    this.fleet = opts.fleet;
    this.playbook = opts.playbook;
    this.reportTemplates = opts.reportTemplates;
    this.reportTemplateControl = opts.reportTemplateControl;
    this.kevStore = opts.kevStore;
    this.hypothesisStore = opts.hypothesisStore;
    this.synthMeta = opts.synthMeta;
    this.lateralPathDismissals = opts.lateralPathDismissals;
    this.reportVersions = opts.reportVersions;
    this.analysisRuns = opts.analysisRuns;
    this.complianceControl = opts.complianceControl;
    this.clockSkew = opts.clockSkew;
  }

  // Second-look collection leads (investigation-guidance #11, deferred): requests the raw re-query made
  // that matched NOTHING — each an actionable "collect this next" gap. Lives in synth-meta, not state, so
  // it's loaded here on demand for the report. [] when unavailable.
  private async loadSecondLookLeads(caseId: string): Promise<string[]> {
    if (!this.synthMeta) return [];
    try {
      return (await this.synthMeta.load(caseId)).secondLook?.leads ?? [];
    } catch {
      return [];
    }
  }

  // Synthesis coverage footnote (#62) — OPT-IN via DFIR_REPORT_SYNTH_COVERAGE. Off by default (the
  // footnote adds internal methodology detail not every report should carry); returns null unless the
  // flag is truthy and a coverage snapshot was recorded on the last run.
  private async loadCoverage(caseId: string): Promise<SynthesisCoverage | null> {
    const flag = (process.env.DFIR_REPORT_SYNTH_COVERAGE ?? "").trim().toLowerCase();
    if (!this.synthMeta || flag === "" || flag === "0" || flag === "false" || flag === "off") return null;
    try {
      return (await this.synthMeta.load(caseId)).coverage ?? null;
    } catch {
      return null;
    }
  }

  // Model-performance footnote (#74) — OPT-IN via DFIR_REPORT_MODEL_PERF, same posture as the
  // synthesis-coverage footnote (internal methodology detail, not every report should carry it).
  private async loadModelPerf(caseId: string): Promise<ModelPerfSnapshot | null> {
    const flag = (process.env.DFIR_REPORT_MODEL_PERF ?? "").trim().toLowerCase();
    if (!this.synthMeta || flag === "" || flag === "0" || flag === "false" || flag === "off") return null;
    try {
      const meta = await this.synthMeta.load(caseId);
      return {
        synthModel: meta.synthModel,
        findingsCount: meta.findingsCount,
        highSeverityBackfillCount: meta.highSeverityBackfillCount,
        parseRetries: meta.parseRetries,
        secondOpinionPerf: meta.secondOpinionPerf,
      };
    } catch {
      return null;
    }
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
    // Clock-skew alignment (#228) applies FIRST, so every consumer of this method — the report, the
    // evidence graph, the lateral-movement paths, the CSV/Timesketch exports — reasons over one time
    // axis. It is a projection: each shifted event keeps its recorded time in `originalTimestamp`,
    // and nothing here is ever written back to the case. Scope filtering follows, so an alignment
    // that moves an event across the investigation window is honoured by the window too.
    const skew = this.clockSkew ? await this.clockSkew.load(caseId) : undefined;
    const aligned = { ...loaded, forensicTimeline: projectAlignment(skew, loaded.forensicTimeline) };
    const scoped = projectScope(aligned, this.scope ? await this.scope.load(caseId) : NO_SCOPE);
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
    return renderDocxReport(
      state,
      meta,
      await this.loadExposure(caseId),
      await this.loadTemplate(caseId),
      (await this.hostScope?.(caseId)) ?? null,
    );
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

  // Ordered lateral-movement chains (entry host → pivot → ... → target, #92) for the case, derived
  // on demand with the same scope/legitimate filtering as the report. An optional time `window`
  // (#83) narrows it to events in that range. Chains the analyst has DISMISSED are dropped — pass
  // includeDismissed to get them back, each flagged, for the review/undo view.
  async lateralPaths(
    caseId: string,
    window?: TimeWindow,
    includeDismissed = false,
  ): Promise<LateralPath[] | AnnotatedLateralPath[]> {
    const paths = buildLateralPaths(await this.loadFilteredState(caseId), window);
    const dismissals = await this.loadLateralPathDismissals(caseId);
    return includeDismissed
      ? annotateDismissedPaths(paths, dismissals)
      : filterDismissedPaths(paths, dismissals);
  }

  private async loadLateralPathDismissals(caseId: string): Promise<LateralPathDismissal[]> {
    if (!this.lateralPathDismissals) return [];
    try {
      return await this.lateralPathDismissals.load(caseId);
    } catch {
      return [];
    }
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

  // Timeline gaps (#83): long silent periods — complete (every source dark, the log-tampering
  // signature), partial (one tool blind), or `betweenWaves` (dwell time between two bursts). Read via
  // detectGapsWithWaves so this panel labels a window exactly as the finding about it does.
  async timelineGaps(caseId: string): Promise<TimelineGap[]> {
    const state = await this.loadFilteredState(caseId);
    return detectGapsWithWaves(state.forensicTimeline, gapEnvOptions()).gaps;
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
    // Without this, an analyst who just merged a near-duplicate pair ("Same host — merge") would see
    // this derived table keep listing both spellings as separate scored hosts — contradicting the
    // decision they just made. loadHostAliasIndex is the same lightweight recipe caseAppliers.ts's
    // syncPlaybook uses; unlike the hostScope callback below, it does not aggregate the super-timeline,
    // so it stays cheap enough for this read-derived endpoint.
    const aliasIndex = await loadHostAliasIndex(
      { assetOverrides: this.assetOverrides, fleet: this.fleet },
      caseId,
    );
    return rankHosts(state, { aliasIndex });
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

  async writeAll(caseId: string, opts: { parentRunId?: string } = {}): Promise<ReportPaths> {
    const startedAt = new Date().toISOString();
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
      analysisRuns: join(dir, "analysis-runs.json"),
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
    // Lateral chains the analyst dismissed must not reappear in the written report.
    const lateralPaths = filterDismissedPaths(
      buildLateralPaths(state),
      await this.loadLateralPathDismissals(caseId),
    );
    const modelPerf = await this.loadModelPerf(caseId);
    const complianceControl = this.complianceControl ? await this.complianceControl.load(caseId) : {};
    const custody = this.custodyStore ? await this.custodyStore.load(caseId) : undefined;
    const c = renderReportContents(
      state,
      meta,
      exposure,
      graph,
      notebookEntries,
      playbookTasks,
      template,
      kevCatalog,
      hypotheses,
      secondLookLeads,
      coverage,
      lateralPaths,
      modelPerf,
      complianceControl,
      custody,
      (await this.hostScope?.(caseId)) ?? null,
    );
    // Staged, not published: nothing in reports/ changes until every artifact AND the provenance
    // record below have succeeded. Writing them straight over the previous report left a mixed
    // generation behind whenever anything in between failed — see reports/reportGeneration.ts.
    const generation = new ReportGeneration();
    const sourceRuns = this.analysisRuns ? await this.analysisRuns.list(caseId) : [];
    let reportRunId: string | undefined;
    // discard() is a no-op once published, so the finally covers every failure path — a render
    // error, a full disk, a permission error, or a provenance write that never completed — without
    // needing to know which one happened.
    try {
      await generation.stage(paths.markdown, c.markdown);
      await generation.stage(paths.html, c.html);
      await generation.stage(paths.findingsCsv, c.findingsCsv);
      await generation.stage(paths.iocsCsv, c.iocsCsv);
      await generation.stage(paths.timelineCsv, c.timelineCsv);
      await generation.stage(paths.forensicTimelineCsv, c.forensicTimelineCsv);
      await generation.stage(paths.stateJson, c.stateJson);
      if (this.analysisRuns) {
        const reportRun = await this.analysisRuns.record(caseId, {
          kind: "report",
          parentRunId: opts.parentRunId,
          startedAt,
          finishedAt: new Date().toISOString(),
          versions: { schema: "report/v1" },
          input: {
            artifacts: [],
            eventIds: state.forensicTimeline.map((event) => event.id),
            entityIds: [...state.findings.map((finding) => finding.id), ...state.iocs.map((ioc) => ioc.id)],
            selectionHash: hashManifestValue({
              sourceRunIds: sourceRuns.map((run) => run.id),
              eventIds: state.forensicTimeline.map((event) => event.id),
            }),
          },
          configuration: {
            templateHash: hashManifestValue(template),
            parameters: {
              templateId: template.id,
              pinnedRunIds: sourceRuns.map((run) => run.id),
            },
            filteringPolicy: {
              reportScopeApplied: true,
              falsePositivesExcluded: true,
            },
          },
          output: {
            entityIds: [
              "report.md",
              "report.html",
              "findings.csv",
              "iocs.csv",
              "timeline.csv",
              "forensic-timeline.csv",
              "state-export.json",
            ],
            hashes: [
              ["report.md", c.markdown],
              ["report.html", c.html],
              ["findings.csv", c.findingsCsv],
              ["iocs.csv", c.iocsCsv],
              ["timeline.csv", c.timelineCsv],
              ["forensic-timeline.csv", c.forensicTimelineCsv],
              ["state-export.json", c.stateJson],
            ].map(([id, contents]) => ({
              id,
              sha256: createHash("sha256").update(contents).digest("hex"),
            })),
            claims: state.findings.map((finding) =>
              claimSnapshot(finding.id, {
                title: finding.title,
                severity: finding.severity,
                description: finding.description,
                evidenceEventIds: finding.relatedEventIds,
              }),
            ),
          },
        });
        reportRunId = reportRun.id;
        await generation.stage(
          paths.analysisRuns,
          JSON.stringify(await this.analysisRuns.list(caseId), null, 2),
        );
      } else {
        await generation.stage(paths.analysisRuns, "[]\n");
      }
      // Every artifact and the provenance record are on disk — publish them as one generation.
      await generation.publish();
    } finally {
      await generation.discard();
    }
    // #77 report versioning: snapshot markdown + meta + the diff-relevant slice of state so the
    // dashboard can diff two generations and roll back to a prior version's editable meta.
    // Best-effort — a version-store failure must never break report generation itself.
    if (this.reportVersions) {
      try {
        await this.reportVersions.snapshot(caseId, {
          markdown: c.markdown,
          meta,
          state: {
            findings: state.findings,
            iocs: state.iocs,
            forensicTimeline: state.forensicTimeline,
            uncertainties: state.uncertainties,
          },
          template,
          analysisRunIds: [...sourceRuns.map((run) => run.id), ...(reportRunId ? [reportRunId] : [])],
        });
      } catch {
        /* best-effort — see comment above */
      }
    }
    return paths;
  }

  // Render the report artifacts from an ANONYMIZED copy of the case (for the redacted export, #54).
  // `redact` is the anonymizer's apply(): the loaded state, metadata, and asset overrides are
  // deep-walked so internal indicators become tokens (the same value -> same token, since one
  // anonymizer instance is used across all artifacts). The asset/IoC graph is derived from the
  // already-anonymized state so its labels are tokenized too. The on-disk report is never touched.
  // The investigating firm's logo (a base64 data URI) is left intact — it is branding, not victim PII.
  async redactedReportContents(
    caseId: string,
    redact: (s: string) => string,
  ): Promise<RedactedReportContents> {
    const state = applyAnonDeep(await this.loadFilteredState(caseId), redact);
    const rawMeta = this.reportMeta ? await this.reportMeta.load(caseId) : emptyReportMeta();
    // The redacted export is meant for EXTERNAL parties. The anonymizer's apply() only tokenizes
    // structured indicators (IP/email/host/domain/path/account/secret) — it has no detector for
    // free-text PEOPLE names or the investigating firm's internal distribution list. Without
    // stripping these, the redacted report shipped the victim org's CISO by name ("Chris Reynolds
    // — CISO, GlobalTech Industries"), the VP Engineering, the case investigators, and the
    // incident manager in cleartext (bug #18). These fields are firm-internal metadata, not case
    // content an external party needs, so blank them in the redacted meta copy. The on-disk
    // report (writeAll) keeps them; only the redacted export is affected.
    const redactedMeta: ReportMeta = {
      ...rawMeta,
      investigators: [],
      reviewer: "",
      incidentManager: "",
      distribution: [],
    };
    const meta: ReportMeta = { ...applyAnonDeep(redactedMeta, redact), companyLogo: rawMeta.companyLogo };
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
    // Dismissals are anchored on REAL host ids, but this state is anonymized — so run them through
    // the same redaction before matching, exactly as the asset overrides above are.
    const lateralPaths = filterDismissedPaths(
      buildLateralPaths(state),
      applyAnonDeep(await this.loadLateralPathDismissals(caseId), redact),
    );
    // The control carries no case data (a date and a framework list), so it needs no redaction.
    const complianceControl = this.complianceControl ? await this.complianceControl.load(caseId) : {};
    // Custody records live in custody.jsonl, NOT in investigation.json, so they never passed
    // through the applyAnonDeep(state) above. Redacting them here is what stops the appendix
    // shipping real hostnames, analyst names and filesystem paths to an external party (#231).
    // Field by field rather than wholesale, so the artifact hashes survive and the recipient can
    // actually check the chain against the evidence they hold (#362).
    const custody = this.custodyStore
      ? redactCustodyRecords(await this.custodyStore.load(caseId), redact)
      : undefined;
    // A manifest describing the REDACTED appendix, signed so this installation can later prove what
    // it sent. Built from the redacted records, never the store's: handing the real ones to an
    // external party is precisely what this export exists to prevent (#362 follow-up). The chain head
    // and any breaks come from the real log — hashes, line numbers and an enum carry no case data.
    const custodyManifest =
      this.custodyStore && this.instanceSecret && custody
        ? assembleCustodyManifest({
            caseId,
            records: custody,
            head: await this.custodyStore.chainHead(caseId),
            breaks: await this.custodyStore.verifyChain(caseId),
            secret: this.instanceSecret,
          })
        : undefined;
    return {
      ...renderReportContents(
        state,
        meta,
        exposure,
        graph,
        notebookEntries,
        playbookTasks,
        template,
        kevCatalog,
        hypotheses,
        secondLookLeads,
        undefined,
        lateralPaths,
        undefined,
        complianceControl,
        custody,
        (await this.hostScope?.(caseId)) ?? null,
      ),
      custodyManifest,
    };
  }
}
